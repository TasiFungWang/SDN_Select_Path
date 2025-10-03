# path_selection.py
# -----------------------------------------------------------------------------
# Ryu app: User-specified path installer with topology discovery, path listing,
#          deletion API, ARP proxy (no flood when possible) & diagnostics
#
# 功能總覽：
#   1) 自動掃描拓樸（switches、links），建立方向圖（DiGraph），並記錄每條「方向連結」的輸出埠 out_port
#      - 使用 ryu.topology（需 --observe-links），每次查詢 /topo、/paths 前會同步拓樸
#      - 維護 isw_ports：所有交換器的「連接埠」(dpid, port_no)
#      - 若 mac_table 裡有主機被「誤學在連接埠」，會在拓樸重建時清掉
#
#   2) L2 學習主機：只在「非連接埠」學習 MAC -> (dpid, port)
#      - 避免把主機 MAC 誤學在 uplink
#      - 開啟 debug_learn 時會在 Ryu log 印出學習/忽略紀錄（方便除錯）
#
#   3) ARP 處理：優先 ARP Proxy，不泛洪；若資訊不足，才「有限度」對連接埠泛洪
#      - 維護 ip_table（IP -> MAC）
#      - 看到 ARP Request 且已知目標 IP 的 MAC：由控制器直接送 ARP Reply 回入埠（不泛洪）
#      - 否則僅對「連接埠」做有限度泛洪（不丟到邊緣主機埠），避免風暴，並協助跨交換器學習
#      - 目標：在你 DELETE 路徑之後，也能可靠地重新學回主機位置、恢復列徑與選路
#
#   4) 路徑列舉（以交換器序列表示）：
#      - 需先學到 src/dst 主機所連之交換器（兩邊主機各送一包，如 ping 一下）
#      - 使用 networkx.all_simple_paths，並設安全閥：
#           MAX_HOPS = 8、MAX_PATHS = 32
#      - 路徑排序「穩定」：先依 hop 數，若相同再以 switch 序列字典序
#      - 有 path_cache，拓樸變動時自動清空
#
#   5) 指定路徑安裝：
#      - REST 可用 path_id（來自 /paths 回傳）或直接提供 switch 列表
#      - 若路徑未包含兩端交換器，會自動補上
#      - 沿路徑每跳安裝規則（中繼->下一跳 out_port；尾端->對端主機埠）
#      - 同時安裝 IPv4 與 ARP 規則（讓 ARP 也走同一路徑），priority=FLOW_PRIORITY(=100)
#      - 可選雙向（預設 true）
#
#   6) 刪除路徑：
#      - 僅刪掉App 下發的 IPv4/ARP 精準規則（priority=100），使用 OFPFC_DELETE_STRICT
#      - 若 bidirectional=True，會兩個方向（src->dst 與 dst->src）都刪
#      - 不影響 LLDP 與 table-miss（拓樸偵測仍運作）
#
#   7) 偵錯輔助：
#      - /hosts：直接回傳 mac_table（目前學到的主機：MAC -> dpid,port）
#      - /topo：回傳拓樸節點與方向連結清單（含每條方向邊的 out_port）
#      - Ryu log：含學習/忽略、ARP proxy 回覆、有限度泛洪等詳細紀錄
#
# REST 端點：
#   - GET  /topo
#       回傳目前拓樸（switch 清單＋links 清單；每條方向連結附 out_port）
#   - GET  /hosts
#       回傳目前 mac_table（主機 MAC -> (dpid, port)），用於偵錯學習狀態
#   - GET  /paths?src_mac=&dst_mac=
#       列出 (src_mac, dst_mac) 主機對的可行交換器路徑（依 hop 數->字典序排序並編號）
#       注意：請先讓兩端主機各送一包（如 ping 一次）以便學到所屬 switch/port
#   - POST /path
#       安裝路徑（預設雙向）
#       JSON（擇一）：
#         { "src_mac":"..", "dst_mac":"..", "path_id": 2, "bidirectional": true }
#         { "src_mac":"..", "dst_mac":"..", "path": [1,5,2], "bidirectional": true }
#       若使用 path_id，會套用 /paths 回傳之對應 switch 序列
#   - DELETE /path?src_mac=&dst_mac=&bidirectional=true
#       使用 DELETE_STRICT 精準刪除先前安裝的 IPv4/ARP 規則（priority=100）
#
# 執行方式（建議）：
#   ryu-manager --observe-links --wsapi-port 8080 path_selection.py ryu.app.rest_topology
#     - --observe-links：啟用 Ryu 拓樸 API（LLDP）
#     - ryu.app.rest_topology：方便用 /v1.0/topology/* 交叉驗證
#
# Mininet 參考：
#   sudo mn --custom topo.py --topo user_mesh \
#           --controller=remote,ip=127.0.0.1,port=6633 \
#           --switch ovsk,protocols=OpenFlow13 --mac --link=tc
#
# 常見操作流程：
#   1) 兩邊主機各送一包（ping）-> /hosts 應看得到
#   2) 查路徑：GET /paths?src_mac=&dst_mac=
#   3) 安裝路徑：POST /path（path_id 或明確 switch 列表）
#   4) 驗證：Mininet 內 ping；ovs-ofctl dump-flows sX 應看見 priority=100 的 IPv4/ARP 規則
#   5) 切換路徑：先 DELETE /path -> 兩邊主機各送一包（或等待 ARP）-> 再 POST 新路徑
#
# 重要預設值：
#   - OpenFlow 1.3
#   - FLOW_PRIORITY = 100（App 裝的規則優先度）
#   - MAX_HOPS = 8、MAX_PATHS = 32（列舉安全閥）
#
# 設計取捨與限制：
#   - _all_normal_ports() 以 1..32 示意；正式環境應查詢實際可用埠
#   - ARP Proxy 基於簡單 ip_table（實驗足夠）；首次未知時會對「連接埠」有限度泛洪
#   - 僅 L2 精準 match（eth_type + src/dst MAC），不做 L3/L4 精細分類
#   - 若主機 MAC / IP 變更，需重新學習（送流量或清 ARP 後 ping）
#   - 此段註解由ChatGPT提供
# -----------------------------------------------------------------------------

from ryu.base import app_manager                    # Ryu 應用程式基底類別（RyuApp）
from ryu.controller import ofp_event                # OpenFlow 事件（PacketIn、Features 等）
from ryu.controller.handler import (                # 事件處理器工具
    MAIN_DISPATCHER,                                # 交換器進入 main 狀態
    CONFIG_DISPATCHER,                              # 交換器剛連上，用來下初始規則
    set_ev_cls                                      # 把函式註冊成事件處理器
)
from ryu.ofproto import ofproto_v1_3               # OpenFlow 1.3 常數/結構定義
from ryu.lib.packet import packet, ethernet, arp   # 封包容器、Ethernet/ARP 協定剖析
from ryu.app.wsgi import (                         # 內建 WSGI（REST API）框架
    WSGIApplication, ControllerBase, route
)
from ryu.topology import event, api as topo_api    # 拓樸事件（Link/Switch 變動）與查詢 API
from ryu.lib.packet import lldp                    # LLDP 協定（拓樸探索用；用來略過學習）
from ryu.lib.packet import ether_types             # EtherType（例如 ETH_TYPE_ARP，用於 ARP Reply）
from webob import Response                         # REST 回覆物件（JSON/狀態碼）
import json                                        # JSON 編碼/解碼（REST 輸入輸出）
import networkx as nx                              # 圖論與路徑列舉


REST_PORT = 8080

PATH_APP_INSTANCE_NAME = 'path_app_api'

# --------- 統一 JSON 回應格式 ------------------------------------------------
"""將 Python 物件轉成 UTF-8 bytes（避免中文亂碼），供 WebOb Response 使用。"""
def _json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False).encode('utf-8')

"""建立一個成功的 JSON 回應"""
def ok_json(payload, status=200):
    return Response(
        status=status,
        content_type='application/json; charset=utf-8',
        body=_json_bytes(payload)
    )


"""建立一個錯誤 JSON 回應"""
def bad_json(message, status=400):
    return ok_json({"ok": False, "error": str(message)}, status=status)

"""將 MAC 位址字串正規化成小寫，避免大小寫造成的比對失敗"""
def mac_str(mac: str) -> str:
    return mac.lower()



class UserPathController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    # 路徑列舉的安全閥（避免爆量）
    MAX_HOPS = 8
    MAX_PATHS = 32

    # 安裝規則所使用的優先度 (刪除時用 DELETE_STRICT 必須一致)
    FLOW_PRIORITY = 100

    """
    初始化應用程式：
      - 註冊 REST Controller。
      - 建立狀態表（datapaths、mac_table、拓樸圖與連結埠對照、路徑快取）。
      - isw_ports: 所有交換器連接埠集合 (dpid, port_no)。
      - ip_table: 簡易 IP -> MAC 對照，供 ARP Proxy 使用。
      - debug_learn: 是否輸出學習/忽略等偵錯訊息到 Ryu log。
    """
    def __init__(self, *args, **kwargs):
        super(UserPathController, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(UserPathRest, {PATH_APP_INSTANCE_NAME: self})

        # 控制器狀態
        self.datapaths = {}         # dpid -> datapath 物件
        self.mac_table = {}         # mac (str) -> (dpid (int), port_no (int))
        self.graph = nx.DiGraph()   # 方向圖；每個方向的 out_port 可能不同
        self.link_port = {}         # (src_dpid, dst_dpid) -> out_port_on_src

        # 快取 (src_sw, dst_sw) 對應的候選路徑列表（拓樸改變時清空）
        self.path_cache = {}

        self.isw_ports = set()      # 所有交換器連接埠 (dpid, port_no)
        self.ip_table = {}          # ARP Proxy 用：IP -> MAC
        self.debug_learn = True     # 是否在學習/忽略時印出詳細 log

    # === Topology events ===
    """有交換器進入拓樸時觸發 (重新同步拓樸資訊)"""
    @set_ev_cls(event.EventSwitchEnter)
    def _on_switch_enter(self, ev):
        self._rebuild_topology()


    """同上但離開拓樸時觸發"""
    @set_ev_cls(event.EventSwitchLeave)
    def _on_switch_leave(self, ev):
        self._rebuild_topology()


    """同上但偵測到新增連結時觸發"""
    @set_ev_cls(event.EventLinkAdd)
    def _on_link_add(self, ev):
        self._rebuild_topology()


    """同上但偵測到連結被移除時觸發"""
    @set_ev_cls(event.EventLinkDelete)
    def _on_link_del(self, ev):
        self._rebuild_topology()


    """
    從 Ryu topology API 讀取目前 switches/links，重建：
      - self.graph：方向圖（節點為 dpid，邊為 src->dst）。
      - self.link_port：每條方向邊 (src, dst) 的輸出埠 out_port。
      - self.isw_ports：連接埠集合（用於避免在 uplink 口學到主機）。
    另外：
      - 如果 mac_table 內主機位置落在連接埠，視為誤學並移除。
      - 清除 path_cache，以避免使用過期路徑。
    """
    def _rebuild_topology(self):
        switches = topo_api.get_switch(self, None)
        links = topo_api.get_link(self, None)

        self.graph.clear()
        self.link_port.clear()
        self.isw_ports.clear()

        # 加入節點（交換器）
        for sw in switches:
            self.graph.add_node(sw.dp.id)

        # 加入方向邊，並記錄 out_port 與連接埠
        for l in links:
            src = l.src.dpid
            dst = l.dst.dpid
            self.graph.add_edge(src, dst)
            self.link_port[(src, dst)] = l.src.port_no
            self.isw_ports.add((src, l.src.port_no))

        # 移除主機紀錄以學的連接埠（避免誤學）
        bad = [mac for mac, (dpid, port) in self.mac_table.items()
               if (dpid, port) in self.isw_ports]
        for mac in bad:
            del self.mac_table[mac]
            if self.debug_learn:
                self.logger.info("Forget host on inter-switch port: mac=%s", mac)

        # 拓樸變更 -> 清掉路徑快取
        self.path_cache.clear()
        self.logger.info("Topology rebuilt: %d switches, %d directed links", len(switches), len(links))


    # === Switch (datapath) connection & table-miss ===
    """
    交換器建立 OpenFlow 連線後觸發：
      - 註冊 datapath。
      - 安裝 table-miss（priority=0）讓未知封包送到控制器（CONTROLLER:65535）。
    """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _on_switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # 記錄 datapath
        self.datapaths[dp.id] = dp

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected: dpid=%s (table-miss installed)", dp.id)


    # === PacketIn for L2 learning & ARP handling ===
    """
    接收 PacketIn：
      - L2 學習：只在非連接埠學習 MAC 所在的 (dpid, port)。
      - ARP：
          * 如果是 ARP Request 並且已知目標 IP 的 MAC，直接由控制器送 ARP Reply（Proxy，不泛洪）。
          * 否則僅對「連接埠」做有限度 flood（不丟到邊緣主機埠與入埠），協助跨交換器學習。
      - 其他封包：若已有規則一般不會進到控制器，所以就不轉送。
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        if pkt.get_protocol(lldp.lldp):
            # LLDP 給 topology app 用；這邊不處理
            return

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src = mac_str(eth.src)
        dst = mac_str(eth.dst)

        # 只在「非連接埠」學習主機位置
        if (dpid, in_port) not in self.isw_ports:
            prev = self.mac_table.get(src)
            self.mac_table[src] = (dpid, in_port)
            if self.debug_learn and prev != (dpid, in_port):
                self.logger.info("Learn host: mac=%s at dpid=%s,port=%s", src, dpid, in_port)
        else:
            if self.debug_learn:
                self.logger.info("Ignore learning on inter-switch port: mac=%s at dpid=%s,port=%s", src, dpid, in_port)

        # --- ARP 處理 ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # 記錄 sender 的 IP -> MAC（供後續 Proxy 使用）
            self.ip_table[arp_pkt.src_ip] = src

            # 如果是 Request 並且已知目標 IP 的 MAC -> Proxy 回覆
            if arp_pkt.opcode == arp.ARP_REQUEST:
                t_mac = self.ip_table.get(arp_pkt.dst_ip)
                if t_mac:
                    self._send_arp_reply(
                        dp=dp, in_port=in_port,
                        requester_mac=src, requester_ip=arp_pkt.src_ip,
                        target_mac=t_mac, target_ip=arp_pkt.dst_ip
                    )
                    if self.debug_learn:
                        self.logger.info("ARP proxy reply at dpid=%s to %s for %s is %s",
                                         dpid, src, arp_pkt.dst_ip, t_mac)
                    return

            # 否則對「連接埠」做有限泛洪（避免影響主機邊緣埠與入埠）
            actions = []
            for p in self._uplink_ports_of(dpid):
                if p != in_port:
                    actions.append(parser.OFPActionOutput(p))
            if actions:
                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data
                )
                dp.send_msg(out)
                if self.debug_learn:
                    self.logger.info("ARP limited-flood from dpid=%s,in_port=%s to %d uplink ports",
                                     dpid, in_port, len(actions))
            return


    """
    以控制器身分組出 ARP Reply，直接回送給請求端（requester）：
      - Ethernet: dst=requester_mac, src=target_mac, ethertype=ARP
      - ARP: opcode=REPLY,  sender=(target_mac,target_ip), target=(requester_mac,requester_ip)
    避免 ARP 在拓樸內廣播，提升穩定性與效率。
    """
    def _send_arp_reply(self, dp, in_port, requester_mac, requester_ip, target_mac, target_ip):
        e = ethernet.ethernet(dst=requester_mac, src=target_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=target_mac, src_ip=target_ip,
                    dst_mac=requester_mac, dst_ip=requester_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        parser = dp.ofproto_parser
        ofp = dp.ofproto
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions,
            data=p.data
        )
        dp.send_msg(out)

    """
    取得某交換器的邊緣主機埠（排除連接埠）。
    程式中沒用到。
    如果要找出所有邊緣主機 port 就可以用 OpenFlow port-desc / features 搭配 _edge_ports_of 用
    """
    def _edge_ports_of(self, dpid):
        interlinks = {p for (d, p) in self.isw_ports if d == dpid}
        return [p for p in range(1, 33) if p not in interlinks]


    """
    取得某交換器的連接埠列表（uplink/inter-switch）。
    用於 ARP 有限度泛洪，避免打到主機邊緣口。
    """
    def _uplink_ports_of(self, dpid):
        return sorted({p for (d, p) in self.isw_ports if d == dpid})


    # === FlowMod 發佈 ===
    """
    在指定交換器安裝一條 Flow：
      - priority: 規則優先度
      - match:    比對條件（OFPMatch）
      - actions:  執行動作（一般為輸出到某埠）
      - idle/hard timeout: 逾時設定（此專案預設 0=永不逾時）
    """
    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    # === Path enumeration ===
    """
    列舉兩端主機（src_mac, dst_mac）之間，以「交換器序列」表示的所有簡單路徑：
      - 先由 mac_table 找到兩端主機各自接在的交換器（src_sw, dst_sw）。
      - 以 networkx.all_simple_paths 列舉（cutoff=MAX_HOPS；最多取 MAX_PATHS）。
      - 排序規則：先依 hop 數，再以 switch 序列字典序，確保 ID 穩定。
      - 回傳格式：[{id, switches:[...], hops:int}, ...]
    搓作前記得兩端主機須先送過封包（如 ping）要先學到位置，否則就會拋出錯誤。
    """
    def list_paths_for_hosts(self, src_mac: str, dst_mac: str):
        src_mac = mac_str(src_mac)
        dst_mac = mac_str(dst_mac)
        if src_mac not in self.mac_table or dst_mac not in self.mac_table:
            raise ValueError("Unknown host(s). Make sure both hosts sent some traffic (e.g., ping once).")

        src_sw, _ = self.mac_table[src_mac]
        dst_sw, _ = self.mac_table[dst_mac]

        key = (src_sw, dst_sw)
        if key in self.path_cache:
            return self.path_cache[key]

        if src_sw not in self.graph or dst_sw not in self.graph:
            raise ValueError("Host-attached switch not in topology graph.")

        # 列舉簡單路徑，加入安全閥
        candidates = []
        try:
            gen = nx.all_simple_paths(self.graph, source=src_sw, target=dst_sw, cutoff=self.MAX_HOPS)
            for sw_seq in gen:
                candidates.append(sw_seq)
                if len(candidates) >= self.MAX_PATHS:
                    break
        except nx.NetworkXNoPath:
            candidates = []

        candidates.sort(key=lambda seq: (len(seq), seq))  # 同長度再按序列字典序
        result = [{"id": i, "switches": sw_seq, "hops": len(sw_seq) - 1}
                  for i, sw_seq in enumerate(candidates, start=1)]

        self.path_cache[key] = result

        if result:
            pretty = ", ".join([f"{p['id']}:{'-'.join(map(str,p['switches']))}" for p in result])
            self.logger.info("Paths %s->%s: %s", src_sw, dst_sw, pretty)
        else:
            self.logger.info("No path between %s and %s", src_sw, dst_sw)
        return result

    # === Path installation ===
    """
    沿指定交換器序列安裝路徑規則（含 IPv4 與 ARP；預設雙向）：
      - 若 path_switches 未包含端點交換器，會自動補上。
      - 依 (u->v) 查表 self.link_port[(u,v)] 取得 out_port。
      - 最後一跳輸出到對端主機的 host port。
    失敗情況：
      - 未學到主機位置。
      - 路徑中出現未連線的交換器。
      - 某跳查無對應 link_port（拓樸不一致）。
    """
    def install_path(self, src_mac: str, dst_mac: str, path_switches, bidirectional: bool = True):
        src_mac = mac_str(src_mac)
        dst_mac = mac_str(dst_mac)

        if src_mac not in self.mac_table or dst_mac not in self.mac_table:
            raise ValueError("Unknown host(s). Make sure both hosts sent some traffic (e.g., ping once)")

        # 檢查 path 內每個交換器是否在線
        for dpid in path_switches:
            if dpid not in self.datapaths:
                raise ValueError(f"Switch {dpid} not connected")

        # 端點交換器與 host port
        src_sw, src_host_port = self.mac_table[src_mac]
        dst_sw, dst_host_port = self.mac_table[dst_mac]

        # 自動補上端點交換器
        full_path = list(path_switches)
        if full_path[0] != src_sw:
            full_path = [src_sw] + full_path
        if full_path[-1] != dst_sw:
            full_path = full_path + [dst_sw]

        # 計算每跳 (u->v) 的 out_port
        hop_out = {}
        for u, v in zip(full_path[:-1], full_path[1:]):
            key = (u, v)
            if key not in self.link_port:
                raise ValueError(f"No link info for {u}->{v}. Is the topology correct?")
            hop_out[(u, v)] = self.link_port[key]

        # 正向（src->dst）
        self._program_chain(
            path=full_path,
            hop_out=hop_out,
            match_src_mac=src_mac,
            match_dst_mac=dst_mac,
            final_host_port=dst_host_port
        )

        # 反向（dst->src）
        if bidirectional:
            rev_path = list(reversed(full_path))
            rev_hop_out = {}
            for u, v in zip(rev_path[:-1], rev_path[1:]):
                key = (u, v)
                if key not in self.link_port:
                    raise ValueError(f"No reverse link info for {u}->{v}.")
                rev_hop_out[(u, v)] = self.link_port[key]
            self._program_chain(
                path=rev_path,
                hop_out=rev_hop_out,
                match_src_mac=dst_mac,
                match_dst_mac=src_mac,
                final_host_port=src_host_port
            )

        self.logger.info("Installed path %s for %s -> %s (bidir=%s)", full_path, src_mac, dst_mac, bidirectional)

    """
    依交換器序列逐跳安裝規則：
      - 中繼交換器：輸出到下一跳對應的 out_port。
      - 最尾交換器：輸出到對端主機的 host port。
      - 安裝兩類規則：IPv4（eth_type=0x0800）與 ARP（eth_type=0x0806），priority=FLOW_PRIORITY。
    """
    def _program_chain(self, path, hop_out, match_src_mac, match_dst_mac, final_host_port):
        for idx, sw in enumerate(path):
            dp = self.datapaths[sw]
            parser = dp.ofproto_parser

            if idx < len(path) - 1:
                nxt = path[idx + 1]
                out_port = hop_out[(sw, nxt)]
            else:
                out_port = final_host_port

            actions = [parser.OFPActionOutput(out_port)]

            # IPv4
            match_ip = parser.OFPMatch(eth_type=0x0800, eth_src=match_src_mac, eth_dst=match_dst_mac)
            self._add_flow(dp, priority=self.FLOW_PRIORITY, match=match_ip, actions=actions, idle_timeout=0)

            # ARP
            match_arp = parser.OFPMatch(eth_type=0x0806, eth_src=match_src_mac, eth_dst=match_dst_mac)
            self._add_flow(dp, priority=self.FLOW_PRIORITY, match=match_arp, actions=actions, idle_timeout=0)

    # === Path deletion ===
    """
    刪除 (src_mac, dst_mac) 主機對的規則：
      - 僅刪除App 裝的 IPv4/ARP 規則（priority 與 match 必須一致）。
      - bidirectional=True，則兩方向（src->dst 與 dst->src）都刪除。
      - 不影響 table-miss 或 LLDP。
    """
    def remove_path(self, src_mac: str, dst_mac: str, bidirectional: bool = True, priority: int = None):
        src_mac = mac_str(src_mac)
        dst_mac = mac_str(dst_mac)
        if priority is None:
            priority = self.FLOW_PRIORITY

        for dpid, dp in self.datapaths.items():
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            # forward: IPv4
            match_v4 = parser.OFPMatch(eth_type=0x0800, eth_src=src_mac, eth_dst=dst_mac)
            mod_v4 = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=priority,
                match=match_v4
            )
            dp.send_msg(mod_v4)

            # forward: ARP
            match_arp = parser.OFPMatch(eth_type=0x0806, eth_src=src_mac, eth_dst=dst_mac)
            mod_arp = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=priority,
                match=match_arp
            )
            dp.send_msg(mod_arp)

            if bidirectional:
                # reverse: IPv4
                match_v4_r = parser.OFPMatch(eth_type=0x0800, eth_src=dst_mac, eth_dst=src_mac)
                mod_v4_r = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofp.OFPFC_DELETE_STRICT,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    priority=priority,
                    match=match_v4_r
                )
                dp.send_msg(mod_v4_r)

                # reverse: ARP
                match_arp_r = parser.OFPMatch(eth_type=0x0806, eth_src=dst_mac, eth_dst=src_mac)
                mod_arp_r = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofp.OFPFC_DELETE_STRICT,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    priority=priority,
                    match=match_arp_r
                )
                dp.send_msg(mod_arp_r)

        self.logger.info("Removed flows for %s <-> %s (bidir=%s)", src_mac, dst_mac, bidirectional)


# === REST Controller ===

class UserPathRest(ControllerBase):

    """取得主程式 app 實例，供各 REST handler 呼叫邏輯。"""
    def __init__(self, req, link, data, **config):
        super(UserPathRest, self).__init__(req, link, data, **config)
        self.app: UserPathController = data[PATH_APP_INSTANCE_NAME]

    """
    取得拓樸快照：
      - switches: 目前所有交換器 dpid（排序）。
      - links:    方向連結清單，每筆包含 src/dst 與對應 out_port。
    呼叫前先同步拓樸（確保 isw_ports 與 link_port 為最新）。
    """
    @route('userpath', '/topo', methods=['GET'])
    def get_topo(self, req, **kwargs):
        self.app._rebuild_topology()
        g = self.app.graph
        switches = sorted(list(g.nodes()))
        links = sorted([
            {"src": u, "dst": v, "out_port": self.app.link_port.get((u, v))}
            for u, v in g.edges()
        ], key=lambda x: (x["src"], x["dst"]))
        payload = {"switches": switches, "links": links}
        return ok_json(payload)


    """
    取得目前已學到的主機表（mac_table）：
      - 每筆包含 mac、dpid、port
    檢查是否有誤學，或是否已成功重新學到。
    """
    @route('userpath', '/hosts', methods=['GET'])
    def get_hosts(self, req, **kwargs):
        table = [
            {"mac": mac, "dpid": dpid, "port": port}
            for mac, (dpid, port) in sorted(self.app.mac_table.items())
        ]
        return ok_json({"ok": True, "count": len(table), "hosts": table})


    """
    查詢 (src_mac, dst_mac) 的候選交換器路徑：
      - 要先讓兩端主機各送一包（例如 ping）以便學習位置。
      - 回傳路徑列表（依 hop 數->字典序排序並編號）。
    """
    @route('userpath', '/paths', methods=['GET'])
    def get_paths(self, req, **kwargs):
        self.app._rebuild_topology()
        params = req.GET
        src_mac = params.get('src_mac')
        dst_mac = params.get('dst_mac')
        if not src_mac or not dst_mac:
            return bad_json("Query string must include src_mac & dst_mac", status=400)

        try:
            paths = self.app.list_paths_for_hosts(src_mac, dst_mac)
            payload = {
                "ok": True,
                "src_mac": mac_str(src_mac),
                "dst_mac": mac_str(dst_mac),
                "max_hops": self.app.MAX_HOPS,
                "max_paths": self.app.MAX_PATHS,
                "count": len(paths),
                "paths": paths
            }
            return ok_json(payload)
        except Exception as e:
            return bad_json(e, status=400)


    """
    安裝指定的路徑規則（預設雙向）：
      - 接受兩種格式：
          * {"src_mac","dst_mac","path_id", "bidirectional"}  # 以 /paths 回傳的 id 指定
          * {"src_mac","dst_mac","path":[...], "bidirectional"} # 直接給交換器序列
      - 會自動補上端點交換器，並在沿途裝 IPv4/ARP 規則（priority=100）。
    """
    @route('userpath', '/path', methods=['POST'])
    def set_path(self, req, **kwargs):
        try:
            content = req.json if req.body else {}
        except ValueError:
            return bad_json("Invalid JSON", status=400)

        try:
            src_mac = content['src_mac']
            dst_mac = content['dst_mac']
            bidir = bool(content.get('bidirectional', True))

            if 'path_id' in content:
                # 用編號選路線（從 /paths 的結果中挑）
                pid = int(content['path_id'])
                paths = self.app.list_paths_for_hosts(src_mac, dst_mac)
                choice = next((p for p in paths if p['id'] == pid), None)
                if not choice:
                    return bad_json(f"path_id {pid} not found for given hosts", status=400)
                path_switches = choice['switches']
            else:
                # 直接給 switch 序列
                path = content['path']
                if not isinstance(path, list) or not path:
                    return bad_json("path must be a non-empty list of switch dpids", status=400)
                path_switches = path

            self.app.install_path(src_mac, dst_mac, path_switches, bidirectional=bidir)
            return ok_json({"ok": True, "path": path_switches, "bidirectional": bidir})
        except Exception as e:
            return bad_json(e, status=400)


    """
    刪除針對 (src_mac, dst_mac) 安裝的 IPv4/ARP 規則（預設雙向）：
      - 僅刪除 App 所裝的 priority=FLOW_PRIORITY 的精準規則。
      - 不影響拓樸偵測（LLDP）與 table-miss。
    """
    @route('userpath', '/path', methods=['DELETE'])
    def delete_path(self, req, **kwargs):
        params = req.GET
        src_mac = params.get('src_mac')
        dst_mac = params.get('dst_mac')
        bidir = params.get('bidirectional', 'true').lower() != 'false'
        if not src_mac or not dst_mac:
            return bad_json("Query string must include src_mac & dst_mac", status=400)

        try:
            self.app.remove_path(src_mac, dst_mac, bidirectional=bidir, priority=self.app.FLOW_PRIORITY)
            return ok_json({
                "ok": True,
                "src_mac": mac_str(src_mac),
                "dst_mac": mac_str(dst_mac),
                "bidirectional": bidir
            })
        except Exception as e:
            return bad_json(e, status=400)

