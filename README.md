# **SDN_Select_Path**

### **製作者 : 王采風**

### **簡介**
本專案利用 **Ryu Controller** 搭配 **Mininet** 實作一個 **可自訂封包傳送路徑的 SDN 環境**。  
透過 REST API，使用者可以查詢拓樸、列出主機間的候選路徑，並動態安裝/刪除流表，達到 **封包路徑控制與切換** 的目的。


### **系統總覽（Architecture）**

```css
 Host h1                                  SDN Switches                                    Host h2
(Client)   <-- OpenFlow Rules -->   [ Path Selection Control ]   <-- OpenFlow Rules -->   (Server)
  發送封包          封包依規則轉送 (L2/L3)              接收封包
                    ^                                     |
                    |   REST API (Topology/Path Control)  |
                    +---------------- Ryu Controller -----+
                                    (path_selection.py)
```
自訂封包亮點 : 
1. 定義了一個應用層自訂封包（放在 TCP 裡）：
格式 : [0]AA [1]BB [2]type [3]priority [4]flags [5]ttl [6]len_lo [7]len_hi [8..]payload [end]checksum(payload XOR)

2.TTL 遞減＋自毀（drop）做在路上（Relay），並回 NACK 讓 Client 立即重傳 --> 模擬跨層行為。

### **自訂功能總覽**

|UI 選單| Type | 封包 Priority 值 | Flags | 行為 |
| :--: | :--: | :--: | :--: | :--: |
| 0 | Data | Priority0 | Priority0 | 延遲顯示 |
| 1 | Data | Priority1 | Require_ACK | 立即顯示(增加印出封包格式展示用) |
| 2 | Data | Priority2 | Require_ACK | 暫時顯示 |
| 3 | Data | Priority3 | Require_ACK | 支援壓縮(RLE 壓縮) |
| 4 | Data | Priority1 | Require_ACK | 自毀重傳(Relay回復NACK) |
| 5 | Heartbeat | Priority1 | Require_ACK | 確認對方存在 |


+---------------------+
| Ryu App |
| path_selection.py |
| - Topology |
| - Host Learning |
| - ARP Proxy |
| - Path Control |
+----------+----------+
|
REST API (WSGI)
|

| |
+-----v-----+ +-----v-----+
| Mininet | | User |
| topo.py | | curl / |
| (h1-s1..) | | scripts |
| h2-s2..) | +-----------+
+-----------+

### **編譯方式**
```bash
gcc packet_server.c -o server.exe -lws2_32
gcc relay_ttl.c  -o relay.exe  -lws2_32
gcc packet_client.c -o client.exe -lws2_32
```

### **執行範例影片**
[C_Custom_Packet viedo](https://youtu.be/mssxgwr5olU)
