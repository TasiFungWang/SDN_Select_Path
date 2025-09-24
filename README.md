# **SDN_Select_Path**

### **製作者 : 王采風**

### **簡介**
本專案利用 **Ryu Controller** 搭配 **Mininet** 實作一個 **可自訂封包傳送路徑的 SDN 環境**。  
透過 REST API，使用者可以查詢拓樸、列出主機間的候選路徑，並動態安裝/刪除流表，達到 **封包路徑控制與切換** 的目的。


## **系統總覽（Architecture）**

```css
 Host h1                                  SDN Switches                                    Host h2
(Client)   <-- OpenFlow Rules -->   [ Path Selection Control ]   <-- OpenFlow Rules -->   (Server)
  發送封包          封包依規則轉送 (L2/L3)              接收封包
                    ^                                     |
                    |   REST API (Topology/Path Control)  |
                    +---------------- Ryu Controller -----+
                                    (path_selection.py)
```

## **執行方式&功能**

### **Enroll Member 註冊會員**

```bash
gcc packet_server.c -o server.exe -lws2_32
gcc relay_ttl.c  -o relay.exe  -lws2_32
gcc packet_client.c -o client.exe -lws2_32
```

### **執行範例影片**
[C_Custom_Packet viedo](https://youtu.be/dJa6oouFyHk)
