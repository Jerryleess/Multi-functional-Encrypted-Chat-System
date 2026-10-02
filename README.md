Computer Networks Project - Phase 1
===
41247014S 李韋達
## How to build
```bash
cd code
make
```
這會在 code 資料夾中產生 server 和 client 兩個可執行檔。
## How to run
首先，在第一個終端機啟動 server：
```bash
./server
```
這會啟動伺服器並監聽在本機的預設 8888 port。\
若要指定自訂的 port：
```bash
./server <port>
```

接著在另一個終端機啟動 client：
```bash
./client
```
這會連線到預設的 `localhost` 上的 `8888` port。\
也可以指定伺服器 IP 或 port：
```bash
./client <server_ip> <port>
```
## client commands
### • register
註冊新使用者，並設定 ID 和 密碼：
```
> register <id> <pw>
```

### • login
註冊後即可登入，登入時必須同時指定一個用來接收訊息的 port：
```
> login <id> <pw> <port>
```
### • logout
向伺服器登出，登出後該使用者將不再被列為在線上：
```
> logout
```

### • list
列出所有線上使用者及其對應的 port：
```
> list
```
輸出格式如下：
```
Total number of online users: <user_count>
<username1>: <port1>
<username2>: <port2>
...
```

### • chat
向在線用戶發起 P2P 聊天請求。
```
> chat <username>
```
收到聊天請求時，要回應 accept 或 reject。
```
> accept
> reject
```
要離開房間，請在聊天室中輸入 `/quit`。

### • send file
在P2P聊天室內，可以輸入指令來傳送檔案：
```
> /send <path_to_file>
```

### • group chat
進入一個群聊房間。如果房間不存在，則會被創建。房間中的訊息會進行加密。
```
> group <group_name>
```
要離開房間，請在聊天室中輸入 `/quit`。


### • quit
退出 client 程式。如果目前已登入，會自動先登出：
```
> quit
```

### • Youtube 影片連結
```
https://youtu.be/Oejwwi-DU3U
```