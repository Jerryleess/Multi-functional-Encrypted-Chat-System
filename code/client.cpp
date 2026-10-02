// =============================
// client.cpp
// Client: register/login/logout/list + P2P chat with invite/accept/reject + OpenSSL encryption (Base)
// Build: g++ -std=c++17 -pthread client.cpp -o client -lssl -lcrypto
// Run:   ./client 127.0.0.1 8888
// =============================

#include "header.h"
#include "func.h"

using namespace std;

// ======== client 狀態 ========

string g_my_id;
int    g_listen_port = -1;

pthread_mutex_t g_chat_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  g_chat_cv  = PTHREAD_COND_INITIALIZER;

int    g_chat_fd      = -1;
string g_chat_peer_id;
bool   g_in_chat      = false;

int    g_pending_fd   = -1;
string g_pending_peer_id;
bool   g_pending_has  = false;
int    g_chat_action  = 0;

static string trim(const string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static string basename_of(const string& path) {
    size_t p = path.find_last_of("/\\");
    if (p == string::npos) return path;
    return path.substr(p + 1);
}

static bool file_size_of(const string& path, uint64_t& sz) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    sz = (uint64_t)st.st_size;
    return true;
}

// BLOB frame: "BLOB" + type(1) + len(4 big-endian) + data
static bool send_blob(int fd, char type, const unsigned char* data, uint32_t len) {
    string p;
    p.reserve(4 + 1 + 4 + len);
    p.append("BLOB", 4);
    p.push_back(type);
    p.push_back((char)((len >> 24) & 0xFF));
    p.push_back((char)((len >> 16) & 0xFF));
    p.push_back((char)((len >> 8) & 0xFF));
    p.push_back((char)(len & 0xFF));
    if (len > 0) p.append((const char*)data, len);
    return secure_send(fd, p);
}

static bool parse_blob(const string& p, char& type, const unsigned char*& data, uint32_t& len) {
    if (p.size() < 9) return false;
    if (memcmp(p.data(), "BLOB", 4) != 0) return false;
    type = p[4];
    const unsigned char* b = (const unsigned char*)p.data();
    len = ((uint32_t)b[5] << 24) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 8) | (uint32_t)b[8];
    if (p.size() != 9ull + len) return false;
    data = (const unsigned char*)p.data() + 9;
    return true;
}

// ======== 聊天室（加密）: select(stdin + chat_fd) ========

void run_chat_session() {
    int chat_fd;
    string peer_id;
    pthread_mutex_lock(&g_chat_mtx);
    chat_fd = g_chat_fd;
    peer_id = g_chat_peer_id;
    pthread_mutex_unlock(&g_chat_mtx);

    cout << "=== 與 '" << peer_id << "' 的聊天室 ===\n";
    cout << "輸入訊息後 Enter 送出，輸入 /exit 離開聊天室。\n";
    cout << "輸入 /send <filepath> 送檔案。\n";

    fd_set readfds;
    bool running = true;

    int old_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, old_flags | O_NONBLOCK);

    // ===== 收檔案狀態 =====
    bool receiving = false;
    FILE* rf = nullptr;
    uint64_t recv_total = 0;
    uint64_t recv_got = 0;
    string recv_name;

    auto close_recv = [&]() {
        if (rf) { fclose(rf); rf = nullptr; }
        receiving = false;
        recv_total = recv_got = 0;
        recv_name.clear();
    };

    while (running) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(chat_fd, &readfds);
        int maxfd = max(STDIN_FILENO, chat_fd) + 1;

        int ret = select(maxfd, &readfds, nullptr, nullptr, nullptr);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        // ===== 使用者輸入 =====
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            string line;
            if (!getline(cin, line)) {
                running = false;
            } else if (line == "/exit") {
                // 若正在收檔案，直接中止（可選）
                close_recv();
                secure_send(chat_fd, "__EXIT__");
                running = false;
            } else if (line.rfind("/send ", 0) == 0) {
                string path = line.substr(6);
                if (path.empty()) {
                    cout << "[系統] 用法: /send <filepath>\n";
                    continue;
                }

                uint64_t fsz = 0;
                if (!file_size_of(path, fsz)) {
                    cout << "[系統] 找不到檔案或不是一般檔案: " << path << "\n";
                    continue;
                }

                string fname = basename_of(path);

                // 送 offer
                if (!secure_send(chat_fd, "__FILE_OFFER__ " + fname + " " + to_string(fsz))) {
                    cout << "[系統] 送出檔案邀請失敗。\n";
                    continue;
                }

                // 等對方回覆 accept/reject（同步等待，最簡單穩）
                string resp;
                if (!secure_recv(chat_fd, resp)) {
                    cout << "[系統] 對方離線，無法送檔。\n";
                    running = false;
                    break;
                }
                if (resp == "__FILE_REJECT__") {
                    cout << "[系統] 對方拒絕接收檔案。\n";
                    continue;
                }
                if (resp != "__FILE_ACCEPT__") {
                    cout << "[系統] 未知回覆：" << resp << "\n";
                    continue;
                }

                // 開始送檔（chunk）
                FILE* f = fopen(path.c_str(), "rb");
                if (!f) {
                    cout << "[系統] 無法開啟檔案讀取。\n";
                    continue;
                }

                const uint32_t CHUNK = 64 * 1024;
                vector<unsigned char> buf(CHUNK);
                uint64_t sent = 0;

                while (sent < fsz) {
                    size_t need = (size_t)min<uint64_t>(CHUNK, fsz - sent);
                    size_t rsz = fread(buf.data(), 1, need, f);
                    if (rsz != need) {
                        cout << "[系統] 讀檔失敗，中止傳送。\n";
                        break;
                    }
                    if (!send_blob(chat_fd, 'F', buf.data(), (uint32_t)rsz)) {
                        cout << "[系統] 傳送 chunk 失敗，中止。\n";
                        break;
                    }
                    sent += (uint64_t)rsz;
                }

                fclose(f);

                // 結尾
                secure_send(chat_fd, "__FILE_END__");
                cout << "[系統] 檔案傳送完成: " << fname << " (" << fsz << " bytes)\n";
            }
            else if (!line.empty()) {
                secure_send(chat_fd, line);
            }
        }

        // ===== 對方訊息 / 檔案 / 離線 =====
        if (FD_ISSET(chat_fd, &readfds)) {
            string msg;
            if (!secure_recv(chat_fd, msg)) {
                cout << "\n[系統] 對方連線中斷，聊天室結束。\n";
                close_recv();
                running = false;
            } else if (msg == "__EXIT__") {
                cout << "\n[系統] 對方已離開聊天室。\n";
                close_recv();
                running = false;
            }
            // 收到檔案邀請
            else if (msg.rfind("__FILE_OFFER__ ", 0) == 0) {
                // __FILE_OFFER__ <filename> <size>
                istringstream iss(msg);
                string tag, fname;
                uint64_t fsz;
                iss >> tag >> fname >> fsz;

                if (fname.empty() || !iss) {
                    secure_send(chat_fd, "__FILE_REJECT__");
                    continue;
                }

                // 你的「自訂接收方式」：自動接受 + 存到 recv_<filename>
                string save_as = "recv_" + fname;

                rf = fopen(save_as.c_str(), "wb");
                if (!rf) {
                    cout << "[系統] 無法建立接收檔案：" << save_as << "\n";
                    secure_send(chat_fd, "__FILE_REJECT__");
                    close_recv();
                    continue;
                }

                receiving = true;
                recv_total = fsz;
                recv_got = 0;
                recv_name = save_as;

                secure_send(chat_fd, "__FILE_ACCEPT__");
                cout << "[系統] 開始接收檔案: " << fname << " -> " << save_as
                     << " (" << fsz << " bytes)\n";
            }
            // 收到檔案結束
            else if (msg == "__FILE_END__") {
                if (receiving) {
                    fclose(rf); rf = nullptr;
                    cout << "[系統] 檔案接收完成: " << recv_name
                         << " (" << recv_got << "/" << recv_total << " bytes)\n";
                }
                close_recv();
            }
            else {
                // 可能是 BLOB chunk 或一般聊天文字
                char type = 0;
                const unsigned char* data = nullptr;
                uint32_t len = 0;

                if (parse_blob(msg, type, data, len) && type == 'F') {
                    if (receiving && rf) {
                        if (len > 0) {
                            size_t w = fwrite(data, 1, len, rf);
                            if (w != len) {
                                cout << "\n[系統] 寫檔失敗，停止接收。\n";
                                close_recv();
                            } else {
                                recv_got += (uint64_t)len;
                            }
                        }
                    } else {
                        // 沒在接收狀態卻收到 chunk：忽略
                    }
                } else {
                    // 一般文字訊息
                    if (!msg.empty()) {
                        cout << peer_id << ": " << msg << "\n" << flush;
                    }
                }
            }
        }
    }

    fcntl(STDIN_FILENO, F_SETFL, old_flags);
    close_recv();

    close(chat_fd);

    pthread_mutex_lock(&g_chat_mtx);
    g_in_chat = false;
    g_chat_fd = -1;
    g_chat_peer_id.clear();
    pthread_mutex_unlock(&g_chat_mtx);

    cout << "[系統] 聊天已結束，返回指令模式。\n";
}

static void run_group_session(int server_fd, const string& room) {
    cout << "=== 群聊房間 '" << room << "' ===\n";
    cout << "輸入訊息後 Enter 送出，輸入 /exit 離開群聊回到 cmd>。\n";

    fd_set readfds;
    bool running = true;

    int old_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, old_flags | O_NONBLOCK);

    while (running) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(server_fd, &readfds);
        int maxfd = max(STDIN_FILENO, server_fd) + 1;

        int ret = select(maxfd, &readfds, nullptr, nullptr, nullptr);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        // 使用者輸入
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            string line;
            if (!getline(cin, line)) {
                running = false;
            } else if (line == "/exit") {
                secure_send(server_fd, "GLEAVE " + room);
                // 不強制等待回覆也行，但等一下比較乾淨
                string resp; secure_recv(server_fd, resp);
                running = false;
            } else if (!line.empty()) {
                secure_send(server_fd, "GMSG " + room + " " + line);
            }
        }

        // 伺服器推播（群聊訊息）
        if (FD_ISSET(server_fd, &readfds)) {
            string msg;
            if (!secure_recv(server_fd, msg)) {
                cout << "\n[系統] 與 server 連線中斷，返回 cmd>。\n";
                running = false;
                break;
            }
            
            // 只處理 GROOM / GNOTICE（其他回覆也印出來避免卡住）
            if (msg.rfind("GROOM ", 0) == 0) {
                // GROOM <room> <seq> <sender> <text...>
                istringstream iss(msg);
                string tag, r, sender;
                uint64_t seq;
                iss >> tag >> r >> seq >> sender;
                string text;
                getline(iss, text);
                if (!text.empty() && text[0] == ' ') text.erase(0, 1);

                if (r == room) {
                    // 自己打的訊息不要再顯示一次
                    if (sender != g_my_id) {
                        cout << sender << ": " << text << "\n" << flush;
                    }
                }
            }
            else if (msg.rfind("GNOTICE ", 0) == 0) {
                // GNOTICE <room> <seq> <text...>
                istringstream iss(msg);
                string tag, r;
                uint64_t seq;
                iss >> tag >> r >> seq;

                string text;
                getline(iss, text);
                if (!text.empty() && text[0] == ' ') text.erase(0, 1);

                if (r == room) {
                    // 只印通知文字給使用者
                    cout << text << "\n" << flush;
                }
            }
            else {
                // 其他 server 回覆（例如 OK / ERROR），照樣印出避免卡住
                cout << msg << "\n" << flush;
            }
        }
    }

    fcntl(STDIN_FILENO, F_SETFL, old_flags);
    cout << "[系統] 已離開群聊房間，返回指令模式。\n";
}

// ======== P2P listener：收到 INVITE（加密）後通知主線程 accept/reject ========

void* p2p_listener(void* arg) {
    int listen_port = *(int*)arg;
    delete (int*)arg;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("[P2P] socket"); return nullptr; }

    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(lfd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("[P2P] bind"); close(lfd); return nullptr; }
    if (listen(lfd, 5) < 0) { perror("[P2P] listen"); close(lfd); return nullptr; }

    while (true) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("[P2P] accept");
            continue;
        }

        // 期待收到加密的 "INVITE <peer_id>"
        string first;
        if (!secure_recv(cfd, first)) {
            close(cfd);
            continue;
        }

        istringstream iss(first);
        string cmd, peer_id;
        iss >> cmd >> peer_id;
        if (cmd != "INVITE" || peer_id.empty()) {
            secure_send(cfd, "REJECT");
            close(cfd);
            continue;
        }

        pthread_mutex_lock(&g_chat_mtx);
        if (g_in_chat || g_pending_has) {
            pthread_mutex_unlock(&g_chat_mtx);
            secure_send(cfd, "REJECT busy");
            close(cfd);
            continue;
        }

        g_pending_fd = cfd;
        g_pending_peer_id = peer_id;
        g_pending_has = true;
        g_chat_action = 0;
        pthread_mutex_unlock(&g_chat_mtx);

        cout << "\n[P2P] 使用者 '" << peer_id << "' 想和你聊天。\n";
        cout << "     請在 cmd> 輸入: accept 或 reject\n";
        cout << "cmd> " << flush;

        pthread_mutex_lock(&g_chat_mtx);
        while (g_chat_action == 0) {
            pthread_cond_wait(&g_chat_cv, &g_chat_mtx);
        }
        int action = g_chat_action;
        g_chat_action = 0;
        pthread_mutex_unlock(&g_chat_mtx);

        if (action == 2) {
            secure_send(cfd, "REJECT");
            close(cfd);

            pthread_mutex_lock(&g_chat_mtx);
            g_pending_fd = -1;
            g_pending_peer_id.clear();
            g_pending_has = false;
            pthread_mutex_unlock(&g_chat_mtx);
            continue;
        }

        if (action == 1) {
            secure_send(cfd, "ACCEPT");

            pthread_mutex_lock(&g_chat_mtx);
            g_chat_fd = g_pending_fd;
            g_chat_peer_id = g_pending_peer_id;
            g_in_chat = true;
            g_pending_fd = -1;
            g_pending_peer_id.clear();
            g_pending_has = false;
            pthread_mutex_unlock(&g_chat_mtx);
            continue;
        }

        close(cfd);
    }

    close(lfd);
    return nullptr;
}

// ======== 透過 LIST（加密）取得目標 port ========

static bool get_peer_port_from_server(int server_fd, const string &target_id, int &peer_port) {
    if (!secure_send(server_fd, "LIST")) return false;

    string resp;
    if (!secure_recv(server_fd, resp)) return false;

    // resp 可能多行：用 '\n' split
    istringstream iss(resp);
    string line;
    bool found = false;

    // 第一行 Total number...
    getline(iss, line);

    while (getline(iss, line)) {
        if (line.empty()) continue;
        auto pos = line.find(':');
        if (pos == string::npos) continue;
        string uid = trim(line.substr(0, pos));
        string port = trim(line.substr(pos + 1));
        if (uid == target_id) {
            try {
                peer_port = stoi(port);
                found = true;
                break;
            } catch (...) {
                return false;
            }
        }
    }

    if (!found) {
        cout << "使用者 '" << target_id << "' 不在線上或不存在。\n";
    }
    return found;
}

// ======== 發起 P2P chat（加密） ========

static void start_outgoing_chat(int server_fd, const string &peer_id) {
    int peer_port = -1;
    if (!get_peer_port_from_server(server_fd, peer_id, peer_port)) return;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("[chat] socket"); return; }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)peer_port);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);

    if (connect(fd, (sockaddr*)&peer, sizeof(peer)) < 0) {
        perror("[chat] connect");
        close(fd);
        return;
    }

    // 加密送 INVITE
    if (!secure_send(fd, "INVITE " + g_my_id)) {
        close(fd);
        return;
    }

    // 等加密回覆
    string resp;
    if (!secure_recv(fd, resp)) {
        close(fd);
        return;
    }

    if (resp.rfind("ACCEPT", 0) == 0) {
        pthread_mutex_lock(&g_chat_mtx);
        if (g_in_chat) {
            pthread_mutex_unlock(&g_chat_mtx);
            close(fd);
            return;
        }
        g_chat_fd = fd;
        g_chat_peer_id = peer_id;
        g_in_chat = true;
        pthread_mutex_unlock(&g_chat_mtx);

        run_chat_session();
        return;
    } else {
        cout << "[chat] 對方拒絕聊天：" << resp << endl;
        close(fd);
        return;
    }
}

int main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();

    string server_ip = (argc>=2)? argv[1] : "127.0.0.1";
    int server_port  = (argc>=3)? stoi(argv[2]) : 8888;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons((uint16_t)server_port);
    if (inet_pton(AF_INET, server_ip.c_str(), &srv.sin_addr) != 1) {
        cerr << "無效的 IP 位址: " << server_ip << endl;
        close(sfd);
        return 1;
    }
    if (connect(sfd, (sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect");
        close(sfd);
        return 1;
    }

    cout << "Connected to server.\n"
         << "\033[1;36m================= 指令清單 ========================\033[0m\n"
         << "\033[1;33m  register <id> <pw>\033[0m        - 註冊帳號\n"
         << "\033[1;33m  login <id> <pw> <port>\033[0m    - 登入並指定 P2P 監聽 port\n"
         << "\033[1;33m  logout\033[0m                    - 登出\n"
         << "\033[1;33m  list\033[0m                      - 顯示線上使用者\n"
         << "\033[1;33m  chat <id>\033[0m                 - 發起 P2P 聊天邀請\n"
         << "\033[1;33m  group <room>\033[0m              - 進入群聊房間(relay mode)\n"
         << "\033[1;33m  quit\033[0m                      - 離開程式\n"
         << "\033[1;36m===================================================\033[0m\n";

    bool p2p_started = false;

    while (true) {
        cout << "cmd> ";
        string line;
        if (!getline(cin, line)) break;

        istringstream iss(line);
        string cmd;
        iss >> cmd;

        if (cmd == "register") {
            string id, pw;
            if (!(iss >> id >> pw)) {
                cout << "Wrong input, 正確指令: register <id> <pw>\n";
                continue;
            }
            secure_send(sfd, "REGISTER " + id + " " + pw);
            string resp;
            if (secure_recv(sfd, resp)) cout << resp << endl;

        } else if (cmd == "login") {
            if (!g_my_id.empty()) {
                cout << "已以帳號 '" << g_my_id << "' 登入，請先 logout。\n";
                continue;
            }
            string id, pw, sport;
            int port = -1;
            if (!(iss >> id >> pw >> sport)) {
                cout << "Wrong input, 正確指令: login <id> <pw> <port>\n";
                continue;
            }
            try {
                size_t idx = 0;
                long p = stol(sport, &idx);
                if (idx != sport.size()) throw invalid_argument("non-numeric");
                if (p < 1024 || p > 65535) throw out_of_range("range");
                port = (int)p;
            } catch (...) {
                cout << "Error: port 必須是 1024~65535 的整數\n";
                continue;
            }

            secure_send(sfd, "LOGIN " + id + " " + pw + " " + to_string(port));
            string resp;
            if (secure_recv(sfd, resp)) {
                cout << resp << endl;
                if (resp.rfind("OK", 0) == 0) {
                    g_my_id = id;
                    g_listen_port = port;

                    if (!p2p_started) {
                        int *parg = new int(port);
                        pthread_t tid;
                        if (pthread_create(&tid, nullptr, p2p_listener, parg) == 0) {
                            pthread_detach(tid);
                            p2p_started = true;
                        } else {
                            delete parg;
                        }
                    }
                }
            }

        } else if (cmd == "logout") {
            if (g_my_id.empty()) {
                cout << "尚未登入\n";
                continue;
            }
            if (g_in_chat) {
                cout << "目前在聊天室中，請先輸入 /exit 離開。\n";
                continue;
            }
            secure_send(sfd, "LOGOUT " + g_my_id);
            string resp;
            if (secure_recv(sfd, resp)) {
                cout << resp << endl;
                if (resp.rfind("OK", 0) == 0) g_my_id.clear();
            }

        } else if (cmd == "list") {
            secure_send(sfd, "LIST");
            string resp;
            if (secure_recv(sfd, resp)) cout << resp;

        } else if (cmd == "chat") {
            if (g_my_id.empty()) {
                cout << "請先 login 再使用 chat。\n";
                continue;
            }
            if (g_in_chat) {
                cout << "目前已在聊天室中，不能再發起新的聊天。\n";
                continue;
            }
            string peer_id;
            if (!(iss >> peer_id)) {
                cout << "用法: chat <user_id>\n";
                continue;
            }
            if (peer_id == g_my_id) {
                cout << "ERROR: 不能對自己發起聊天。\n";
                continue;
            }
            start_outgoing_chat(sfd, peer_id);

        } else if (cmd == "accept" || cmd == "reject") {
            pthread_mutex_lock(&g_chat_mtx);
            if (!g_pending_has) {
                pthread_mutex_unlock(&g_chat_mtx);
                cout << "目前沒有待處理的聊天邀請。\n";
                continue;
            }
            g_chat_action = (cmd == "accept") ? 1 : 2;
            pthread_cond_signal(&g_chat_cv);
            pthread_mutex_unlock(&g_chat_mtx);

            if (cmd == "accept") {
                usleep(100 * 1000);

                pthread_mutex_lock(&g_chat_mtx);
                bool can_chat = g_in_chat && g_chat_fd != -1;
                pthread_mutex_unlock(&g_chat_mtx);

                if (can_chat) run_chat_session();
                else cout << "[accept] 建立聊天室失敗。\n";
            }

        }
        else if (cmd == "group") {
            if (g_my_id.empty()) {
                cout << "請先 login 再使用 group。\n";
                continue;
            }
            string room;
            if (!(iss >> room)) {
                cout << "用法: group <room>\n";
                continue;
            }

            // 加入房間
            secure_send(sfd, "GJOIN " + room);
            string resp;
            if (!secure_recv(sfd, resp)) {
                cout << "ERROR: server disconnected\n";
                break;
            }
            cout << resp << endl;
            if (resp.rfind("OK", 0) != 0) continue;

            // 進入群聊模式（relay）
            run_group_session(sfd, room);
        }
        else if (cmd == "quit") {
            if (g_in_chat) {
                cout << "目前在聊天室中，請先輸入 /exit 離開。\n";
                continue;
            }
            if (!g_my_id.empty()) {
                secure_send(sfd, "LOGOUT " + g_my_id);
                string resp;
                secure_recv(sfd, resp);
                g_my_id.clear();
            }
            cout << "Connection closed. Goodbye!\n";
            break;

        } else if (!cmd.empty()) {
            cout << "Unknown command\n";
        }
    }

    close(sfd);
    return 0;
}