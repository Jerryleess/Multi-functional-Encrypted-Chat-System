// =============================
// server.cpp
// Multithread worker-pool chat server (up to 10 concurrent clients) + OpenSSL encryption (Base)
// + Group chatting (relay mode, ordered) + join/leave notifications (basic)
// Build: g++ -std=c++17 -pthread server.cpp -o server -lssl -lcrypto
// Run:   ./server 8888
// =============================

#include "header.h"
#include "func.h"

using namespace std;

// ======= 原本 server 功能 =======

struct User {
    string password;
    int port = -1;
    bool online = false;
};

unordered_map<string, User> users;
// fd -> user id
unordered_map<int, string> fd_to_user;

pthread_mutex_t users_mtx = PTHREAD_MUTEX_INITIALIZER;

// ===== 工作佇列（worker pool 用） =====
queue<int> client_queue;
pthread_mutex_t queue_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cv = PTHREAD_COND_INITIALIZER;

static const int MAX_WORKERS = 10;

// ===== 群聊房間 =====
struct Room {
    unordered_set<int> members;
    uint64_t seq = 0;
};

unordered_map<string, Room> rooms;
pthread_mutex_t rooms_mtx = PTHREAD_MUTEX_INITIALIZER;

// ===== 小工具：取得 fd 對應 user id（已登入才會有）=====
static string get_userid_by_fd(int fd) {
    pthread_mutex_lock(&users_mtx);
    auto it = fd_to_user.find(fd);
    string uid = (it != fd_to_user.end()) ? it->second : "";
    pthread_mutex_unlock(&users_mtx);
    return uid;
}

// ===== 小工具：把 fd 從所有房間移除，並通知其他人（logout / disconnect 共用）=====
static void remove_fd_from_all_rooms_and_notify(int fd, const string& uid) {
    if (uid.empty()) {
        // 沒有 uid 就不送通知，但仍可清理房間（保守）
        pthread_mutex_lock(&rooms_mtx);
        for (auto it = rooms.begin(); it != rooms.end(); ) {
            it->second.members.erase(fd);
            if (it->second.members.empty()) it = rooms.erase(it);
            else ++it;
        }
        pthread_mutex_unlock(&rooms_mtx);
        return;
    }

    pthread_mutex_lock(&rooms_mtx);

    for (auto it = rooms.begin(); it != rooms.end(); ) {
        Room &rm = it->second;
        const string room_name = it->first;

        bool was_member = (rm.members.erase(fd) > 0);
        if (was_member) {
            // 送離開通知給剩下的人
            uint64_t seq = ++rm.seq;
            string notice = "GNOTICE " + room_name + " " + to_string(seq) + " " + uid + " left the room";
            for (int mfd : rm.members) {
                secure_send(mfd, notice);
            }
        }

        if (rm.members.empty()) it = rooms.erase(it);
        else ++it;
    }

    pthread_mutex_unlock(&rooms_mtx);
}

// ===== 真正處理一個 client 的邏輯（在 worker 裡呼叫） =====
static void serve_client(int fd) {
    string line;
    while (secure_recv(fd, line)) {
        istringstream iss(line);
        string cmd; iss >> cmd;

        if (cmd == "REGISTER") {
            string id, pw; iss >> id >> pw;
            string resp;

            pthread_mutex_lock(&users_mtx);
            if (users.count(id)) resp = "ERROR, the user already exists";
            else {
                users[id] = User{pw, -1, false};
                resp = "OK Registered";
            }
            pthread_mutex_unlock(&users_mtx);

            secure_send(fd, resp);
        }

        else if (cmd == "LOGIN") {
            string id, pw; int port;
            string resp;
            if (!(iss >> id >> pw >> port)) {
                secure_send(fd, "ERROR, Wrong arguments");
                continue;
            }
            if (port < 1024 || port > 65535) {
                secure_send(fd, "ERROR, Invalid port");
                continue;
            }

            pthread_mutex_lock(&users_mtx);
            bool conflict = false;
            for (const auto &kv : users) {
                if (kv.first != id && kv.second.online && kv.second.port == port) {
                    conflict = true;
                    break;
                }
            }
            if (!users.count(id)) resp = "ERROR, No such user";
            else if (users[id].password != pw) resp = "ERROR, Wrong password";
            else if (users[id].online) resp = "ERROR, already online";
            else if (conflict) resp = "ERROR, Port in use";
            else {
                users[id].online = true;
                users[id].port = port;
                fd_to_user[fd] = id;   // 紀錄此連線的使用者
                resp = "OK LoggedIn";
            }
            pthread_mutex_unlock(&users_mtx);

            secure_send(fd, resp);
        }

        else if (cmd == "LOGOUT") {
            string id; iss >> id;
            string resp;

            bool do_remove_rooms = false;
            pthread_mutex_lock(&users_mtx);
            if (!users.count(id) || !users[id].online) resp = "ERROR, Not online";
            else {
                users[id].online = false;
                users[id].port = -1;
                auto it = fd_to_user.find(fd);
                if (it != fd_to_user.end() && it->second == id) {
                    fd_to_user.erase(it);
                }
                resp = "OK LoggedOut";
                do_remove_rooms = true;
            }
            pthread_mutex_unlock(&users_mtx);

            // 先回應 logout，再清理房間（避免 client 端卡住等待 resp）
            secure_send(fd, resp);

            if (do_remove_rooms) {
                remove_fd_from_all_rooms_and_notify(fd, id);
            }
        }

        else if (cmd == "LIST") {
            ostringstream oss;
            pthread_mutex_lock(&users_mtx);
            int cnt = 0;
            for (auto &u : users) if (u.second.online) cnt++;
            oss << "Total number of online users: " << cnt << "\n";
            for (auto &u : users) if (u.second.online)
                oss << u.first << ": " << u.second.port << "\n";
            pthread_mutex_unlock(&users_mtx);

            secure_send(fd, oss.str());
        }

        // ===== 群聊：加入 =====
        else if (cmd == "GJOIN") {
            string room;
            iss >> room;
            if (room.empty()) {
                secure_send(fd, "ERROR, Wrong arguments");
                continue;
            }

            string uid = get_userid_by_fd(fd);
            if (uid.empty()) {
                secure_send(fd, "ERROR, Please login first");
                continue;
            }

            pthread_mutex_lock(&rooms_mtx);
            Room &rm = rooms[room];
            bool inserted = rm.members.insert(fd).second;

            if (inserted) {
                // 通知房內其他人
                uint64_t seq = ++rm.seq;
                string notice = "GNOTICE " + room + " " + to_string(seq) + " " + uid + " joined the room";
                for (int mfd : rm.members) {
                    if (mfd == fd) continue; // 不通知自己（你若也想自己看到就刪掉這行）
                    secure_send(mfd, notice);
                }
            }
            pthread_mutex_unlock(&rooms_mtx);

            secure_send(fd, "OK Joined " + room);
        }

        // ===== 群聊：離開 =====
        else if (cmd == "GLEAVE") {
            string room;
            iss >> room;
            if (room.empty()) {
                secure_send(fd, "ERROR, Wrong arguments");
                continue;
            }

            string uid = get_userid_by_fd(fd);
            if (uid.empty()) {
                secure_send(fd, "ERROR, Please login first");
                continue;
            }

            pthread_mutex_lock(&rooms_mtx);
            auto it = rooms.find(room);
            if (it != rooms.end()) {
                Room &rm = it->second;
                bool was_member = (rm.members.erase(fd) > 0);

                if (was_member) {
                    uint64_t seq = ++rm.seq;
                    string notice = "GNOTICE " + room + " " + to_string(seq) + " " + uid + " left the room";
                    for (int mfd : rm.members) {
                        secure_send(mfd, notice);
                    }
                }

                if (rm.members.empty()) rooms.erase(it);
            }
            pthread_mutex_unlock(&rooms_mtx);

            secure_send(fd, "OK Left " + room);
        }

        // ===== 群聊：發送訊息 =====
        else if (cmd == "GMSG") {
            string room;
            iss >> room;
            string msg;
            getline(iss, msg);
            if (!msg.empty() && msg[0] == ' ') msg.erase(0, 1);

            if (room.empty()) {
                secure_send(fd, "ERROR, Wrong arguments");
                continue;
            }

            string sender = get_userid_by_fd(fd);
            if (sender.empty()) {
                secure_send(fd, "ERROR, Please login first");
                continue;
            }

            pthread_mutex_lock(&rooms_mtx);
            auto rit = rooms.find(room);
            if (rit == rooms.end() || rit->second.members.count(fd) == 0) {
                pthread_mutex_unlock(&rooms_mtx);
                secure_send(fd, "ERROR, Not in room");
                continue;
            }

            uint64_t seq = ++rit->second.seq;

            // broadcast 格式：GROOM <room> <seq> <sender> <msg>
            string out = "GROOM " + room + " " + to_string(seq) + " " + sender + " " + msg;

            for (int mfd : rit->second.members) {
                secure_send(mfd, out);
            }
            pthread_mutex_unlock(&rooms_mtx);
        }

        else {
            secure_send(fd, "ERROR, Unknown command");
        }
    }

    // ===== secure_recv 回傳 false：連線關閉/錯誤 → 自動下線 + 離開房間通知 =====
    string uid = get_userid_by_fd(fd);
    if (!uid.empty()) {
        // users 狀態設 offline
        pthread_mutex_lock(&users_mtx);
        auto u_it = users.find(uid);
        if (u_it != users.end()) {
            u_it->second.online = false;
            u_it->second.port = -1;
        }
        fd_to_user.erase(fd);
        pthread_mutex_unlock(&users_mtx);
    }

    // 清理房間並通知其他人
    remove_fd_from_all_rooms_and_notify(fd, uid);

    close(fd);
}

// ===== worker thread 主函式：從佇列取出 fd → serve_client =====
void* worker_main(void*) {
    while (true) {
        int fd;
        pthread_mutex_lock(&queue_mtx);
        while (client_queue.empty()) {
            pthread_cond_wait(&queue_cv, &queue_mtx);
        }
        fd = client_queue.front();
        client_queue.pop();
        pthread_mutex_unlock(&queue_mtx);

        serve_client(fd);
    }
    return nullptr;
}

int main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();

    int port = (argc >= 2) ? stoi(argv[1]) : 8888;

    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(listenfd, SOMAXCONN) < 0) {
        perror("listen"); return 1;
    }

    cout << "Server listening on 127.0.0.1:" << port << endl;

    // ===== 建立 worker pool（10 個 pthread）=====
    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; ++i) {
        pthread_create(&workers[i], nullptr, worker_main, nullptr);
        pthread_detach(workers[i]);
    }

    // ===== 主執行緒：accept() 後丟到佇列 =====
    while (true) {
        int cfd = accept(listenfd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pthread_mutex_lock(&queue_mtx);
        client_queue.push(cfd);
        pthread_cond_signal(&queue_cv);
        pthread_mutex_unlock(&queue_mtx);
    }
}