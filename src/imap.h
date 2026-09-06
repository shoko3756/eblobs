#pragma once

#include <string>
#include <vector>

struct Message {
    int seq = 0;
    std::string subject;
    std::string from;
    std::string date;
    std::string body;
    std::string mailbox;
    std::string category;
    std::string raw;
    std::string msg_id;
    std::string irt;
    bool seen = false;
    bool answered = false;
    bool flagged = false;
};

class Imap {
public:
    struct Mailbox {
        std::string raw;
        std::string display;
    };

    Imap();
    ~Imap();

    void connect(const std::string& host, int port);
    void login(const std::string& user, const std::string& password);
    int select_mailbox(const std::string& mailbox);
    std::vector<Mailbox> list_folders();
    std::vector<int> search(const std::string& criteria);
    Message fetch(int seq);
    void logout();

private:
    void recv_more();
    std::string read_line();
    std::string read_skip_literals();
    void consume(size_t n);
    std::string consume_str(size_t n);
    void send_raw(const std::string& s);
    std::string next_tag();
    struct Reply {
        bool ok = false;
        std::string text;
    };
    Reply sync(const std::string& cmd, std::vector<std::string>& untagged);
    void close();

    int sock = -1;
    void* ssl = nullptr;
    void* ssl_ctx = nullptr;
    std::string buf;
    int tag_counter = 0;
};