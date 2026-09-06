#include "imap.h"

#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <stdexcept>
#include <sys/select.h>
#include <sys/time.h>
#include <utility>

#include "mime.h"

static bool sock_is_pending(int e) {
    return e == EINPROGRESS || e == EALREADY;
}
static int sock_error() {
    return errno;
}
static int socket_close(int fd) {
    return ::close(fd);
}
static bool set_nonblocking(int fd, bool yes) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, yes ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
}

namespace {

const int CONNECT_TIMEOUT_S = 3;
const int IO_TIMEOUT_S = 3;

std::string ssl_error_str() {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e != 0) ERR_error_string_n(e, buf, sizeof buf);
    return buf;
}

// Connect to one resolved address with a hard timeout (non-blocking + select).
bool connect_with_timeout(int fd, const struct sockaddr* sa, socklen_t len, int secs) {
    if (!set_nonblocking(fd, true)) return false;

    bool ok = false;
    int rc = ::connect(fd, sa, static_cast<int>(len));
    if (rc == 0) {
        ok = true;
    } else if (sock_is_pending(sock_error())) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(fd, &w);
        struct timeval tv = {secs, 0};
        int sr = select(fd + 1, nullptr, &w, nullptr, &tv);
        if (sr > 0) {
            int soerr = 0;
            socklen_t sl = sizeof soerr;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0) {
                ok = true;
            }
        }
    }
    if (!set_nonblocking(fd, false)) ok = false;
    return ok;
}

// Whether an SSL failure was caused by our socket read/write timeout.
bool is_timeout() {
    int e = sock_error();
    return e == EAGAIN || e == EWOULDBLOCK;
}

std::string imap_quote(const std::string& s) {
    std::string q = "\"";
    for (char c : s) {
        if (c == '\\' || c == '"') q += '\\';
        q += c;
    }
    q += '"';
    return q;
}

// If the line ends with a literal marker `{N}` returns N, else -1.
long trailing_literal_size(const std::string& line) {
    if (line.empty() || line.back() != '}') return -1;
    size_t open = line.find_last_of('{');
    if (open == std::string::npos) return -1;
    std::string num = line.substr(open + 1, line.size() - open - 2);
    if (num.empty()) return -1;
    for (char c : num) if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
    return std::strtol(num.c_str(), nullptr, 10);
}

// Extract flags between "FLAGS (" and its closing ")" if present.
std::string extract_flags(const std::string& line) {
    size_t p = line.find("FLAGS ");
    if (p == std::string::npos) return {};
    p += 6;
    while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) p++;
    if (p >= line.size() || line[p] != '(') return {};
    size_t close = line.find(')', p);
    if (close == std::string::npos) return {};
    return line.substr(p + 1, close - p - 1);
}

// Parse a mailbox name out of `* LIST (...)` response lines.
std::string parse_list_name(const std::string& line) {
    size_t close = line.find(')');
    if (close == std::string::npos) return {};
    size_t q1 = line.find('"', close);
    if (q1 == std::string::npos) return {};
    size_t q2 = line.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    size_t q3 = line.find('"', q2 + 1);
    if (q3 == std::string::npos) return trim(line.substr(q2 + 1));
    std::string name;
    for (size_t i = q3 + 1; i < line.size(); i++) {
        if (line[i] == '"') break;
        if (line[i] == '\\' && i + 1 < line.size()) {
            name += line[i + 1];
            i++;
        } else {
            name += line[i];
        }
    }
    return name;
}

// --- modified UTF-7 (RFC 3501, section 5.1.3) ---

int modb64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == ',') return 63;
    return -1;
}

bool base64_modified_decode(const std::string& in, std::vector<unsigned char>& out) {
    int val = 0, bits = 0;
    for (char ch : in) {
        int v = modb64_val(static_cast<unsigned char>(ch));
        if (v < 0) return false;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xff));
        }
    }
    return true;
}

std::string utf16be_to_utf8(const std::vector<unsigned char>& bytes) {
    std::string out;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        unsigned int cp = (static_cast<unsigned int>(bytes[i]) << 8) | bytes[i + 1];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < bytes.size()) {
            unsigned int lo = (static_cast<unsigned int>(bytes[i + 2]) << 8) | bytes[i + 3];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else {
                continue;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            continue;
        }
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

std::string decode_modified_utf7(const std::string& in) {
    std::string out;
    size_t i = 0;
    while (i < in.size()) {
        if (in[i] == '&') {
            size_t j = i + 1;
            while (j < in.size() && in[j] != '-') j++;
            std::string body = in.substr(i + 1, j - i - 1);
            if (body.empty()) {
                out += '&';
            } else {
                std::vector<unsigned char> bytes;
                if (base64_modified_decode(body, bytes)) {
                    out += utf16be_to_utf8(bytes);
                } else {
                    out += in.substr(i, j - i + 1);
                }
            }
            if (j > in.size()) break;
            i = j + 1;
        } else {
            size_t amp = in.find('&', i);
            if (amp == std::string::npos) {
                out += in.substr(i);
                break;
            }
            out += in.substr(i, amp - i);
            i = amp;
        }
    }
    return out;
}

std::string lower_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

// Parse a "* LIST (attrs) delim name" line. Skips Noselect pseudo-folders.
std::string parse_list_name2(const std::string& line, bool& noselect) {
    noselect = false;
    if (line.rfind("* LIST", 0) != 0) return {};
    size_t p0 = 6;
    while (p0 < line.size() && line[p0] == ' ') p0++;
    size_t close = line.find(')', p0);
    if (close == std::string::npos) return {};
    std::string attrs = line.substr(p0, close - p0);
    if (lower_ascii(attrs).find("noselect") != std::string::npos) noselect = true;
    size_t q1 = line.find('"', close);
    if (q1 == std::string::npos) return {};
    size_t q2 = line.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    size_t qn = line.find('"', q2 + 1);
    if (qn == std::string::npos) return {};
    std::string name;
    for (size_t i = qn + 1; i < line.size(); i++) {
        if (line[i] == '"') break;
        if (line[i] == '\\' && i + 1 < line.size()) {
            name += line[i + 1];
            i++;
        } else {
            name += line[i];
        }
    }
    return name;
}

}  // namespace

Imap::Imap() = default;
Imap::~Imap() { close(); }

void Imap::close() {
    if (ssl) {
        SSL_shutdown(static_cast<SSL*>(ssl));
        SSL_free(static_cast<SSL*>(ssl));
        ssl = nullptr;
    }
    if (ssl_ctx) {
        SSL_CTX_free(static_cast<SSL_CTX*>(ssl_ctx));
        ssl_ctx = nullptr;
    }
    if (sock >= 0) {
        ::close(sock);
        sock = -1;
    }
}

std::string Imap::next_tag() {
    return "A" + std::to_string(++tag_counter);
}

void Imap::send_raw(const std::string& s) {
    const char* p = s.data();
    size_t left = s.size();
    while (left > 0) {
        int n = SSL_write(static_cast<SSL*>(ssl), p, static_cast<int>(left));
        if (n <= 0) {
            if (is_timeout())
                throw std::runtime_error("timed out writing to server (no response for " +
                                         std::to_string(IO_TIMEOUT_S) + "s)");
            throw std::runtime_error("write failed: " + ssl_error_str());
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
}

void Imap::recv_more() {
    char tmp[16384];
    int n = SSL_read(static_cast<SSL*>(ssl), tmp, sizeof tmp);
    if (n <= 0) {
        if (is_timeout())
            throw std::runtime_error("timed out waiting for server (no data for " +
                                     std::to_string(IO_TIMEOUT_S) + "s)");
        throw std::runtime_error("connection closed: " + ssl_error_str());
    }
    buf.append(tmp, static_cast<size_t>(n));
}

std::string Imap::read_line() {
    while (true) {
        size_t p = buf.find('\n');
        if (p != std::string::npos) {
            std::string line = buf.substr(0, p);
            buf.erase(0, p + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        recv_more();
    }
}

std::string Imap::read_skip_literals() {
    std::string line = read_line();
    while (true) {
        long n = trailing_literal_size(line);
        if (n < 0) break;
        consume(static_cast<size_t>(n));
        line = read_line();
    }
    return line;
}

void Imap::consume(size_t n) {
    while (buf.size() < n) recv_more();
    buf.erase(0, n);
}

std::string Imap::consume_str(size_t n) {
    while (buf.size() < n) recv_more();
    std::string out = buf.substr(0, n);
    buf.erase(0, n);
    return out;
}

void Imap::connect(const std::string& host, int port) {
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portstr = std::to_string(port);
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), portstr.c_str(), &hints, &res);
    if (rc != 0) throw std::runtime_error("cannot resolve " + host + ": " + gai_strerror(rc));

    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, CONNECT_TIMEOUT_S)) {
            sock = fd;
            struct timeval tv = {IO_TIMEOUT_S, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            break;
        }
        ::close(fd);
    }
    freeaddrinfo(res);
    if (sock < 0)
        throw std::runtime_error("could not connect to " + host + ":" + portstr +
                                 " (timeout or refused after " +
                                 std::to_string(CONNECT_TIMEOUT_S) + "s)");

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) throw std::runtime_error("SSL_CTX_new failed");
    SSL_CTX_set_default_verify_paths(static_cast<SSL_CTX*>(ssl_ctx));

    ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx));
    if (!ssl) throw std::runtime_error("SSL_new failed");
    SSL_set_fd(static_cast<SSL*>(ssl), sock);
    SSL_set_tlsext_host_name(static_cast<SSL*>(ssl), host.c_str());
    SSL_set1_host(static_cast<SSL*>(ssl), host.c_str());
    SSL_set_connect_state(static_cast<SSL*>(ssl));

    if (SSL_connect(static_cast<SSL*>(ssl)) != 1) {
        throw std::runtime_error("TLS handshake with " + host + " failed: " + ssl_error_str());
    }

    std::string greeting = read_skip_literals();  // consume * OK greeting
    if (greeting.rfind("* OK", 0) != 0 && greeting.rfind("* PREAUTH", 0) != 0 &&
        greeting.rfind("* BYE", 0) != 0) {
        throw std::runtime_error("unexpected greeting: " + greeting);
    }
}

Imap::Reply Imap::sync(const std::string& cmd, std::vector<std::string>& untagged) {
    std::string tag = next_tag();
    send_raw(tag + " " + cmd + "\r\n");
    untagged.clear();
    while (true) {
        std::string line = read_skip_literals();
        if (line == tag || line.rfind(tag + " ", 0) == 0) {
            Reply r;
            std::string rest = line == tag ? std::string() : line.substr(tag.size() + 1);
            r.ok = rest.rfind("OK", 0) == 0;
            if (rest.rfind("NO", 0) == 0)
                r.text = rest.substr(2);
            else if (rest.rfind("BAD", 0) == 0)
                r.text = rest.substr(3);
            else if (rest.rfind("OK", 0) == 0)
                r.text = rest.substr(2);
            else
                r.text = rest;
            return r;
        }
        untagged.push_back(line);
    }
}

void Imap::login(const std::string& user, const std::string& password) {
    std::vector<std::string> untagged;
    Reply r = sync("LOGIN " + imap_quote(user) + " " + imap_quote(password), untagged);
    if (!r.ok) {
        throw std::runtime_error("login failed: " + trim(r.text));
    }
}

int Imap::select_mailbox(const std::string& mailbox) {
    std::vector<std::string> untagged;
    Reply r = sync("SELECT " + imap_quote(mailbox), untagged);
    if (!r.ok) throw std::runtime_error("SELECT " + mailbox + " failed: " + trim(r.text));
    int total = 0;
    for (const auto& line : untagged) {
        if (line.rfind("* ", 0) != 0) continue;
        std::string rest = line.substr(2);
        size_t sp = rest.find(' ');
        if (sp == std::string::npos) continue;
        std::string num = rest.substr(0, sp);
        std::string word = rest.substr(sp + 1);
        size_t sp2 = word.find(' ');
        if (sp2 != std::string::npos) word = word.substr(0, sp2);
        if (word != "EXISTS") continue;
        bool digits = true;
        for (char c : num)
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                digits = false;
                break;
            }
        if (digits) total = std::atoi(num.c_str());
    }
    return total;
}

std::vector<Imap::Mailbox> Imap::list_folders() {
    std::vector<std::string> untagged;
    Reply r = sync("LIST \"\" \"*\"", untagged);
    if (!r.ok) throw std::runtime_error("LIST failed: " + trim(r.text));
    std::vector<Mailbox> out;
    for (const auto& line : untagged) {
        bool noselect = false;
        std::string raw = parse_list_name2(line, noselect);
        if (raw.empty() || noselect) continue;
        out.push_back({raw, decode_modified_utf7(raw)});
    }
    return out;
}

std::vector<int> Imap::search(const std::string& criteria) {
    std::vector<std::string> untagged;
    Reply r = sync("SEARCH " + criteria, untagged);
    if (!r.ok) throw std::runtime_error("SEARCH " + criteria + " failed: " + trim(r.text));
    std::vector<int> out;
    for (const auto& line : untagged) {
        if (line.rfind("* SEARCH", 0) != 0) continue;
        std::string rest = line.substr(8);
        std::string num;
        for (size_t i = 0; i <= rest.size(); i++) {
            if (i < rest.size() && rest[i] != ' ') {
                num += rest[i];
            } else if (!num.empty()) {
                out.push_back(std::atoi(num.c_str()));
                num.clear();
            }
        }
    }
    return out;
}

Message Imap::fetch(int seq) {
    std::string tag = next_tag();
    std::string cmd = tag + " FETCH " + std::to_string(seq) + " (FLAGS BODY.PEEK[])";
    send_raw(cmd + "\r\n");

    Message m;
    m.seq = seq;
    bool seen = false, answered = false, flagged = false;
    std::string raw;

    while (true) {
        std::string line = read_line();
        if (line == tag || line.rfind(tag + " ", 0) == 0) break;

        std::string flags = extract_flags(line);
        if (flags.find("\\Seen") != std::string::npos) seen = true;
        if (flags.find("\\Answered") != std::string::npos) answered = true;
        if (flags.find("\\Flagged") != std::string::npos) flagged = true;

        long n = trailing_literal_size(line);
        if (n >= 0) raw = consume_str(static_cast<size_t>(n));
    }

    m.seen = seen;
    m.answered = answered;
    m.flagged = flagged;
    m.raw = std::move(raw);

    size_t sep = m.raw.find("\r\n\r\n");
    if (sep == std::string::npos) sep = m.raw.find("\n\n");
    std::string headers = m.raw.substr(0, sep);
    m.subject = rfc2047_decode(header_value(headers, "Subject"));
    m.from = rfc2047_decode(header_value(headers, "From"));
    m.date = trim(header_value(headers, "Date"));
    m.msg_id = first_id(header_value(headers, "Message-ID"));
    std::string irt = header_value(headers, "In-Reply-To");
    if (irt.empty()) irt = header_value(headers, "References");
    m.irt = first_id(irt);
    return m;
}

void Imap::logout() {
    try {
        std::vector<std::string> untagged;
        sync("LOGOUT", untagged);
    } catch (...) {
    }
    close();
}