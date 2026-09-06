#include "mime.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <utility>

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string qp_decode(const std::string& in) {
    std::string out;
    auto hex = [](char h) -> int {
        if (h >= '0' && h <= '9') return h - '0';
        if (h >= 'a' && h <= 'f') return h - 'a' + 10;
        if (h >= 'A' && h <= 'F') return h - 'A' + 10;
        return 0;
    };
    size_t i = 0;
    while (i < in.size()) {
        char c = in[i];
        if (c == '=' && i + 2 < in.size()) {
            char h1 = in[i + 1];
            if (h1 == '\r' && i + 3 <= in.size() && in[i + 2] == '\n') {
                i += 3;
                continue;
            }
            if (h1 == '\n') {
                i += 2;
                continue;
            }
            if (std::isxdigit(static_cast<unsigned char>(h1)) &&
                std::isxdigit(static_cast<unsigned char>(in[i + 2]))) {
                out += static_cast<char>((hex(h1) << 4) | hex(in[i + 2]));
                i += 3;
                continue;
            }
        }
        out += c;
        i++;
    }
    return out;
}

std::string decode_entities(const std::string& s) {
    static const std::pair<const char*, const char*> reps[] = {
        {"&nbsp;", " "},   {"&amp;", "&"},    {"&lt;", "<"},     {"&gt;", ">"},
        {"&quot;", "\""},  {"&apos;", "'"},   {"&#39;", "'"},    {"&#x27;", "'"},
        {"&#34;", "\""},   {"&#x22;", "\""},  {"&mdash;", "--"}, {"&ndash;", "-"},
        {"&hellip;", "..."}, {"&trade;", "(tm)"}, {"&copy;", "(c)"}, {"&reg;", "(r)"},
    };
    std::string out = s;
    for (const auto& r : reps) {
        std::string from = r.first;
        std::string to = r.second;
        size_t p = 0;
        while ((p = out.find(from, p)) != std::string::npos) {
            out.replace(p, from.size(), to);
            p += to.size();
        }
    }
    return out;
}

std::string html_to_text(const std::string& in) {
    std::string out;
    bool inTag = false;
    for (char c : in) {
        if (c == '<') {
            inTag = true;
            continue;
        }
        if (c == '>') {
            inTag = false;
            continue;
        }
        if (!inTag) out += c;
    }
    return decode_entities(out);
}

std::string decode_body(const std::string& body, const std::string& encoding,
                        const std::string& ctype) {
    std::string enc = lower(trim(encoding));
    if (enc == "base64") return trim(base64_decode(body));
    if (enc == "quoted-printable") return trim(qp_decode(body));
    if (lower(ctype).find("text/html") != std::string::npos)
        return trim(html_to_text(body));
    return trim(body);
}

}  // namespace

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

std::string base64_decode(const std::string& in) {
    static const std::string tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = -8;
    std::string out;
    for (unsigned char c : in) {
        if (c == '=') break;
        size_t p = tbl.find(static_cast<char>(c));
        if (p == std::string::npos) continue;
        val = (val << 6) + static_cast<int>(p);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::string base64_encode(const std::string& in) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out += tbl[(val >> bits) & 0x3F];
            bits -= 6;
        }
    }
    if (bits > -6) out += tbl[((val << 8) >> (bits + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

static std::string q_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '_') {
            out += ' ';
        } else if (s[i] == '=' && i + 2 < s.size()) {
            auto hex = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return 0;
            };
            out += static_cast<char>((hex(s[i + 1]) << 4) | hex(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string rfc2047_decode(const std::string& in) {
    std::string out;
    size_t i = 0;
    while (i < in.size()) {
        size_t start = in.find("=?", i);
        if (start == std::string::npos) {
            out += in.substr(i);
            break;
        }
        out += in.substr(i, start - i);
        size_t end = in.find("?=", start + 2);
        if (end == std::string::npos) {
            out += in.substr(start);
            break;
        }
        std::string token = in.substr(start + 2, end - (start + 2));
        size_t p1 = token.find('?');
        size_t p2 = token.find('?', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) {
            out += in.substr(start, end - start + 2);
            i = end + 2;
            continue;
        }
        std::string encoding = token.substr(p1 + 1, p2 - p1 - 1);
        std::string payload = token.substr(p2 + 1);
        if (encoding == "B" || encoding == "b") {
            out += base64_decode(payload);
        } else if (encoding == "Q" || encoding == "q") {
            out += q_decode(payload);
        } else {
            out += payload;
        }
        i = end + 2;
    }
    return trim(out);
}

std::string header_value(const std::string& block, const std::string& name) {
    std::string needle = lower(name) + ":";
    std::string result;
    bool captured = false;
    size_t pos = 0;
    while (pos <= block.size()) {
        size_t nl = block.find('\n', pos);
        if (nl == std::string::npos) nl = block.size();
        std::string line = block.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        pos = nl + 1;

        bool continuation = !line.empty() && (line[0] == ' ' || line[0] == '\t');
        if (continuation && captured) {
            result += " " + trim(line);
            continue;
        }
        captured = false;
        if (lower(line).rfind(needle, 0) == 0) {
            result = trim(line.substr(needle.size()));
            captured = true;
        }
    }
    return trim(result);
}

std::string mime_body_text(const std::string& raw) {
    size_t sep = raw.find("\r\n\r\n");
    size_t sepLen = 4;
    if (sep == std::string::npos) {
        sep = raw.find("\n\n");
        sepLen = 2;
    }
    if (sep == std::string::npos) return {};
    std::string headers = raw.substr(0, sep);
    std::string body = raw.substr(sep + sepLen);

    std::string ctype = lower(header_value(headers, "Content-Type"));
    std::string enc = header_value(headers, "Content-Transfer-Encoding");

    if (ctype.find("multipart/") == std::string::npos)
        return decode_body(body, enc, ctype);

    size_t bp = ctype.find("boundary=");
    if (bp == std::string::npos) return decode_body(body, enc, ctype);
    std::string bv = trim(ctype.substr(bp + 9));
    if (!bv.empty() && bv.front() == '"') {
        bv.erase(0, 1);
        size_t q = bv.find('"');
        if (q != std::string::npos) bv = bv.substr(0, q);
    } else {
        size_t sc = bv.find(';');
        if (sc != std::string::npos) bv = bv.substr(0, sc);
    }
    std::string marker = "--" + trim(bv);
    if (marker.size() == 2) return decode_body(body, enc, ctype);

    bool havePlain = false;
    bool haveHtml = false;
    std::string plain;
    std::string html;
    std::string part;
    bool inPart = false;

    auto finish_part = [&]() {
        if (part.empty()) return;
        size_t psep = part.find("\r\n\r\n");
        size_t sl = 4;
        if (psep == std::string::npos) {
            psep = part.find("\n\n");
            sl = 2;
        }
        std::string ph = psep == std::string::npos ? part : part.substr(0, psep);
        std::string pb = psep == std::string::npos ? std::string() : part.substr(psep + sl);
        std::string pct = lower(header_value(ph, "Content-Type"));
        std::string penc = header_value(ph, "Content-Transfer-Encoding");
        if (pct.find("text/plain") != std::string::npos) {
            if (havePlain)
                plain += "\n\n" + decode_body(pb, penc, pct);
            else {
                plain = decode_body(pb, penc, pct);
                havePlain = true;
            }
        } else if (pct.find("text/html") != std::string::npos && !haveHtml) {
            html = decode_body(pb, penc, pct);
            haveHtml = true;
        }
        part.clear();
    };

    size_t pos = 0;
    while (pos <= body.size()) {
        size_t nl = body.find('\n', pos);
        if (nl == std::string::npos) nl = body.size();
        std::string line = body.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        pos = nl + 1;

        if (line.rfind(marker, 0) == 0) {
            if (inPart) finish_part();
            inPart = true;
            if (line == marker + "--") break;
        } else if (inPart) {
            part += line + "\n";
        }
    }
    if (havePlain) return trim(plain);
    if (haveHtml) return trim(html_to_text(html));
    return {};
}

std::string first_id(const std::string& s) {
    std::string t = trim(s);
    size_t a = t.find('<');
    if (a != std::string::npos) {
        size_t b = t.find('>', a + 1);
        if (b != std::string::npos) return trim(t.substr(a + 1, b - a - 1));
    }
    size_t sp = t.find_first_of(" \t\r\n");
    if (sp != std::string::npos) t = t.substr(0, sp);
    return trim(t);
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 16);
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '\\': o += "\\\\"; break;
            case '"': o += "\\\""; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            case '<':
                if (i + 1 < s.size() && s[i + 1] == '/') o += "<\\/";
                else o += '<';
                break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}