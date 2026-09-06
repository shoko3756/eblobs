#include <netdb.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "imap.h"
#include "mime.h"

namespace {

std::string utf8_encode(unsigned int cp) {
    std::string out;
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
    return out;
}

// Unicode-aware lowercase for folder-name matching: ASCII, Latin-1
// (accented European letters), Greek, Cyrillic, plus German ẞ and Turkish İ.
std::string lowercase(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        unsigned char b0 = static_cast<unsigned char>(s[i]);
        unsigned int cp = b0;
        int extra = 0;
        bool lead = true;
        if (b0 < 0x80) {
            extra = 0;
        } else if ((b0 >> 5) == 0x6) {
            cp &= 0x1F; extra = 1;
        } else if ((b0 >> 4) == 0xE) {
            cp &= 0x0F; extra = 2;
        } else if ((b0 >> 3) == 0x1E) {
            cp &= 0x07; extra = 3;
        } else {
            lead = false;
        }
        if (!lead) {
            out += static_cast<char>(b0);
            i++;
            continue;
        }
        bool ok = (i + static_cast<size_t>(extra) < s.size());
        if (ok) {
            for (int k = 1; k <= extra && ok; k++) {
                unsigned char b = static_cast<unsigned char>(s[i + k]);
                if ((b >> 6) != 0x2) ok = false;
                else cp = (cp << 6) | (b & 0x3F);
            }
            unsigned int minv = extra == 0 ? 0 : (extra == 1 ? 0x80 : (extra == 2 ? 0x800 : 0x10000));
            if (ok && cp < minv) ok = false;
        }
        if (!ok) {
            out += static_cast<char>(b0);
            i++;
            continue;
        }
        if (cp >= 'A' && cp <= 'Z') {
            cp += 0x20;
        } else if (cp >= 0xC0 && cp <= 0xDE && cp != 0xD7) {
            cp += 0x20;                                  // À-Þ -> à-þ
        } else if (cp == 0x0130) {
            cp = 'i';                                    // İ -> i
        } else if (cp == 0x1E9E) {
            cp = 0x00DF;                                 // ẞ -> ß
        } else if (cp >= 0x0391 && cp <= 0x03A9 && cp != 0x03A2) {
            cp += 0x20;                                  // Greek Α-Ω -> α-ω
        } else if (cp >= 0x0410 && cp <= 0x042F) {
            cp += 0x20;                                  // Cyrillic А-Я -> а-я
        } else if (cp >= 0x0400 && cp <= 0x040F) {
            cp += 0x50;                                  // Ё-Џ -> ё-џ (incl. Ё->ё)
        }
        out += utf8_encode(cp);
        i += static_cast<size_t>(extra) + 1;
    }
    return out;
}

std::string domain_of(const std::string& email) {
    size_t at = email.find_last_of('@');
    if (at == std::string::npos) return {};
    std::string d = email.substr(at + 1);
    return lowercase(trim(d));
}

std::string detect_host(const std::string& email) {
    std::string d = domain_of(email);
    if (d.find("gmail.com") != std::string::npos ||
        d.find("googlemail.com") != std::string::npos)
        return "imap.gmail.com";
    if (d.find("yahoo") != std::string::npos) return "imap.mail.yahoo.com";
    if (d.find("outlook") != std::string::npos ||
        d.find("hotmail") != std::string::npos ||
        d.find("live.com") != std::string::npos ||
        d.find("msn.com") != std::string::npos ||
        d.find("office365") != std::string::npos)
        return "outlook.office365.com";
    if (d.find("aol.com") != std::string::npos) return "imap.aol.com";
    if (d.find("icloud.com") != std::string::npos ||
        d.find("me.com") != std::string::npos)
        return "imap.mail.me.com";
    if (d.find("zoho") != std::string::npos) return "imap.zoho.com";
    if (d.find("yandex") != std::string::npos) return "imap.yandex.ru";
    if (d.find("mail.ru") != std::string::npos ||
        d.find("inbox.ru") != std::string::npos ||
        d.find("bk.ru") != std::string::npos ||
        d.find("list.ru") != std::string::npos)
        return "imap.mail.ru";
    if (d.find("gmx") != std::string::npos) return "imap.gmx.net";
    if (d.find("web.de") != std::string::npos) return "imap.web.de";
    if (d.find("fastmail") != std::string::npos) return "imap.fastmail.com";
    if (d.find("proton") != std::string::npos ||
        d.find("tutanota") != std::string::npos)
        throw std::runtime_error("this provider (" + d +
                                 ") does not expose IMAP with a plain app password");
    std::string guess = "imap." + d;
    std::cerr << "unknown provider \"" << d << "\", trying " << guess
              << " (specify a different host later if needed)\n";
    return guess;
}

// Provider-specific "create an app password" instructions, keyed by domain.
// Returns an empty string for providers we do not recognise.
std::string app_password_instructions(const std::string& email) {
    std::string d = domain_of(email);
    if (d.find("gmail.com") != std::string::npos ||
        d.find("googlemail.com") != std::string::npos)
        return "Google — turn on 2-Step Verification, then create one at\n"
               "      https://myaccount.google.com/apppasswords (choose \"Mail\").";
    if (d.find("yahoo.com") != std::string::npos ||
        d.find("ymail.com") != std::string::npos ||
        d.find("rocketmail.com") != std::string::npos)
        return "Yahoo — Account security → generate an app password at\n"
               "      https://login.yahoo.com/account/security.";
    if (d.find("outlook") != std::string::npos ||
        d.find("hotmail") != std::string::npos ||
        d.find("live.com") != std::string::npos ||
        d.find("msn.com") != std::string::npos ||
        d.find("office365") != std::string::npos)
        return "Microsoft (Outlook/Hotmail) — turn on two-step verification, then\n"
               "      Advanced security options → create an app password at\n"
               "      https://account.microsoft.com/security.";
    if (d.find("aol.com") != std::string::npos)
        return "AOL — Account security → generate an app password at\n"
               "      https://login.aol.com/account/security.";
    if (d.find("icloud.com") != std::string::npos ||
        d.find("me.com") != std::string::npos)
        return "Apple (iCloud Mail) — sign in at\n"
               "      https://account.apple.com/sign-in\n"
               "      then Sign-In and Security → App-Specific Passwords (needs 2FA).";
    if (d.find("zoho") != std::string::npos)
        return "Zoho Mail — Security → app-specific passwords at\n"
               "      https://accounts.zoho.com/.";
    if (d.find("yandex") != std::string::npos)
        return "Yandex — Security → app passwords at\n"
               "      https://id.yandex.ru/security/ (choose \"External mail client\").";
    if (d.find("mail.ru") != std::string::npos ||
        d.find("inbox.ru") != std::string::npos ||
        d.find("bk.ru") != std::string::npos ||
        d.find("list.ru") != std::string::npos)
        return "Mail.ru — Security → generate a password for external apps at\n"
               "      https://id.mail.ru/security/.";
    if (d.find("gmx") != std::string::npos)
        return "GMX — create an app password in your mailbox settings\n"
               "      (your main GMX password no longer works for third-party apps).";
    if (d.find("web.de") != std::string::npos)
        return "web.de — create an app password in your mailbox settings\n"
               "      (not your normal login password).";
    if (d.find("fastmail") != std::string::npos)
        return "Fastmail — Settings → Password and Security → app passwords.";
    return {};
}

std::string read_password() {
    struct termios oldt = {};
    bool hidden = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    struct termios newt = oldt;
    if (hidden) {
        newt.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    std::string p;
    std::getline(std::cin, p);
    if (hidden) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\n";
    }
    return p;
}

std::string html_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
        }
    }
    return o;
}

std::string to_json(const std::vector<Message>& msgs) {
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < msgs.size(); i++) {
        const Message& m = msgs[i];
        if (i) os << ",";
        os << "{\"s\":\"" << json_escape(m.subject)
           << "\",\"f\":\"" << json_escape(m.from)
           << "\",\"d\":\"" << json_escape(m.date)
           << "\",\"b\":\"" << json_escape(m.body)
           << "\",\"c\":\"" << json_escape(m.category)
           << "\",\"n\":\"" << json_escape(m.mailbox)
           << "\",\"i\":\"" << json_escape(m.msg_id)
           << "\",\"r\":\"" << json_escape(m.irt)
           << "\",\"u\":" << (m.seen ? "false" : "true")
           << ",\"a\":" << (m.answered ? "true" : "false")
           << ",\"g\":" << (m.flagged ? "true" : "false") << "}";
    }
    os << "]";
    return os.str();
}

std::string build_html(const std::vector<Message>& msgs, const std::string& email) {
    static const char* templ = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>emailblob</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0b0e1a;
    --panel: rgba(255,255,255,0.05);
    --ink: #e8ecf8;
    --muted: #8a93b0;
    --accent: #7c6cff;
  }
  html, body { height: 100%; }
  body {
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background:
      radial-gradient(900px 600px at 50% -10%, rgba(124,108,255,0.25), transparent 60%),
      radial-gradient(700px 500px at 90% 100%, rgba(64,192,255,0.15), transparent 60%),
      var(--bg);
    color: var(--ink);
    overflow: hidden;
  }
  header {
    position: relative;
    z-index: 5;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    padding: 18px 26px;
    background: linear-gradient(180deg, rgba(11,14,26,0.95), rgba(11,14,26,0.6));
    border-bottom: 1px solid rgba(255,255,255,0.08);
    backdrop-filter: blur(6px);
  }
  header .title { display:flex; align-items:center; gap:12px; }
  header h1 { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
  header .email { font-size: 13px; color: var(--muted); max-width: 300px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .filters { display: flex; gap: 8px; margin-left: auto; flex-wrap: wrap; align-items: center; }
  .fbtn {
    border: 1px solid rgba(255,255,255,0.14);
    background: var(--panel);
    color: var(--ink);
    font: inherit; font-size: 13px;
    padding: 7px 14px; border-radius: 999px;
    cursor: pointer;
    transition: transform .12s ease, background .12s ease, border-color .12s ease;
    -webkit-tap-highlight-color: transparent;
  }
  .fbtn:hover { transform: translateY(-1px); border-color: rgba(255,255,255,0.3); }
  .fbtn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .divider { width: 1px; height: 22px; background: rgba(255,255,255,0.15); }
  .stats { font-size: 12px; color: var(--muted); }

  #field {
    position: fixed;
    inset: 76px 0 0 0;
  }
  .hub {
    position: absolute;
    left: 50%; top: 50%;
    transform: translate(-50%, -50%);
    width: 190px; height: 160px;
    display: flex; align-items: center; justify-content: center;
    text-align: center; padding: 18px;
    background: radial-gradient(120% 130% at 30% 20%,
      rgba(124,108,255,0.55), rgba(36,34,80,0.9) 70%);
    border: 1px solid rgba(180,170,255,0.35);
    border-radius: 62% 38% 55% 45% / 48% 58% 42% 52%;
    box-shadow: 0 0 60px rgba(124,108,255,0.35), inset 0 0 30px rgba(255,255,255,0.06);
    animation: wobble 9s ease-in-out infinite;
    z-index: 1;
  }
  .hub b { font-size: 15px; line-height: 1.35; word-break: break-word; color: #fff; }

  .blob {
    position: absolute;
    display: flex; align-items: center; justify-content: center;
    padding: 12px;
    color: #f2f5ff;
    cursor: pointer;
    overflow: hidden;
    user-select: none;
    -webkit-user-select: none;
    z-index: 2;
    text-align: center;
    font-weight: 600;
    border: 1px solid rgba(255,255,255,0.35);
    box-shadow:
      0 6px 18px rgba(8,12,28,0.35),
      inset 0 1px 0 rgba(255,255,255,0.35),
      inset 0 -12px 20px rgba(255,255,255,0.05);
    transition: transform .12s ease, box-shadow .12s ease;
    animation: bob linear infinite;
  }
  .blob::before {
    content: "";
    position: absolute;
    top: 7%; left: 9%;
    width: 38%; height: 24%;
    border-radius: 50%;
    background: radial-gradient(closest-side, rgba(255,255,255,0.35), transparent);
    pointer-events: none;
  }
  .blob::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: inherit;
    box-shadow: inset 0 0 0 0.5px rgba(255,255,255,0.25);
    pointer-events: none;
  }
  .blob .label { font-size: 11.5px; line-height: 1.25; max-height: 100%; overflow: hidden; }
  .blob:hover { z-index: 4; }
  .blob.grabbed {
    transform: scale(1.18);
    z-index: 6;
    box-shadow:
      0 18px 46px rgba(0,0,0,0.55),
      inset 0 1px 0 rgba(255,255,255,0.4);
  }
  .blob.unread {
    background-image:
      radial-gradient(130% 140% at 28% 18%, rgba(255,255,255,0.35), rgba(30,55,110,0.15) 55%, rgba(30,55,110,0) 75%),
      linear-gradient(160deg, #3d67b8 0%, #223c74 70%, #1a2c58 100%);
  }
  .blob.answered {
    background-image:
      radial-gradient(130% 140% at 28% 18%, rgba(255,255,255,0.35), rgba(30,110,70,0.15) 55%, rgba(30,110,70,0) 75%),
      linear-gradient(160deg, #2f9c6b 0%, #1d6a45 70%, #154d33 100%);
  }
  .blob.flagged {
    background-image:
      radial-gradient(130% 140% at 28% 18%, rgba(255,255,255,0.35), rgba(130,95,20,0.15) 55%, rgba(130,95,20,0) 75%),
      linear-gradient(160deg, #c79a3a 0%, #8a6517 70%, #63480f 100%);
  }
  .blob.spam {
    background-image:
      radial-gradient(130% 140% at 28% 18%, rgba(255,255,255,0.35), rgba(120,40,40,0.18) 55%, rgba(120,40,40,0) 75%),
      linear-gradient(160deg, #b85458 0%, #7e2f33 70%, #5a2024 100%);
  }
  .blob.read {
    background-image:
      radial-gradient(130% 140% at 28% 18%, rgba(255,255,255,0.32), rgba(90,100,130,0.15) 55%, rgba(90,100,130,0) 75%),
      linear-gradient(160deg, #7d8499 0%, #52586b 70%, #3a3f4e 100%);
  }
  .blob.hidden { display: none; }

  @keyframes bob {
    0%,100% { margin-top: 0px; }
    50%     { margin-top: -6px; }
  }
  @keyframes wobble {
    0%,100% { border-radius: 62% 38% 55% 45% / 48% 58% 42% 52%; }
    50%     { border-radius: 48% 52% 60% 40% / 55% 45% 52% 48%; }
  }

  #modal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 20;
    background: rgba(4,6,14,0.75);
    backdrop-filter: blur(4px);
    align-items: center;
    justify-content: center;
  }
  #modal.open { display: flex; }
  #modal .card {
    width: min(720px, 94vw);
    max-height: 92vh;
    overflow-y: auto;
    background: linear-gradient(180deg, #171b2f, #10131f);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 22px;
    padding: 26px;
    box-shadow: 0 20px 70px rgba(0,0,0,0.6);
  }
  #modal .card h2 { font-size: 18px; margin-bottom: 12px; color: #fff; padding-right: 24px; }
  #modal .row { font-size: 13px; color: var(--muted); margin-bottom: 8px; word-break: break-word; }
  #modal .row b { color: var(--ink); font-weight: 600; }
  #modal .chips { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
  #modal .chip { font-size: 11px; padding: 4px 10px; border-radius: 999px;
    border: 1px solid rgba(255,255,255,0.15); color: var(--ink); }
  #modal .chip.on { background: var(--accent); border-color: var(--accent); }
  #modal .close { float: right; background: none; border: none; color: var(--muted);
    font: inherit; font-size: 20px; cursor: pointer; line-height: 1; }
  #modal .bodywrap { margin-top: 16px; }
  #modal .bodywrap .lbl { font-size: 12px; color: var(--muted); margin-bottom: 6px; display: block; }
  #modal #m-body {
    white-space: pre-wrap; word-break: break-word;
    font-size: 13px; line-height: 1.5;
    max-height: 40vh; overflow-y: auto;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 12px; padding: 14px; color: var(--ink);
  }
  .empty { position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; color: var(--muted); font-size: 15px; }
  svg#lines { position:absolute; inset:0; width:100%; height:100%;
    pointer-events:none; z-index:0; }
  .threadwrap .tlbl { font-size:12px; color:var(--muted); margin-bottom:8px; display:block; }
  #thread { position:relative; padding-left:24px; }
  #thread::before { content:""; position:absolute; left:8px; top:10px; bottom:14px; width:2px;
    background: linear-gradient(180deg, rgba(124,108,255,0.75), rgba(64,192,255,0.35));
    border-radius:2px; }
  .tnode { position:relative; display:flex; flex-direction:column; gap:2px;
    padding:10px 12px; background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.1); border-radius:12px; margin-bottom:14px; cursor:pointer; }
  .tnode::before { content:""; position:absolute; left:-16px; top:15px; width:16px; height:2px;
    background:rgba(124,108,255,0.7); }
  .tnode::after { content:""; position:absolute; left:-20px; top:12px; width:8px; height:8px;
    border-radius:50%; background:#7c6cff; box-shadow:0 0 6px rgba(124,108,255,0.8); }
  .tnode.current { border-color:var(--accent); box-shadow:0 0 0 1px var(--accent) inset; }
  .tnode.current::after { background:#fff; }
  .tnode .ts { font-weight:600; font-size:13px; color:var(--ink); word-break:break-word; }
  .tnode .tf { font-size:11px; color:var(--muted); }
  .tnode .td { font-size:11px; color:var(--muted); }
</style>
</head>
<body>
<header>
  <div class="title">
    <h1>emailblob</h1>
    <span class="email">EMAIL_PLACEHOLDER</span>
  </div>
  <div class="stats" id="stats"></div>
  <nav class="filters" id="filters">
    <button class="fbtn" data-f="all">All</button>
    <div class="divider"></div>
    <button class="fbtn" data-t="folder" data-f="inbox">Inbox</button>
    <button class="fbtn" data-t="folder" data-f="spam">Spam</button>
    <button class="fbtn" data-t="folder" data-f="other">Other</button>
    <div class="divider"></div>
    <button class="fbtn" data-t="flag" data-f="unread">Unread</button>
    <button class="fbtn" data-t="flag" data-f="replied">Replied</button>
    <button class="fbtn" data-t="flag" data-f="flagged">Flagged</button>
  </nav>
</header>

<div id="field">
  <svg id="lines" xmlns="http://www.w3.org/2000/svg"></svg>
</div>

<div id="modal">
  <div class="card">
    <button class="close" id="close">&times;</button>
    <h2 id="m-subject"></h2>
    <div class="row"><b>From:</b> <span id="m-from"></span></div>
    <div class="row"><b>Date:</b> <span id="m-date"></span></div>
    <div class="row"><b>Folder:</b> <span id="m-folder"></span></div>
    <div class="chips">
      <span class="chip" id="c-unread">unread</span>
      <span class="chip" id="c-replied">replied</span>
      <span class="chip" id="c-flagged">flagged</span>
    </div>
    <div class="threadwrap" id="threadwrap">
      <span class="tlbl">conversation</span>
      <div id="thread"></div>
    </div>
    <div class="bodywrap">
      <span class="lbl">message</span>
      <div id="m-body"></div>
    </div>
  </div>
</div>

<script>
const DATA = __DATA__;
const EMAIL = "EMAIL_PLACEHOLDER";

const field = document.getElementById('field');
const rng = (function(){ let s = 0x9e3779b9;
  return function(){ s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff; }; })();

function hashStr(t){ let h = 0; for (let i=0;i<t.length;i++){ h = (h*31 + t.charCodeAt(i)) & 0xffffffff; } return h>>>0; }

const n = DATA.length;
const cats = { inbox: 0, spam: 0, other: 0 };
DATA.forEach(m => cats[m.c] = (cats[m.c] || 0) + 1);
document.getElementById('stats').textContent =
  n + ' msgs · inbox ' + cats.inbox + ' · spam ' + cats.spam + ' · other ' + cats.other;

const byId = {};
DATA.forEach(m => { if (m.i) byId[m.i] = m; });

if (n === 0) {
  const e = document.createElement('div');
  e.className = 'empty';
  e.textContent = 'no emails found';
  field.appendChild(e);
}

const pos = [];
const W0 = field.clientWidth, H0 = field.clientHeight;
DATA.forEach((m, i) => {
  const el = document.createElement('div');
  el.className = 'blob ' + (m.c === 'spam' ? 'spam' :
    (m.a ? 'answered' : (m.g ? 'flagged' : (m.u ? 'unread' : 'read'))));
  el.dataset.c = m.c;
  el.dataset.u = m.u ? '1' : '0';
  el.dataset.a = m.a ? '1' : '0';
  el.dataset.g = m.g ? '1' : '0';

  const h = hashStr(m.s + '|' + m.f + '|' + m.c);
  const crowd = Math.max(1, Math.sqrt(n / 60));
  const size = Math.max(30, Math.round((48 + (h % 88)) / crowd));
  const wpx = size, hpx = size * (0.72 + (h >> 5) % 30 / 100);
  const rad = (wpx + hpx) / 4 + 4;
  el.style.width = wpx + 'px';
  el.style.height = hpx + 'px';
  el.style.borderRadius =
    (38 + h % 22) + '% ' + (62 - h % 22) + '% ' + (48 + (h>>3) % 16) + '% ' + (52 - (h>>3) % 16) + '% / ' +
    (52 + h % 18) + '% ' + (48 - h % 18) + '% ' + (56 + (h>>6) % 14) + '% ' + (44 - (h>>6) % 14) + '%';
  el.style.animationDuration = (5 + rng() * 5).toFixed(2) + 's';
  el.style.animationDelay = (-rng() * 5).toFixed(2) + 's';

  const label = document.createElement('span');
  label.className = 'label';
  label.textContent = m.s.trim() ? m.s.slice(0, 26) : '(no subject)';
  el.title = m.n + '  |  ' + m.s + '  |  ' + m.f;

  el.appendChild(label);
  el.addEventListener('click', () => openMessage(m));
  el.addEventListener('contextmenu', e => e.preventDefault());
  field.appendChild(el);

  const pad = 26;
  pos.push({
    el, m, rad, w: wpx, h: hpx,
    x: pad + Math.random() * (W0 - 2 * pad),
    y: pad + Math.random() * (H0 - 2 * pad),
    vx: 0, vy: 0,
    drift: 0.4 + Math.random() * 1.4,
    phase: Math.random() * Math.PI * 2,
  });
});

// Pre-relax so blobs start spread out instead of crammed.
for (let iter = 0; iter < 60; iter++) {
  for (let i = 0; i < pos.length - 1; i++) {
    for (let j = i + 1; j < pos.length; j++) {
      const a = pos[i], b = pos[j];
      const dx = b.x - a.x, dy = b.y - a.y;
      const min = a.rad + b.rad + 18;
      const d2 = dx * dx + dy * dy;
      if (d2 < min * min && d2 > 1e-6) {
        const d = Math.sqrt(d2);
        const push = (min - d) * 0.5;
        a.x -= dx / d * push; a.y -= dy / d * push;
        b.x += dx / d * push; b.y += dy / d * push;
      }
    }
  }
  for (const p of pos) {
    p.x = Math.min(Math.max(p.x, p.rad), W0 - p.rad);
    p.y = Math.min(Math.max(p.y, p.rad), H0 - p.rad);
  }
}
pos.forEach(p => {
  p.el.style.left = (p.x - p.w / 2) + 'px';
  p.el.style.top = (p.y - p.h / 2) + 'px';
});

// Live thread connector lines (updated every physics frame).
const edges = [];
pos.forEach((p, i) => {
  const par = byId[p.m.r];
  if (!par || par === p.m) return;
  const pi = DATA.indexOf(par);
  if (pi < 0) return;
  edges.push({ i, pi, el: null });
});
const svg = document.getElementById('lines');
function updateLines() {
  for (const e of edges) {
    const a = pos[e.i], b = pos[e.pi];
    if (!e.el) {
      e.el = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      e.el.setAttribute('stroke', 'rgba(150,160,255,0.3)');
      e.el.setAttribute('stroke-width', '1.4');
      e.el.setAttribute('stroke-dasharray', '3 5');
      e.el.setAttribute('stroke-linecap', 'round');
      e.el.setAttribute('fill', 'none');
      svg.appendChild(e.el);
    }
    e.el.setAttribute('d', 'M ' + a.x.toFixed(1) + ' ' + a.y.toFixed(1) +
                          ' L ' + b.x.toFixed(1) + ' ' + b.y.toFixed(1));
  }
}

// Right-button drag to move a blob around.
let dragging = null, mouseX = 0, mouseY = 0;
field.addEventListener('mousedown', e => {
  if (e.button !== 2) return;
  const t = e.target;
  const b = t.closest ? t.closest('.blob') : null;
  if (!b) return;
  const p = pos.find(q => q.el === b);
  if (!p) return;
  e.preventDefault();
  dragging = p;
  p.el.classList.add('grabbed');
  mouseX = e.clientX; mouseY = e.clientY;
});
window.addEventListener('mousemove', e => {
  if (dragging) { mouseX = e.clientX; mouseY = e.clientY; }
});
window.addEventListener('mouseup', () => {
  if (dragging) { dragging.el.classList.remove('grabbed'); dragging = null; }
});

let paused = false;
function tick() {
  const W = field.clientWidth, H = field.clientHeight;
  const t = performance.now() / 1000;
  for (let i = 0; i < pos.length - 1; i++) {
    const a = pos[i];
    for (let j = i + 1; j < pos.length; j++) {
      const b = pos[j];
      const dx = b.x - a.x, dy = b.y - a.y;
      const min = a.rad + b.rad + 16;
      const d2 = dx * dx + dy * dy;
      if (d2 < min * min && d2 > 1e-9) {
        const d = Math.sqrt(d2);
        const push = (min - d) * 0.14;
        a.vx -= dx / d * push; a.vy -= dy / d * push;
        b.vx += dx / d * push; b.vy += dy / d * push;
      }
    }
  }
  for (const p of pos) {
    if (p === dragging) {
      p.vx += (mouseX - p.x) * 0.11;
      p.vy += (mouseY - p.y) * 0.11;
    } else {
      p.vx += Math.sin(t * p.drift + p.phase) * 0.012 + p.phase * 0.002;
      p.vy += Math.cos(t * p.drift * 1.37 + p.phase) * 0.012;
      p.vx += (W / 2 - p.x) * 0.00055;
      p.vy += (H / 2 - p.y) * 0.00055;
    }
    p.vx *= 0.9; p.vy *= 0.9;
    p.x += p.vx; p.y += p.vy;
    if (p.x < p.rad) { p.x = p.rad; p.vx *= -0.4; }
    if (p.x > W - p.rad) { p.x = W - p.rad; p.vx *= -0.4; }
    if (p.y < p.rad) { p.y = p.rad; p.vy *= -0.4; }
    if (p.y > H - p.rad) { p.y = H - p.rad; p.vy *= -0.4; }
  }
  for (const p of pos) {
    p.el.style.left = (p.x - p.w / 2) + 'px';
    p.el.style.top = (p.y - p.h / 2) + 'px';
  }
  updateLines();
  if (!paused) requestAnimationFrame(tick);
}
requestAnimationFrame(tick);

let current = null;
function fullThread(m) {
  let root = m;
  while (root.r && byId[root.r]) root = byId[root.r];
  const kids = new Map();
  DATA.forEach(x => {
    const p = x.r ? byId[x.r] : null;
    if (p) {
      const a = kids.get(p) || [];
      a.push(x);
      kids.set(p, a);
    }
  });
  const res = [];
  const seen = new Set();
  (function walk(n) {
    if (seen.has(n)) return;
    seen.add(n);
    res.push(n);
    (kids.get(n) || []).forEach(walk);
  })(root);
  return res;
}
function renderThread() {
  const tw = document.getElementById('thread');
  const wrap = document.getElementById('threadwrap');
  tw.innerHTML = '';
  const chain = fullThread(current);
  if (chain.length < 2) {
    if (current.r && !byId[current.r]) {
      wrap.style.display = '';
      const note = document.createElement('div');
      note.className = 'tlbl';
      note.textContent = 'reply · original message #' +
          (('' + current.r).replace(/[<>]/g, '').slice(0, 40)) +
          ' is not in the fetched mailboxes';
      tw.appendChild(note);
    } else {
      wrap.style.display = 'none';
    }
    return;
  }
  wrap.style.display = '';
  const lbl = document.createElement('div');
  lbl.className = 'tlbl';
  lbl.textContent = 'conversation · ' + chain.length + ' messages';
  tw.appendChild(lbl);
  chain.forEach(c => {
    const node = document.createElement('div');
    node.className = 'tnode' + (c === current ? ' current' : '');
    const s = document.createElement('div'); s.className = 'ts';
    s.textContent = (c.s && c.s.trim()) ? c.s : '(no subject)';
    const f = document.createElement('div'); f.className = 'tf';
    f.textContent = (c.f || 'unknown') + '  ·  ' + (c.n || c.c);
    const d = document.createElement('div'); d.className = 'td';
    d.textContent = c.d || '';
    node.appendChild(s); node.appendChild(f); node.appendChild(d);
    if (c !== current) node.addEventListener('click', () => openMessage(c));
    tw.appendChild(node);
  });
}
function openMessage(m) {
  current = m;
  paused = true;
  document.getElementById('m-subject').textContent =
      (m.s && m.s.trim()) ? m.s : '(no subject)';
  document.getElementById('m-from').textContent = m.f || '(unknown)';
  document.getElementById('m-date').textContent = m.d || '(unknown)';
  document.getElementById('m-folder').textContent = m.n || m.c;
  document.getElementById('m-body').textContent =
      (m.b && m.b.trim()) ? m.b : '(no message body)';
  document.getElementById('c-unread').classList.toggle('on', m.u);
  document.getElementById('c-replied').classList.toggle('on', m.a);
  document.getElementById('c-flagged').classList.toggle('on', m.g);
  renderThread();
  document.getElementById('modal').classList.add('open');
}

document.getElementById('close').addEventListener('click', () => {
  document.getElementById('modal').classList.remove('open');
  paused = false;
  requestAnimationFrame(tick);
});
document.getElementById('modal').addEventListener('click', (e) => {
  if (e.target === document.getElementById('modal')) {
    document.getElementById('modal').classList.remove('open');
    paused = false;
    requestAnimationFrame(tick);
  }
});

let folderF = null, flagF = null;
const buttons = document.querySelectorAll('.fbtn');
function applyFilter() {
  document.querySelectorAll('.blob').forEach(b => {
    const okF = folderF === null || b.dataset.c === folderF;
    const okG = flagF === null ||
      (flagF === 'unread' && b.dataset.u === '1') ||
      (flagF === 'replied' && b.dataset.a === '1') ||
      (flagF === 'flagged' && b.dataset.g === '1');
    b.classList.toggle('hidden', !(okF && okG));
  });
}
function refreshButtons() {
  buttons.forEach(x => {
    const on =
      (x.dataset.f === 'all' && folderF === null && flagF === null) ||
      (x.dataset.t === 'folder' && folderF === x.dataset.f) ||
      (x.dataset.t === 'flag' && flagF === x.dataset.f);
    x.classList.toggle('active', on);
  });
}
buttons.forEach(b => b.addEventListener('click', () => {
  if (b.dataset.f === 'all') { folderF = null; flagF = null; }
  else if (b.dataset.t === 'folder') folderF = folderF === b.dataset.f ? null : b.dataset.f;
  else if (b.dataset.t === 'flag') flagF = flagF === b.dataset.f ? null : b.dataset.f;
  refreshButtons();
  applyFilter();
}));
</script>
</body>
</html>
)HTML";

    std::string doc = templ;
    size_t p;
    while ((p = doc.find("EMAIL_PLACEHOLDER")) != std::string::npos)
        doc.replace(p, std::string("EMAIL_PLACEHOLDER").size(), html_escape(email));
    while ((p = doc.find("__DATA__")) != std::string::npos)
        doc.replace(p, std::string("__DATA__").size(), to_json(msgs));
    return doc;
}

void write_html(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot write " + path);
    out << content;
}

// Where the final emails.html goes: $HOME/Documents if it exists,
// otherwise a new $HOME/blobfield/ directory.
std::string output_dir() {
    const char* home = std::getenv("HOME");
    std::string base = home && *home ? home : ".";
    std::string docs = base + "/Documents";
    struct stat st;
    if (stat(docs.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) return docs;
    std::string blob = base + "/blobfield";
    if (mkdir(blob.c_str(), 0755) != 0 && errno != EEXIST) return ".";
    return blob;
}

std::vector<Message> demo_messages() {
    std::vector<Message> out;
    const char* subs[] = {
        "meet me at midnight", "your invoice for august", "package on the way!!",
        "meeting rescheduled to 4pm", "you replied wow", "re: the big blob day",
        "deals you will not want to miss", "friday games night?", "re: hello again",
        "password reset request", "new comment on your photo", "hello from the void",
        "apply now for early access", "the blob has arrived", "re: blob",
        "your weekly digest", "remember to water the plants", "someone liked your post",
    };
    const char* froms[] = {
        "Ada Lovelace", "The Machine <bot@machine.dev>", "Sam <sam@sam.co>",
        "HR Department <hr@corp.example>", "Your Mom <mom@example.com>",
        "GitHub <noreply@github.com>", "Steam Community <noreply@steam.com>",
    };
    const char* dates[] = {
        "2026-09-05 09:41", "2026-09-04 22:10", "2026-09-04 16:02",
        "2026-09-03 11:59", "2026-09-02 08:15",
    };
    const char* bodies[] = {
        "hey,\n\nstuff happened and the blob ate everything. what a day.\n\n- the blob",
        "attached is the file you wanted.\n\ntalk soon\n\n- sam",
        "Your invoice for last month is ready.\n\nTotal: $12.34\n\nthanks!",
        "This is the full message body. It goes on and on and on,\nand eventually it ends.\n\nregards",
        "You are our 1000th visitor! Click now for a free prize.\nDo not miss out!!",
    };
    for (int i = 0; i < 34; i++) {
        Message m;
        m.seq = i + 1;
        m.subject = subs[(i * 7) % (sizeof subs / sizeof *subs)];
        m.from = froms[(i * 13) % (sizeof froms / sizeof *froms)];
        m.date = dates[(i * 3) % (sizeof dates / sizeof *dates)];
        m.body = bodies[i % (sizeof bodies / sizeof *bodies)];
        m.msg_id = "demo-" + std::to_string(i + 1);
        if (i > 0) m.irt = "demo-" + std::to_string(i);
        if (i % 9 == 3) {
            m.category = "spam";
            m.mailbox = "Junk";
        } else if (i % 9 == 5) {
            m.category = "other";
            m.mailbox = "Sent";
        } else {
            m.category = "inbox";
            m.mailbox = "INBOX";
        }
        m.seen = (i % 3) != 0;
        m.answered = (i % 5) == 2;
        m.flagged = (i % 7) == 0;
        out.push_back(m);
    }
    return out;
}

// Fetches up to `cap` messages from one mailbox, parsing full bodies.
int fetch_folder(Imap& imap, const std::string& raw_name, const std::string& disp_name,
                 const std::string& category, int cap, std::vector<Message>& msgs) {
    std::cout << "  reading " << disp_name << " ..." << std::flush;
    int total = imap.select_mailbox(raw_name);
    std::vector<int> seqs = imap.search("ALL");
    int fetched = 0;
    for (int s : seqs) {
        if (fetched >= cap) break;
        try {
            Message m = imap.fetch(s);
            m.mailbox = disp_name;
            m.category = category;
            m.body = mime_body_text(m.raw);
            msgs.push_back(std::move(m));
            fetched++;
        } catch (const std::exception& e) {
            std::cerr << "  skip msg " << s << ": " << e.what() << "\n";
        }
    }
    std::cout << "  " << disp_name << ": " << total << " total, showing " << fetched << "\n";
    return fetched;
}

const int GLOBAL_CAP = 800;
const int INBOX_CAP = 400;
const int SPAM_CAP = 100;
const int OTHER_CAP = 60;

// Spam-folder names across languages (compared lowercased).
const char* const SPAM_FOLDERS[] = {
    "spam", "junk", "bulk",                          // en, + used in many locales
    "спам",                                          // ru, uk, bg
    "unerwünscht", "unerwuenscht",                   // de
    "courrier indésirable", "courrier indesirable", "pourriel",  // fr
    "correo no deseado", "correo basura", "basura",  // es
    "posta indesiderata", "indesiderata",            // it
    "lixo eletrônico", "lixo eletronico", "lixo",    // pt
    "ongewenst",                                     // nl
    "niechciane wiadomości", "niechciane wiadomosci", "smieci", "śmieci",  // pl
    "skräppost", "skrappost",                        // sv
    "roskaposti",                                    // fi
    "søppelpost", "soppelpost", "uønsket", "uonsket",  // no, da
    "nevyžádaná pošta", "nevyzadana posta", "nevyžiadaná pošta",  // cz, sk
    "levélszemét", "levelemet",                      // hu
    "gereksiz", "istenmeyen",                        // tr
    "ανεπιθύμητα", "anepi8ymhta",                    // el
    "垃圾", "垃圾邮件",                                // zh
    "迷惑メール",                                     // ja
    "스팸",                                          // ko
    "ספאם",                                         // he
    "بريد عشوائي", "بريد غير مرغوب فيه",             // ar
    "สแปม",                                         // th
    "स्पैम",                                        // hi
    "hộp thư rác", "hop thu rac",                    // vi
};

// Inbox-folder names across languages (compared lowercased).
const char* const INBOX_FOLDERS[] = {
    "inbox",                                         // en + many locales
    "входящие",                                      // ru, uk, bg
    "posteingang", "eingang", "postfach",            // de
    "boîte de réception", "boite de reception",      // fr
    "recibidos", "entrada",                           // es
    "posta in arrivo", "in arrivo",                  // it
    "caixa de entrada",                              // pt
    "postvak in",                                    // nl
    "skrzynka odbiorcza", "odbierana",               // pl
    "inkorg",                                        // sv
    "saapuneet",                                     // fi
    "indbakke",                                      // da
    "innboks",                                       // no
    "primljene",                                     // hr
    "doručená pošta", "doručena posta", "doraz",     // cz, sk
    "bejövő levelek", "bejovő levelek", "bejovo",    // hu
    "gelen kutusu", "gelenler",                      // tr
    "εισερχόμενα", "eiserochomena",                  // el
    "收件箱", "收件匣",                                 // zh
    "受信トレイ",                                     // ja
    "받은편지함",                                     // ko
    "דואר נכנס",                                     // he
    "علبة الوارد", "الوارد",                          // ar
    "กล่องขาเข้า",                                   // th
    "इनबॉक्स", "प्राप्त",                            // hi
    "hộp thư đến", "hop thu den",                    // vi
};

// Classifies a mailbox display name into inbox/spam/other and its per-folder cap.
std::string classify_folder(const std::string& disp, int& cap) {
    std::string lf = lowercase(disp);
    for (const char* w : SPAM_FOLDERS)
        if (lf.find(w) != std::string::npos) {
            cap = SPAM_CAP;
            return "spam";
        }
    for (const char* w : INBOX_FOLDERS)
        if (lf.find(w) != std::string::npos) {
            cap = INBOX_CAP;
            return "inbox";
        }
    cap = OTHER_CAP;
    return "other";
}

// Tries to fetch the missing ancestor of a thread by searching each mailbox
// for a message carrying that Message-ID.
bool recover_thread_message(Imap& imap, const std::string& id,
                            const std::vector<Imap::Mailbox>& folders,
                            std::vector<Message>& msgs, std::set<std::string>& got_ids,
                            std::set<std::string>& need_ids) {
    for (const Imap::Mailbox& mb : folders) {
        try {
            imap.select_mailbox(mb.raw);
        } catch (const std::exception&) {
            continue;
        }
        std::vector<int> seqs;
        try {
            seqs = imap.search("HEADER Message-ID \"" + id + "\"");
        } catch (const std::exception&) {
            continue;
        }
        for (int s : seqs) {
            try {
                Message m = imap.fetch(s);
                if (m.msg_id.empty() || got_ids.count(m.msg_id)) continue;
                int cap;
                m.category = classify_folder(mb.display, cap);
                m.mailbox = mb.display;
                m.body = mime_body_text(m.raw);
                msgs.push_back(m);
                got_ids.insert(m.msg_id);
                if (!m.irt.empty() && m.irt != m.msg_id && !got_ids.count(m.irt))
                    need_ids.insert(m.irt);
                std::cout << "    recovered missing parent " << m.msg_id
                          << " from " << mb.display << "\n";
                return true;
            } catch (const std::exception&) {
            }
        }
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    std::cout <<
        R"(_______ ______          _____  ______  _______              
 |______ |_____] |      |     | |_____] |______              
 |______ |_____] |_____ |_____| |_____] ______|              
                                                             
 ______  __   __      _______ _     _  _____  _     _  _____ 
 |_____]   \_/        |______ |_____| |     | |____/  |     |
 |_____]    |         ______| |     | |_____| |    \_ |_____|)" << "\n\n";

    bool demo = argc == 2 && std::string(argv[1]) == "--demo";

    if (demo) {
        std::vector<Message> msgs = demo_messages();
        write_html("emails.html", build_html(msgs, "demo@example.com"));
        std::cout << "demo html written to emails.html\n";
        return 0;
    }

    std::cout << "enter your email address: " << std::flush;
    std::string email;
    std::getline(std::cin, email);
    email = lowercase(trim(email));
    if (email.empty() || email.find('@') == std::string::npos) {
        std::cerr << "invalid email address\n";
        return 1;
    }

    std::string host;
    try {
        const char* ovr = std::getenv("EMAILBLOB_HOST");
        host = ovr ? std::string(ovr) : detect_host(email);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    if (std::getenv("EMAILBLOB_HOST"))
        std::cout << "detected provider: " << host << " (overridden)\n";
    else
        std::cout << "detected provider: " << host << "\n";

    std::string hint = app_password_instructions(email);
    if (hint.empty())
        std::cout << "\n  this provider may require an app password — generate one\n"
                  << "  in your account's security settings (not your normal password)\n";
    else
        std::cout << "\n  app password for " << hint << "\n";
    std::cout << "\n";

    std::cout << "enter your app password: " << std::flush;
    std::string password = read_password();
    size_t before = password.size();
    password.erase(std::remove(password.begin(), password.end(), ' '), password.end());
    if (password.size() != before)
        std::cout << "  (removed spaces from app password)\n";

    try {
        Imap imap;
        const char* portEnv = std::getenv("EMAILBLOB_PORT");
        int port = (portEnv && *portEnv) ? std::atoi(portEnv) : 993;
        imap.connect(host, port);
        std::cout << "  connected" << std::flush;
        imap.login(email, password);
        std::cout << " · login ok\n" << std::flush;

        std::vector<Imap::Mailbox> folders;
        try {
            folders = imap.list_folders();
        } catch (const std::exception& e) {
            std::cerr << "  LIST failed (" << e.what() << "), using INBOX only\n";
            folders = {Imap::Mailbox{"INBOX", "INBOX"}};
        }
        if (folders.empty()) folders = {Imap::Mailbox{"INBOX", "INBOX"}};
        std::cout << "  mailboxes: " << folders.size() << "\n" << std::flush;

        std::vector<Message> msgs;
        int fetched = 0;
        for (const Imap::Mailbox& mb : folders) {
            if (fetched >= GLOBAL_CAP) break;
            int cap;
            std::string cat = classify_folder(mb.display, cap);
            try {
                fetched += fetch_folder(imap, mb.raw, mb.display, cat, std::min(cap, GLOBAL_CAP - fetched), msgs);
            } catch (const std::exception& e) {
                std::cerr << "  skip folder " << mb.display << ": " << e.what() << "\n";
            }
        }

        // Recover thread ancestors that weren't in the capped fetch, so replies
        // can still show their original message above them.
        const int RECOVER_MAX = 60;
        std::set<std::string> got_ids, need_ids;
        for (const Message& m : msgs)
            if (!m.msg_id.empty()) got_ids.insert(m.msg_id);
        for (const Message& m : msgs)
            if (!m.irt.empty() && m.irt != m.msg_id && !got_ids.count(m.irt))
                need_ids.insert(m.irt);
        int recovered = 0;
        while (!need_ids.empty() && recovered < RECOVER_MAX) {
            std::string id = *need_ids.begin();
            need_ids.erase(need_ids.begin());
            if (got_ids.count(id)) continue;
            if (recover_thread_message(imap, id, folders, msgs, got_ids, need_ids))
                recovered++;
        }
        if (recovered)
            std::cout << "  recovered " << recovered << " missing thread-parent(s)\n"
                      << std::flush;

        std::string dir = output_dir();
        write_html(dir + "/emails.html", build_html(msgs, email));
        std::cout << "wrote emails.html with " << msgs.size() << " emails\n"
                  << "your blob emails have been made and the directory of the .html is "
                  << dir << "\n";
        imap.logout();
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}