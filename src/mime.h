#pragma once

#include <string>

std::string base64_decode(const std::string& in);
std::string base64_encode(const std::string& in);
std::string rfc2047_decode(const std::string& in);
std::string trim(const std::string& s);
std::string json_escape(const std::string& s);

// Looks up a header field in an IMAP/RFC822 header block (headers only,
// not the body). Field name is case-insensitive; folded lines are unfolded.
std::string header_value(const std::string& header_block, const std::string& name);

// Extracts a readable text body from a raw RFC822 message: handles
// text/plain, text/html (tags stripped), multipart/* and base64 /
// quoted-printable transfer encodings.
std::string mime_body_text(const std::string& raw_message);

// Returns the first bracketed `<message-id>` (or first token) from a
// Message-ID / In-Reply-To / References header value.
std::string first_id(const std::string& s);