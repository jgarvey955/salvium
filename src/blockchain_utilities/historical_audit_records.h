#pragma once
#include <cstdint>
#include <ostream>
#include <string>

namespace cryptonote { namespace historical_audit {
// Small streaming JSONL writer. Chain-controlled strings are escaped even when
// malformed; no wallet secrets or recovered private values enter this stream.
inline std::string quote(const std::string& s) {
  static const char hex[] = "0123456789abcdef";
  std::string r = "\"";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { r += '\\'; r += c; }
    else if (c < 32 || c >= 127) { r += "\\u00"; r += hex[c >> 4]; r += hex[c & 15]; }
    else r += c;
  }
  return r + '"';
}
struct record {
  std::ostream* out;
  explicit record(std::ostream* stream, const std::string& type): out(stream) {
    if (out) *out << "{\"record_type\":" << quote(type);
  }
  record(const record&) = delete;
  ~record() { if (out) *out << "}\n"; }
  record& field(const std::string& k, const std::string& v) {
    if (out) *out << ',' << quote(k) << ':' << quote(v); return *this;
  }
  record& field(const std::string& k, const char* v) { return field(k, std::string(v)); }
  record& field(const std::string& k, uint64_t v) {
    if (out) *out << ',' << quote(k) << ':' << v; return *this;
  }
};
} }
