// SPDX-License-Identifier: MIT
// cpp-ifinet6-watch — IPv6 assigned addresses monitor (/proc/net/if_inet6)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ifinet6-watch
// Usage: ./ifinet6-watch [--iface NAME] [--scope NAME] [--flag NAME] [--global]
//                        [--link] [--host] [--ula] [--permanent] [--top N]
//                        [--watch N] [--json] [--demo] [--file PATH]
//                        [--no-color] [--selftest]

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model — one assigned IPv6 address (one inet6_ifaddr)
// ─────────────────────────────────────────────────────────────────────────────
struct Addr {
  std::array<uint16_t, 8> words{};   // 8 x 16-bit words (network order)
  int ifindex = 0;                   // dev->ifindex (printed as %02x hex)
  int plen = 0;                      // prefix length (bits)
  int scope = 0;                     // __ipv6_addr_type() & IPV6_ADDR_SCOPE_MASK
  int flags = 0;                     // IFA_F_* (u8)
  std::string iface;                 // dev->name
};

struct Snapshot {
  long long ts = 0;
  std::vector<Addr> addrs;

  std::size_t count_scope(int s) const {
    return static_cast<std::size_t>(
      std::count_if(addrs.begin(), addrs.end(), [s](const Addr& a) { return a.scope == s; }));
  }
  std::size_t count_flag(int f) const {
    return static_cast<std::size_t>(
      std::count_if(addrs.begin(), addrs.end(), [f](const Addr& a) { return (a.flags & f) != 0; }));
  }
  std::size_t count_ula() const {
    return static_cast<std::size_t>(
      std::count_if(addrs.begin(), addrs.end(), [](const Addr& a) { return (a.words[0] & 0xfe00) == 0xfc00; }));
  }
  std::set<std::string> ifaces() const {
    std::set<std::string> s;
    for (const auto& a : addrs) s.insert(a.iface);
    return s;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Kernel constants (include/uapi/linux/if_addr.h, include/net/ipv6.h)
// ─────────────────────────────────────────────────────────────────────────────
enum : int {
  IFA_F_SECONDARY    = 0x01,   // temporary / privacy address
  IFA_F_NODAD        = 0x02,   // no duplicate-address detection
  IFA_F_OPTIMISTIC   = 0x04,   // usable before DAD completes
  IFA_F_DADFAILED    = 0x08,   // DAD failed, address unusable
  IFA_F_HOMEADDRESS  = 0x10,   // home address (MIPv6)
  IFA_F_DEPRECATED   = 0x20,   // preferred lifetime expired
  IFA_F_TENTATIVE    = 0x40,   // DAD in progress
  IFA_F_PERMANENT    = 0x80,   // static (no lifetime)
};

// Scope values as printed (__ipv6_addr_type() & IPV6_ADDR_SCOPE_MASK=0x00f0)
enum : int {
  SCOPE_GLOBAL = 0x00,   // 2000::/3 unicast, ULA fc00::/7, ...
  SCOPE_HOST   = 0x10,   // IPV6_ADDR_LOOPBACK (::1)
  SCOPE_LINK   = 0x20,   // fe80::/10 link-local
  SCOPE_SITE   = 0x40,   // fec0::/10 site-local (deprecated)
  SCOPE_ORG    = 0x80,   // org-local (rare)
};

static const char* scope_name(int s) {
  switch (s) {
    case SCOPE_GLOBAL: return "global";
    case SCOPE_HOST:   return "host";
    case SCOPE_LINK:   return "link";
    case SCOPE_SITE:   return "site";
    case SCOPE_ORG:    return "org";
    default:           return "?";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static std::optional<int> parse_hex(std::string_view s) {
  if (s.empty()) return std::nullopt;
  int v = 0;
  for (char c : s) {
    int d = hex_val(c);
    if (d < 0) return std::nullopt;
    v = v * 16 + d;
  }
  return v;
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string pad(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return s + std::string(w - s.size(), ' ');
}
static std::string padl(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return std::string(w - s.size(), ' ') + s;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\t': o += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
    }
  }
  return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 — parse 32-hex string (kernel %pi6, bytes in network order, no colons)
// and compress per RFC 5952 (longest zero-word run, ties -> first).
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_addr32(std::string_view hex, std::array<uint16_t, 8>& words) {
  if (hex.size() != 32) return false;
  for (int i = 0; i < 8; ++i) {
    int v = 0;
    for (int j = 0; j < 4; ++j) {
      int d = hex_val(hex[i * 4 + j]);
      if (d < 0) return false;
      v = v * 16 + d;
    }
    words[static_cast<std::size_t>(i)] = static_cast<uint16_t>(v);
  }
  return true;
}

static std::string compress_ipv6(const std::array<uint16_t, 8>& w) {
  int best_start = -1, best_len = 0;
  int i = 0;
  while (i < 8) {
    if (w[static_cast<std::size_t>(i)] == 0) {
      int j = i;
      while (j < 8 && w[static_cast<std::size_t>(j)] == 0) ++j;
      int len = j - i;
      if (len >= 2 && len > best_len) { best_start = i; best_len = len; }
      i = j;
    } else {
      ++i;
    }
  }
  auto fmt_word = [&](int k) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", w[static_cast<std::size_t>(k)]);
    return std::string(buf);
  };
  if (best_start < 0) {           // no zero-run: full address
    std::string full;
    for (int k = 0; k < 8; ++k) {
      if (!full.empty()) full += ':';
      full += fmt_word(k);
    }
    return full;
  }
  std::string left, right;
  for (int k = 0; k < best_start; ++k) {
    if (!left.empty()) left += ':';
    left += fmt_word(k);
  }
  for (int k = best_start + best_len; k < 8; ++k) {
    if (!right.empty()) right += ':';
    right += fmt_word(k);
  }
  return left + "::" + right;
}

// Well-known classification for ASSIGNED addresses (unicast/anycast on ifaces).
static const char* well_known(const std::array<uint16_t, 8>& w) {
  bool all_zero = true, zero_run = true;
  for (int i = 0; i < 8; ++i) {
    if (w[static_cast<std::size_t>(i)] != 0) { all_zero = false; if (i < 7) zero_run = false; }
  }
  if (all_zero) return "unspecified";
  if (zero_run && w[7] == 1) return "loopback";
  if ((w[0] & 0xffc0) == 0xfe80) return "link-local";
  if ((w[0] & 0xfe00) == 0xfc00) return "ula";
  if (w[0] == 0x2001 && w[1] == 0x0db8) return "doc-range";
  if (w[0] == 0x0064 && w[1] == 0xff9b) return "nat64";
  if (w[0] == 0x2001 && w[1] == 0x0000) return "teredo";
  if (w[0] == 0x2002) return "6to4";
  if ((w[0] & 0xe000) == 0x2000) return "global";
  return "other";
}

static std::string flag_names(int flags) {
  std::string out;
  auto add = [&](int bit, const char* name) {
    if ((flags & bit) != 0) {
      if (!out.empty()) out += "|";
      out += name;
    }
  };
  add(IFA_F_SECONDARY, "SECONDARY");
  add(IFA_F_NODAD, "NODAD");
  add(IFA_F_OPTIMISTIC, "OPTIMISTIC");
  add(IFA_F_DADFAILED, "DADFAILED");
  add(IFA_F_HOMEADDRESS, "HOME");
  add(IFA_F_DEPRECATED, "DEPRECATED");
  add(IFA_F_TENTATIVE, "TENTATIVE");
  add(IFA_F_PERMANENT, "PERMANENT");
  if (out.empty()) out = "-";
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser — /proc/net/if_inet6 (kernel if6_seq_show, net/ipv6/addrconf.c):
//   %pi6 %02x %02x %02x %02x %8s\n   (addr, ifindex, plen, scope, flags, name)
// Comments (#) and malformed lines are skipped.
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_ifinet6_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') continue;
    auto tok = split_ws(t);
    if (tok.size() < 5) continue;               // need addr + 4 hex + iface
    Addr a;
    if (!parse_addr32(tok[0], a.words)) continue;
    std::optional<int> v;
    v = parse_hex(tok[1]); if (!v) continue; a.ifindex = *v;
    v = parse_hex(tok[2]); if (!v) continue; a.plen = *v;
    v = parse_hex(tok[3]); if (!v) continue; a.scope = *v;
    v = parse_hex(tok[4]); if (!v) continue; a.flags = *v;
    a.iface = tok[5];
    snap.addrs.push_back(std::move(a));
  }
  return true;
}

static bool load_snapshot(Snapshot& snap, const std::string& path) {
  snap.addrs.clear();
  bool ok = parse_ifinet6_file(path, snap);
  std::stable_sort(snap.addrs.begin(), snap.addrs.end(),
                   [](const Addr& a, const Addr& b) {
                     if (a.iface != b.iface) return a.iface < b.iface;
                     return compress_ipv6(a.words) < compress_ipv6(b.words);
                   });
  return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// Filters
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  bool json = false;
  bool demo = false;
  bool color = true;
  std::string iface;        // exact interface name
  std::string scope;        // global|host|link|site|org
  std::string flag;         // permanent|tentative|deprecated|secondary|...
  bool only_global = false, only_link = false, only_host = false;
  bool only_ula = false, only_permanent = false;
  std::string file;
  int top = 0;
  int watch = 0;
};

static bool flag_matches(int flags, std::string_view name) {
  if (name == "permanent")  return (flags & IFA_F_PERMANENT) != 0;
  if (name == "tentative")  return (flags & IFA_F_TENTATIVE) != 0;
  if (name == "deprecated") return (flags & IFA_F_DEPRECATED) != 0;
  if (name == "secondary")  return (flags & IFA_F_SECONDARY) != 0;
  if (name == "dadfailed")  return (flags & IFA_F_DADFAILED) != 0;
  if (name == "optimistic") return (flags & IFA_F_OPTIMISTIC) != 0;
  if (name == "nodad")      return (flags & IFA_F_NODAD) != 0;
  if (name == "home")       return (flags & IFA_F_HOMEADDRESS) != 0;
  return false;   // unknown flag name -> matches nothing
}

static bool passes(const Addr& a, const Filters& f) {
  if (!f.iface.empty() && a.iface != f.iface) return false;
  if (!f.scope.empty() && std::string(scope_name(a.scope)) != f.scope) return false;
  if (!f.flag.empty() && !flag_matches(a.flags, f.flag)) return false;
  if (f.only_global && a.scope != SCOPE_GLOBAL) return false;
  if (f.only_link && a.scope != SCOPE_LINK) return false;
  if (f.only_host && a.scope != SCOPE_HOST) return false;
  if (f.only_ula && (a.words[0] & 0xfe00) != 0xfc00) return false;
  if (f.only_permanent && (a.flags & IFA_F_PERMANENT) == 0) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo — synthetic busy host (5 interfaces, 10 addresses)
// ─────────────────────────────────────────────────────────────────────────────
static const char* DEMO_TABLE =
  "# if_inet6 demo — synthetic busy host (comment tolerated)\n"
  "00000000000000000000000000000001 01 80 10 80       lo\n"
  "fe800000000000000000000000000000 02 40 20 80       eth0\n"
  "20010db8000000000000000000000001 02 40 00 80       eth0\n"
  "20010db8000000000000000000000002 02 40 00 01       eth0\n"
  "fd000000000000000000000000000001 03 40 00 80       docker0\n"
  "fe800000000000000000000000000001 04 40 20 80       wlan0\n"
  "20010db8123400000000000000000001 04 40 00 20       wlan0\n"
  "20010db8123400000000000000000002 04 40 00 41       wlan0\n"
  "fe800000000000000000000000000002 05 40 20 80       tailscale0\n"
  "fd7a115c000000000000000000000001 05 40 00 80       tailscale0\n";

static bool demo_load(Snapshot& snap) {
  std::string path = "/tmp/ifinet6-watch-demo.table";
  {
    std::ofstream f(path);
    if (!f) return false;
    f << DEMO_TABLE;
  }
  bool ok = load_snapshot(snap, path);
  std::remove(path.c_str());
  return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render
// ─────────────────────────────────────────────────────────────────────────────
static std::string scope_color(int scope) {
  switch (scope) {
    case SCOPE_GLOBAL: return C_GREEN;
    case SCOPE_HOST:   return C_YELLOW;
    case SCOPE_LINK:   return C_CYAN;
    case SCOPE_SITE:   return C_MAGENTA;
    case SCOPE_ORG:    return C_MAGENTA;
    default:           return C_DIM;
  }
}

static void render_snapshot(const Snapshot& s, const Filters& f, bool watch_hdr) {
  std::vector<const Addr*> rows;
  for (const auto& a : s.addrs) if (passes(a, f)) rows.push_back(&a);
  if (f.top > 0 && static_cast<int>(rows.size()) > f.top)
    rows.resize(static_cast<std::size_t>(f.top));

  if (watch_hdr) std::cout << "\x1b[2J\x1b[H";

  std::cout << C_BOLD << "-- IPv6 assigned addresses  /proc/net/if_inet6 --" << C_RESET << "\n";
  std::cout << "  " << C_DIM << "interfaces " << C_RESET << C_CYAN << s.ifaces().size() << C_RESET
            << "  " << C_DIM << "addresses " << C_RESET << C_BOLD << s.addrs.size() << C_RESET
            << "  " << C_DIM << "host " << C_RESET << C_YELLOW << s.count_scope(SCOPE_HOST) << C_RESET
            << "  " << C_DIM << "link " << C_RESET << C_CYAN << s.count_scope(SCOPE_LINK) << C_RESET
            << "  " << C_DIM << "global " << C_RESET << C_GREEN << s.count_scope(SCOPE_GLOBAL) << C_RESET
            << "  " << C_DIM << "ula " << C_RESET << C_MAGENTA << s.count_ula() << C_RESET
            << "  " << C_DIM << "perm " << C_RESET << C_GREEN << s.count_flag(IFA_F_PERMANENT) << C_RESET
            << "  " << C_DIM << "tent " << C_RESET << C_YELLOW << s.count_flag(IFA_F_TENTATIVE) << C_RESET
            << "  " << C_DIM << "depr " << C_RESET << C_RED << s.count_flag(IFA_F_DEPRECATED) << C_RESET
            << "\n";
  std::cout << "  " << C_DIM << "source: " << C_RESET
            << (f.demo ? "demo (synthetic busy host)" : (f.file.empty() ? "/proc/net/if_inet6" : f.file))
            << "   shown " << rows.size() << "/" << s.addrs.size() << "\n\n";

  std::cout << C_DIM
            << "  address           plen  scope      flags                         iface"
            << C_RESET << "\n";
  std::cout << C_DIM
            << "  -------------------------------------------------------------------------------------"
            << C_RESET << "\n";

  for (const auto* a : rows) {
    std::string addr = compress_ipv6(a->words);
    const char* wkn = well_known(a->words);
    if (std::string(wkn) != "other" && std::string(wkn) != "global")
      addr += " (" + std::string(wkn) + ")";
    std::string flags = flag_names(a->flags);
    bool bad = (a->flags & IFA_F_DADFAILED) != 0 || (a->flags & IFA_F_DEPRECATED) != 0;
    std::string flag_col = bad ? C_RED
                          : ((a->flags & IFA_F_TENTATIVE) != 0 ? C_YELLOW
                          : ((a->flags & IFA_F_PERMANENT) != 0 ? C_GREEN : C_DIM));

    std::cout << "  " << scope_color(a->scope) << pad(addr, 20) << C_RESET
              << " " << padl(std::to_string(a->plen), 3)
              << "  " << scope_color(a->scope) << pad(scope_name(a->scope), 8) << C_RESET
              << "  " << flag_col << pad(flags, 29) << C_RESET
              << "  " << C_BOLD << a->iface << C_RESET
              << "\n";
  }
  std::cout << std::flush;
}

static void render_json(std::ostream& os, const Snapshot& s, bool demo) {
  os << "{\n  \"summary\": {\n";
  os << "    \"interfaces\": " << s.ifaces().size() << ",\n";
  os << "    \"addresses\": " << s.addrs.size() << ",\n";
  os << "    \"host\": " << s.count_scope(SCOPE_HOST) << ",\n";
  os << "    \"link\": " << s.count_scope(SCOPE_LINK) << ",\n";
  os << "    \"global\": " << s.count_scope(SCOPE_GLOBAL) << ",\n";
  os << "    \"site\": " << s.count_scope(SCOPE_SITE) << ",\n";
  os << "    \"ula\": " << s.count_ula() << ",\n";
  os << "    \"permanent\": " << s.count_flag(IFA_F_PERMANENT) << ",\n";
  os << "    \"tentative\": " << s.count_flag(IFA_F_TENTATIVE) << ",\n";
  os << "    \"deprecated\": " << s.count_flag(IFA_F_DEPRECATED) << ",\n";
  os << "    \"dadfailed\": " << s.count_flag(IFA_F_DADFAILED) << ",\n";
  os << "    \"ts\": " << s.ts << ",\n";
  os << "    \"source\": \"" << (demo ? "demo" : "proc") << "\"\n";
  os << "  },\n  \"addresses\": [\n";
  for (std::size_t i = 0; i < s.addrs.size(); ++i) {
    const auto& a = s.addrs[i];
    os << "    {\"addr\": \"" << json_escape(compress_ipv6(a.words)) << "\""
       << ", \"ifindex\": " << a.ifindex
       << ", \"plen\": " << a.plen
       << ", \"scope\": \"" << json_escape(scope_name(a.scope)) << "\""
       << ", \"scope_hex\": \"0x" ;
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%02x", a.scope);
    os << buf << "\""
       << ", \"flags\": \"" << json_escape(flag_names(a.flags)) << "\""
       << ", \"flags_hex\": \"0x";
    std::snprintf(buf, sizeof(buf), "%02x", a.flags);
    os << buf << "\""
       << ", \"iface\": \"" << json_escape(a.iface) << "\""
       << ", \"well_known\": \"" << json_escape(well_known(a.words)) << "\""
       << "}";
    if (i + 1 < s.addrs.size()) os << ",";
    os << "\n";
  }
  os << "  ]\n}\n";
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  std::map<std::string, const Addr*> prev_m, cur_m;
  for (const auto& a : prev.addrs) if (passes(a, f)) prev_m[compress_ipv6(a.words) + "@" + a.iface] = &a;
  for (const auto& a : cur.addrs)  if (passes(a, f)) cur_m[compress_ipv6(a.words) + "@" + a.iface] = &a;

  int born = 0, died = 0, flag_changed = 0, scope_changed = 0;
  for (const auto& [k, a] : cur_m) {
    if (!prev_m.contains(k)) ++born;
    else {
      const Addr* p = prev_m.at(k);
      if (p->flags != a->flags) ++flag_changed;
      if (p->scope != a->scope) ++scope_changed;
    }
  }
  for (const auto& [k, a] : prev_m) if (!cur_m.contains(k)) ++died;

  std::cout << C_DIM << "  delta vs previous: "
            << C_GREEN << "+" << born << " new  "
            << C_RED << "-" << died << " gone  "
            << C_CYAN << flag_changed << " flags  "
            << C_MAGENTA << scope_changed << " scope"
            << C_RESET << "\n";
  for (const auto& [k, a] : cur_m) {
    if (!prev_m.contains(k))
      std::cout << "    " << C_GREEN << "+ " << compress_ipv6(a->words) << "/" << a->plen
                << " on " << a->iface << C_RESET << "\n";
    else {
      const Addr* p = prev_m.at(k);
      if (p->flags != a->flags)
        std::cout << "    " << C_YELLOW << "~ " << compress_ipv6(a->words) << " on " << a->iface
                  << ": flags " << flag_names(p->flags) << " -> " << flag_names(a->flags)
                  << C_RESET << "\n";
    }
  }
  for (const auto& [k, a] : prev_m) {
    if (!cur_m.contains(k))
      std::cout << "    " << C_RED << "- " << compress_ipv6(a->words) << "/" << a->plen
                << " on " << a->iface << C_RESET << "\n";
  }
  std::cout << std::flush;
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void t_check(bool ok, const char* name) {
  if (ok) { ++g_pass; std::cout << "  PASS  " << name << "\n"; }
  else    { ++g_fail; std::cout << "  FAIL  " << name << "\n"; }
}

static std::string compress_str(std::string_view hex) {
  std::array<uint16_t, 8> w{};
  if (!parse_addr32(hex, w)) return "<bad>";
  return compress_ipv6(w);
}

static int run_selftest() {
  std::cout << "-- selftest: IPv6 parse + compress (RFC 5952) --\n";
  t_check(compress_str("00000000000000000000000000000001") == "::1", "::1 compressed");
  t_check(compress_str("00000000000000000000000000000000") == "::", "unspecified ::");
  t_check(compress_str("fe800000000000000000000000000000") == "fe80::", "fe80:: compressed");
  t_check(compress_str("20010db8000000000000000000000001") == "2001:db8::1", "2001:db8::1");
  t_check(compress_str("20010db8123400000000000000000001") == "2001:db8:1234::1", "2001:db8:1234::1");
  t_check(compress_str("20010db8000000000001000000000001") == "2001:db8::1:0:0:1", "tie -> first run kept");
  t_check(compress_str("20010db8000000000000000000000002") == "2001:db8::2", "2001:db8::2");
  t_check(compress_str("0000000000000000000000000000ffff") == "::ffff", "::ffff");
  t_check(compress_str("ff020000000000000000000000000001") == "ff02::1", "ff02::1 multicast");
  t_check(compress_str("20010000000000000000000000000001") == "2001::1", "2001::1");
  t_check(compress_str("123456789abcdef0123456789abcdef0") == "1234:5678:9abc:def0:1234:5678:9abc:def0", "full form");
  t_check(compress_str("1234") == "<bad>", "short hex rejected");
  t_check(compress_str("gg0000000000000000000000000000001") == "<bad>", "non-hex rejected");

  std::cout << "-- selftest: well-known classification --\n";
  std::array<uint16_t, 8> w{};
  parse_addr32("00000000000000000000000000000001", w);
  t_check(std::string(well_known(w)) == "loopback", "::1 -> loopback");
  parse_addr32("fe800000000000000000000000000000", w);
  t_check(std::string(well_known(w)) == "link-local", "fe80:: -> link-local");
  parse_addr32("fd000000000000000000000000000001", w);
  t_check(std::string(well_known(w)) == "ula", "fd00::1 -> ula");
  parse_addr32("20010db8000000000000000000000001", w);
  t_check(std::string(well_known(w)) == "doc-range", "2001:db8::1 -> doc-range");
  parse_addr32("0064ff9b000000000000000000000001", w);
  t_check(std::string(well_known(w)) == "nat64", "64:ff9b::1 -> nat64");
  parse_addr32("20020000000000000000000000000001", w);
  t_check(std::string(well_known(w)) == "6to4", "2002::1 -> 6to4");
  parse_addr32("2607f8b0400000000000000000000001", w);
  t_check(std::string(well_known(w)) == "global", "2607:f8b0:4000::1 -> global");

  std::cout << "-- selftest: scope + flags decode --\n";
  t_check(scope_name(0x10) == std::string("host"), "scope 0x10 -> host");
  t_check(scope_name(0x20) == std::string("link"), "scope 0x20 -> link");
  t_check(scope_name(0x00) == std::string("global"), "scope 0x00 -> global");
  t_check(scope_name(0x40) == std::string("site"), "scope 0x40 -> site");
  t_check(scope_name(0x80) == std::string("org"), "scope 0x80 -> org");
  t_check(flag_names(0x80) == "PERMANENT", "flags 0x80 -> PERMANENT");
  t_check(flag_names(0x40) == "TENTATIVE", "flags 0x40 -> TENTATIVE");
  t_check(flag_names(0x20) == "DEPRECATED", "flags 0x20 -> DEPRECATED");
  t_check(flag_names(0x01) == "SECONDARY", "flags 0x01 -> SECONDARY");
  t_check(flag_names(0x08) == "DADFAILED", "flags 0x08 -> DADFAILED");
  t_check(flag_names(0x41) == "SECONDARY|TENTATIVE", "flags 0x41 -> SECONDARY|TENTATIVE");
  t_check(flag_names(0x00) == "-", "flags 0x00 -> -");
  t_check(flag_matches(0x80, "permanent"), "flag filter permanent matches 0x80");
  t_check(!flag_matches(0x20, "permanent"), "flag filter permanent rejects 0x20");
  t_check(!flag_matches(0x00, "bogus"), "unknown flag filter matches nothing");

  std::cout << "-- selftest: parser --\n";
  Snapshot snap;
  snap.ts = 1;
  std::string path = "/tmp/ifinet6-watch-selftest.table";
  {
    std::ofstream f(path);
    f << "# comment\n"
         "00000000000000000000000000000001 01 80 10 80       lo\n"
         "fe800000000000000000000000000000 02 40 20 80       eth0\n"
         "20010db8000000000000000000000002 02 40 00 01       eth0\n"
         "garbage line that should be skipped\n"
         "fd000000000000000000000000000001 03 40 00 80       docker0\n";
  }
  bool ok = load_snapshot(snap, path);
  std::remove(path.c_str());
  t_check(ok, "parse file opens");
  t_check(snap.addrs.size() == 4, "4 valid rows parsed (garbage skipped)");
  if (snap.addrs.size() == 4) {
    t_check(snap.addrs[0].iface == "docker0", "sorted by iface first (docker0)");
    t_check(snap.addrs[0].plen == 64 && snap.addrs[0].scope == 0x00 && snap.addrs[0].flags == 0x80,
            "docker0 fd00::1 fields correct");
    t_check(snap.addrs[1].iface == "eth0" && snap.addrs[1].plen == 64, "eth0 addr plen 64");
    t_check(snap.addrs[1].flags == 0x01, "eth0 temp addr flags SECONDARY");
    t_check(snap.addrs[2].iface == "eth0" && snap.addrs[2].scope == 0x20, "eth0 fe80:: scope link");
    t_check(snap.addrs[3].iface == "lo" && snap.addrs[3].scope == 0x10 && snap.addrs[3].flags == 0x80,
            "lo ::1 host + permanent");
    t_check(compress_ipv6(snap.addrs[3].words) == "::1", "lo address compressed to ::1");
    t_check(snap.ifaces().size() == 3, "3 distinct interfaces");
    t_check(snap.count_scope(0x10) == 1 && snap.count_scope(0x20) == 1, "scope counts (host=1, link=1)");
    t_check(snap.count_flag(0x80) == 3, "permanent count = 3");
    t_check(snap.count_ula() == 1, "ula count = 1");
  }

  std::cout << "-- selftest: filters --\n";
  {
    Filters f;
    const auto& a0 = snap.addrs[0];   // docker0 fd00::1
    f.iface = "eth0";
    t_check(!passes(a0, f), "iface filter rejects docker0");
    f.iface.clear();
    f.only_ula = true;
    t_check(passes(a0, f), "ula filter accepts fd00::1");
    f.only_ula = false;
    f.scope = "link";
    t_check(!passes(a0, f), "scope filter rejects global");
    f.scope = "global";
    t_check(passes(a0, f), "scope filter accepts global");
    f.scope.clear();
    f.only_permanent = true;
    t_check(passes(a0, f), "permanent filter accepts 0x80");
    f.only_permanent = false;
    f.flag = "secondary";
    t_check(!passes(a0, f), "flag secondary rejects permanent");
  }

  std::cout << "-- selftest: demo + JSON --\n";
  {
    Snapshot d;
    bool dok = demo_load(d);
    t_check(dok, "demo loads");
    t_check(d.addrs.size() == 10, "demo has 10 addresses");
    if (d.addrs.size() == 10) {
      t_check(d.ifaces().size() == 5, "demo has 5 interfaces");
      t_check(d.count_scope(SCOPE_HOST) == 1, "demo host = 1 (::1)");
      t_check(d.count_scope(SCOPE_LINK) == 3, "demo link = 3");
      t_check(d.count_scope(SCOPE_GLOBAL) == 6, "demo global = 6");
      t_check(d.count_ula() == 2, "demo ula = 2 (fd00::1, fd7a::1)");
      t_check(d.count_flag(IFA_F_TENTATIVE) == 1, "demo tentative = 1");
      t_check(d.count_flag(IFA_F_DEPRECATED) == 1, "demo deprecated = 1");
      t_check(d.count_flag(IFA_F_SECONDARY) == 2, "demo secondary = 2");
      t_check(d.count_flag(IFA_F_PERMANENT) == 7, "demo permanent = 7");
    }
    std::ostringstream os;
    render_json(os, d, true);
    std::string j = os.str();
    t_check(j.find("\"addr\": \"::1\"") != std::string::npos, "json contains ::1");
    t_check(j.find("\"iface\": \"tailscale0\"") != std::string::npos, "json contains tailscale0");
    t_check(j.find("\"flags\": \"SECONDARY|TENTATIVE\"") != std::string::npos, "json flags combined");
    t_check(j.find("\"summary\"") != std::string::npos && j.find("\"addresses\"") != std::string::npos,
            "json has summary + addresses");
  }

  std::cout << "-- selftest: real /proc read --\n";
  {
    Snapshot r;
    bool rok = load_snapshot(r, "/proc/net/if_inet6");
    t_check(rok, "/proc/net/if_inet6 opens");
    if (rok) {
      t_check(!r.addrs.empty(), "host has at least one assigned IPv6 address");
      if (!r.addrs.empty()) {
        const auto& a = r.addrs[0];
        t_check(a.ifindex > 0 && a.plen > 0 && a.plen <= 128, "ifindex/plen sane");
        t_check(compress_ipv6(a.words).find(":") != std::string::npos, "real address compresses");
        std::ostringstream os;
        render_json(os, r, false);
        t_check(os.str().find("\"source\": \"proc\"") != std::string::npos, "json source=proc");
      }
    }
  }

  std::cout << "-- selftest: --no-color hygiene --\n";
  {
    Snapshot d;
    demo_load(d);
    Filters f;
    disable_color();
    std::ostringstream os;
    std::streambuf* old = std::cout.rdbuf(os.rdbuf());
    render_snapshot(d, f, false);
    std::cout.rdbuf(old);
    std::string out = os.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    // re-enable for the rest
    C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
    C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
    C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "ifinet6-watch — IPv6 assigned addresses monitor (/proc/net/if_inet6)\n"
    "\n"
    "Usage: ifinet6-watch [options]\n"
    "\n"
    "  --iface NAME     show only addresses of interface NAME\n"
    "  --scope NAME     show only scope: global|host|link|site|org\n"
    "  --flag NAME      show only flag: permanent|tentative|deprecated|secondary|\n"
    "                   dadfailed|optimistic|nodad|home\n"
    "  --global         only global-scope addresses\n"
    "  --link           only link-local addresses\n"
    "  --host           only host-scope (loopback)\n"
    "  --ula            only ULA (fc00::/7) addresses\n"
    "  --permanent      only IFA_F_PERMANENT addresses\n"
    "  --top N          limit rows shown\n"
    "  --watch N        refresh every N seconds with deltas\n"
    "  --json           machine-readable output\n"
    "  --demo           synthetic busy host (5 ifaces, 10 addrs)\n"
    "  --file PATH      parse a dump instead of /proc\n"
    "  --no-color       disable ANSI colors\n"
    "  --selftest       run self-tests and exit\n"
    "  -h, --help       this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  bool color_flag = true;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--iface")      { auto v = next(a); if (!v) return 2; f.iface = *v; }
    else if (a == "--scope") { auto v = next(a); if (!v) return 2; f.scope = *v; }
    else if (a == "--flag")  { auto v = next(a); if (!v) return 2; f.flag = *v; }
    else if (a == "--file")  { auto v = next(a); if (!v) return 2; f.file = *v; }
    else if (a == "--top")   { auto v = next(a); if (!v) return 2; f.top = std::atoi(v->c_str()); }
    else if (a == "--watch") { auto v = next(a); if (!v) return 2; f.watch = std::atoi(v->c_str()); }
    else if (a == "--global")     f.only_global = true;
    else if (a == "--link")       f.only_link = true;
    else if (a == "--host")       f.only_host = true;
    else if (a == "--ula")        f.only_ula = true;
    else if (a == "--permanent")  f.only_permanent = true;
    else if (a == "--json")       f.json = true;
    else if (a == "--demo")       f.demo = true;
    else if (a == "--no-color")   color_flag = false;
    else if (a == "--selftest")   return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  std::string source = f.file.empty() ? "/proc/net/if_inet6" : f.file;

  if (f.watch > 0) {
    Snapshot prev;
    bool first = true;
    for (;;) {
      Snapshot cur;
      cur.ts = now_secs();
      bool ok = f.demo ? demo_load(cur) : load_snapshot(cur, source);
      if (!ok) {
        std::cerr << "error: cannot read " << source << "\n";
        return 1;
      }
      if (!first) render_delta(prev, cur, f);
      render_snapshot(cur, f, !first);
      prev = std::move(cur);
      first = false;
      std::this_thread::sleep_for(std::chrono::seconds(f.watch));
    }
  }

  Snapshot snap;
  snap.ts = now_secs();
  bool ok = f.demo ? demo_load(snap) : load_snapshot(snap, source);
  if (!ok) {
    std::cerr << "error: cannot read " << source << "\n";
    return 1;
  }
  if (f.json) render_json(std::cout, snap, f.demo);
  else render_snapshot(snap, f, false);
  return 0;
}
