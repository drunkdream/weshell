#include "common.h"

#include <mutex>

static std::mutex g_logMutex;

void gpLog(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

void gpLogW(const wchar_t* fmt, ...) {
    wchar_t buffer[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, ap);
    va_end(ap);

    char ansi[8192];
    int n = WideCharToMultiByte(CP_ACP, 0, buffer, -1, ansi, sizeof(ansi) - 1, nullptr, nullptr);
    if (n > 0) {
        ansi[n - 1] = 0;
        gpLog("%s", ansi);
    }
}

static int Base64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> gpBase64Decode(const std::string& text) {
    std::vector<uint8_t> out;
    int value = 0;
    int bits = -8;
    for (char c : text) {
        if (c == '=') break;
        int v = Base64Value(c);
        if (v < 0) continue;
        value = (value << 6) | v;
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<uint8_t>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::string gpWideToAnsi(const std::wstring& s) {
    if (s.empty()) return std::string();
    int len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_ACP, 0, s.c_str(), (int)s.size(), &out[0], len, nullptr, nullptr);
    return out;
}
