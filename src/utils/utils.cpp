#include "utils.hpp"

#include <sstream>
#include <iomanip>

namespace utils {
std::string UnescapeString(const std::string &str) {
    std::ostringstream res;
    for (unsigned char c : str) {
        switch (c) {
            case '\n':
                res << "\\n";
                break;
            case '\t':
                res << "\\t";
                break;
            case '\r':
                res << "\\r";
                break;
            case '\b':
                res << "\\b";
                break;
            case '\f':
                res << "\\f";
                break;
            case '\v':
                res << "\\v";
                break;
            case '\\':
                res << "\\\\";
                break;
            case '\"':
                res << "\\\"";
                break;
            case '\0':
                res << "\\0";
                break;
            default:
                if (c < 32 || c >= 127) {
                    res << "\\x" << std::hex << std::setw(2)
                        << std::setfill('0') << (int)c << std::dec;
                } else {
                    res << c;
                }
        }
    }

    return res.str();
}
}  // namespace utils
