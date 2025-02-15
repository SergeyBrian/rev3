#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <cstdio>
#include <iostream>
#include <sstream>

#include "../config/config.hpp"

namespace logger {
enum class LogType {
    Print,
    Okay,
    Debug,
    Info,
    Warning,
    Error,
};

#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[36m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_GRAY "\033[90m"

#define COLOR_OKAY COLOR_GREEN
#define COLOR_DEBUG COLOR_RESET
#define COLOR_INFO COLOR_RESET
#define COLOR_WARN COLOR_YELLOW
#define COLOR_ERROR COLOR_RED

template <typename... Args>
inline void Log(LogType log_type, const char *format, Args... args) {
    if (!config::Get().verbose_logs && log_type < LogType::Info) return;

    const char *color = COLOR_RESET;
    const char *prefix = "";
    const char *reset = COLOR_RESET;

    switch (log_type) {
        case LogType::Okay:
            color = COLOR_OKAY;
            prefix = "[+] ";
            break;
        case LogType::Debug:
            color = COLOR_DEBUG;
            prefix = "[-] ";
            break;
        case LogType::Info:
            color = COLOR_INFO;
            prefix = "[-] ";
            break;
        case LogType::Warning:
            color = COLOR_WARN;
            prefix = "[*] ";
            break;
        case LogType::Error:
            color = COLOR_ERROR;
            prefix = "[!] ";
            break;
        case LogType::Print:
            color = "";
            reset = "";
            break;
    }

    printf("%s%s", color, prefix);
    printf(format, args...);
    printf("%s\n", reset);
}

template <typename... Args>
inline void Okay(const char *format, Args... args) {
    Log(LogType::Okay, format, args...);
}

template <typename... Args>
inline void Debug(const char *format, Args... args) {
#ifndef NDEBUG
    Log(LogType::Debug, format, args...);
#else
    if constexpr (sizeof...(args) > 0) {
        (void)format;
    }
#endif
}

template <typename... Args>
inline void Info(const char *format, Args... args) {
    Log(LogType::Info, format, args...);
}

template <typename... Args>
inline void Warn(const char *format, Args... args) {
    Log(LogType::Warning, format, args...);
}

template <typename... Args>
inline void Error(const char *format, Args... args) {
    Log(LogType::Error, format, args...);
}

template <typename... Args>
inline void Printf(const char *format, Args... args) {
    Log(LogType::Print, format, args...);
}

class Logger {
public:
    template <typename T>
    Logger &operator<<(const T &value) {
        if (config::Get().verbose_logs) {
            buffer_ << value;
        }
        Flush();
        return *this;
    }

private:
    std::ostringstream buffer_;

    void Flush() {
        std::cout << buffer_.str();
        buffer_.str("");
        buffer_.clear();
    }
};

inline Logger log;

}  // namespace logger

#endif
