#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <cstdio>

#include "../config/config.hpp"

namespace logger {
enum class LogType {
    Okay,
    Debug,
    Info,
    Warning,
    Error,
};

#define COLOR_RESET "\033[0m"
#define COLOR_OKAY "\033[32m"
#define COLOR_DEBUG "\033[0m"
#define COLOR_INFO "\033[0m"
#define COLOR_WARN "\033[33m"
#define COLOR_ERROR "\033[31m"

template <typename... Args>
inline void Log(LogType log_type, const char *format, Args... args) {
    if (!config::Get().verbose_logs && log_type < LogType::Info) return;

    const char *color = COLOR_RESET;
    const char *prefix = "";

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
    }

    printf("%s%s", color, prefix);
    printf(format, args...);
    printf("%s\n", COLOR_RESET);
}

template <typename... Args>
inline void Okay(const char *format, Args... args) {
    Log(LogType::Okay, format, args...);
}

template <typename... Args>
inline void Debug(const char *format, Args... args) {
#ifndef NDEBUG
    Log(LogType::Debug, format, args...);
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
}  // namespace logger

#endif
