#ifndef ERRORS_HPP
#define ERRORS_HPP

enum class ErrorCode {
    Ok,
    FileNotFound,
    ParsingError,
    Count
};

using Err = ErrorCode;

inline const char *ErrorText[static_cast<int>(ErrorCode::Count)] = {
    "No error",
    "File not found",
    "Parsing failed",
};

#endif
