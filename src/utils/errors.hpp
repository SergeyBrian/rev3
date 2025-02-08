#ifndef ERRORS_HPP
#define ERRORS_HPP

enum class ErrorCode {
    Ok,
    FileNotFound,
    ParsingError,
    UnparsedBinary,
    UnknownFormat,
    NotImplemented,
    InvalidConfigFormat,
    UnknownConfigOption,
    TextSectionNotFound,
    DisassemblerError,
    NoXrefsFound,
    Count
};

using Err = ErrorCode;

inline const char *ErrorText[static_cast<int>(ErrorCode::Count)] = {
    "No error",
    "File not found",
    "Parsing failed",
    "Binary was not parsed yet",
    "Unknown binary file format",
    "Method not implemented yet",
    "Config file has invalid format",
    "Unknown config option",
    "No .text section found",
    "Disassembler failed",
    "No xrefs found",
};

#endif
