#ifndef CORE_STATIC_FILE_HPP
#define CORE_STATIC_FILE_HPP

#include <string>
#include <map>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "../utils/alias.hpp"

#include "bin.hpp"
#include "static/disas/disassembler.hpp"
#include "static/control/control.hpp"

namespace core {
enum class Tag : u8 {
    Source = 1 << 0,
    Sink = 1 << 1,
    Trigger = 1 << 2,
    Masking = 1 << 3,
    Count,
    Any = u8_max,
};

const std::map<Tag, std::string> TagName{
    {Tag::Source, "source"},
    {Tag::Sink, "sink"},
    {Tag::Trigger, "trigger"},
    {Tag::Masking, "masking"},
};

static Tag TagFromString(std::string str) {
    for (const auto &[tag, name] : TagName) {
        if (name == str) return tag;
    }

    return Tag::Any;
}

struct Reference {
    enum class Type : u8 {
        Unknown,
        Function,
        String,
        Immediate,
        Memory,
    } type{};

    u64 address{};
    i64 value{};
    bool direct{};
    x86_op_mem mem{};
};

struct Xref {
    u64 address{};
    std::vector<Reference> args;
};

struct Function {
    u64 address{};
    u64 ret_address{};
    u16 tags{};
    std::string mangled_name{};
    std::string display_name{};
    std::string comment{};
    std::map<u64, Xref> xrefs{};
};

struct Section {
    std::string name{};
    u64 address{};
    usize size{};
    usize virtual_size{};
};

struct String {
    enum class Type : u8 {
        Data,
        Stack,
    } type;
    std::string content{};
    bool encrypted{};

    u64 address{};
    u64 offset{};
};

struct Target {
    std::string filename;
    std::string display_name;
    std::map<std::string, std::vector<Function>> imports;
    std::vector<Section> sections;
    std::map<u64, Function *> functions;
    std::vector<String> strings;
    std::map<u64, std::string> strings_map;
    std::map<u64, std::vector<Reference>> references;

    Section text;

    std::unique_ptr<BinInfo> bin_info;

    static_analysis::disassembler::Disassembly disassembly;
    static_analysis::ControlFlowGraph cfg;

    [[nodiscard]] std::string GetFunctionNameByAddress(u64 address);
    [[nodiscard]] std::string GetEnrichedDisassembly(u64 address = 0,
                                                     usize size = 0);

    [[nodiscard]] std::string GetString(u64 addr, usize size = 0) const;
    [[nodiscard]] std::string GetNodeString(u64 addr) const;

    explicit Target(const std::string &filename);
    void MapFunctions();
    u64 GetFunctionFirstAddress(u64 addr) const;
};
}  // namespace core

#endif
