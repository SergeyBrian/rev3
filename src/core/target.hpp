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
    Count
};

const std::map<Tag, std::string> TagName{
    {Tag::Source, "source"},
    {Tag::Sink, "sink"},
    {Tag::Trigger, "trigger"},
    {Tag::Masking, "masking"},
};

struct Function {
    u64 address{};
    u64 ret_address{};
    u16 tags{};
    std::string mangled_name{};
    std::string display_name{};
    std::string comment{};
    std::vector<u64> xrefs;
};

struct Section {
    std::string name;
    u64 address;
    usize size;
    usize virtual_size;
};

struct Target {
    std::string filename;
    std::string display_name;
    std::map<std::string, std::vector<Function>> imports;
    std::vector<Section> sections;
    std::map<u64, Function *> functions;

    Section text;

    std::unique_ptr<BinInfo> bin_info;

    static_analysis::disassembler::Disassembly disassembly;
    static_analysis::ControlFlowGraph cfg;

    std::string GetFunctionNameByAddress(u64 address);
    std::string GetEnrichedDisassembly(u64 address = 0, usize size = 0);

    explicit Target(const std::string &filename);

private:
    void MapFunctions();
};
}  // namespace core

#endif
