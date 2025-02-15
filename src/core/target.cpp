#include "target.hpp"

#include <filesystem>
#include <sstream>

#include "../utils/logger.hpp"

namespace core {
Target::Target(const std::string &filename) : filename(filename) {
    std::filesystem::path path(filename);
    display_name = path.stem().string();
}

static std::map<u64, std::string> func_name_cache{};
std::string Target::GetFunctionNameByAddress(u64 address) {
    if (func_name_cache.contains(address)) return func_name_cache.at(address);
    for (const auto &[_, funcs] : imports) {
        for (const auto &func : funcs) {
            for (const auto &xref : func.xrefs) {
                auto node = cfg.FindNodeContaining(xref);
                if (node) {
                    func_name_cache[address] = func.display_name;
                    return func.display_name;
                }
            }
        }
    }

    func_name_cache[address] = "";
    return "";
}

void Target::MapFunctions() {
    logger::Debug("Mapping functions...");
    for (auto &[_, funcs] : imports) {
        for (auto &func : funcs) {
            functions[func.address] = &func;
            for (const auto &xref : func.xrefs) {
                auto node = cfg.FindNodeContaining(xref);
                if (!node) continue;
                functions[node->block.real_address] = &func;
            }
        }
    }
}

static std::map<u64, std::map<u64, std::string>> enriched_disassembly_cache{};
std::string Target::GetEnrichedDisassembly(u64 address, usize size) {
    if (enriched_disassembly_cache.contains(address) &&
        enriched_disassembly_cache.at(address).contains(size)) {
        return enriched_disassembly_cache.at(address).at(size);
    }
    usize init_size = size;
    if (functions.empty()) MapFunctions();
    if (size == 0) size = u64_max;
    std::ostringstream res;

    auto it = disassembly.instr_map.lower_bound(address);
    for (; it != disassembly.instr_map.end(); it = std::next(it)) {
        if (size == 0) break;
        const auto &[addr, instr] = *it;
        size -= instr->size;
    }

    enriched_disassembly_cache[address][init_size] = res.str();
    return res.str();
}

static std::map<u64, std::map<u64, std::string>> strings_cache;

std::string Target::GetString(u64 addr, usize size) {
    auto it = disassembly.instr_map.lower_bound(addr);
    if (size == 0) size += it->second->size;
    if (strings_cache.contains(addr) && strings_cache[addr].contains(size)) {
        return strings_cache.at(addr).at(size);
    }

    std::stringstream ss;
    for (; it != disassembly.instr_map.end(); it = std::next(it)) {
        const auto &[address, instr] = *it;
        if (instr->address >= addr + size) break;
        ss << std::hex << "0x" << address << "\t" << instr->mnemonic << " "
           << instr->op_str;
        u8 op_count = instr->detail->x86.op_count;
        auto ops = instr->detail->x86.operands;
        bool call_processed = false;
        for (u8 i = 0; i < op_count; i++) {
            u64 addr{};
            if (ops[i].type == X86_OP_MEM) {
                addr = static_analysis::disassembler::SolveMemAddress(instr);
            } else if (ops[i].type == X86_OP_IMM) {
                addr = ops[i].imm;
            }

            if (strings_map.contains(addr)) {
                ss << COLOR_BLUE << "\t`" << strings_map.at(addr) << "` "
                   << COLOR_RESET;
            }
            if (!call_processed) {
                call_processed = true;
                for (const auto &[_, funcs] : imports) {
                    for (const auto &func : funcs) {
                        for (const auto &xref : func.xrefs) {
                            if (addr == xref + bin_info->ImageBase()) {
                                ss << COLOR_YELLOW << "\t[" << func.display_name
                                   << "]" << COLOR_RESET;
                            }
                        }
                    }
                }
            }
        }
        ss << "\n";
    }
    strings_cache[addr][size] = ss.str();
    return ss.str();
}
}  // namespace core
