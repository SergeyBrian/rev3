#include "target.hpp"

#include <filesystem>
#include <sstream>

#include "../utils/logger.hpp"
#include "../utils/utils.hpp"

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
            for (const auto &[xref_address, _] : func.xrefs) {
                auto node = cfg.FindNodeContaining(xref_address);
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
            references[func.address] = {{
                .type = Reference::Type::Function,
                .address = func.address,
                .direct = true,
            }};
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

std::string Target::GetNodeString(u64 addr) const {
    auto node = cfg.FindNode(addr);
    return GetString(node->block.address, node->block.size);
}

std::string Target::GetString(u64 addr, usize size) const {
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
        if (references.contains(address)) {
            for (const auto &ref : references.at(address)) {
                switch (ref.type) {
                    case Reference::Type::Immediate:
                        ss << COLOR_BLUE << "\t0x" << ref.value << COLOR_RESET;
                        break;
                    case Reference::Type::Unknown:
                        ss << COLOR_GRAY << "\t?0x" << ref.address
                           << COLOR_RESET;
                        break;
                    case Reference::Type::Function: {
                        auto func = functions.at(ref.address);
                        ss << (ref.direct ? COLOR_YELLOW : COLOR_GRAY) << "\t@"
                           << func->display_name << COLOR_RESET;
                        ss << COLOR_GREEN << " (";
                        for (const auto &arg : func->xrefs.at(address).args) {
                            ss << " ";
                            switch (arg.type) {
                                case Reference::Type::Immediate:
                                    ss << "0x" << arg.value;
                                    break;
                                case Reference::Type::Unknown:
                                    ss << "?0x" << arg.address;
                                    break;
                                case Reference::Type::Function:
                                    ss << "@"
                                       << functions.at(arg.address)
                                              ->display_name;
                                    break;
                                case Reference::Type::String:
                                    ss << "`"
                                       << utils::UnescapeString(
                                              strings_map.at(arg.address))
                                       << "`";
                                    break;
                            }
                        }
                        ss << ")" << COLOR_RESET;
                    } break;
                    case Reference::Type::String:
                        ss << (ref.direct ? COLOR_BLUE : COLOR_GRAY) << "\t`"
                           << utils::UnescapeString(strings_map.at(ref.address))
                           << "`" << COLOR_RESET;
                        break;
                }
            }
        }
        ss << "\n";
    }
    strings_cache[addr][size] = ss.str();
    return ss.str();
}
}  // namespace core
