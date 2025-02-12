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
}  // namespace core
