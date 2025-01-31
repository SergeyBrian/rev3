#include "output.hpp"
#include <iostream>

#include "../utils/logger.hpp"

namespace core::output {
void PrintImports(const Target &target) {
    std::cout << "=== Imports table [" << target.name << "] ===\n";

    for (const auto &[lib, imports] : target.imports) {
        std::cout << lib << ":\n";
        size_t max_name_length = 0;
        for (const auto &import : imports) {
            max_name_length =
                std::max(max_name_length, import.lief_info.name().size());
        }

        for (const auto &import : imports) {
            if (import.is_interesting) {
                const char *color;
                switch (import.interest_type) {
                    case InterestType::Source:
                        color = COLOR_YELLOW;
                        break;
                    case InterestType::Sink:
                        color = COLOR_GREEN;
                        break;
                    case InterestType::Masking:
                        color = COLOR_RED;
                        break;
                    default:
                        color = COLOR_RESET;
                }
                std::cout << color;
            }
            std::cout << "\t" << std::left << std::setw(max_name_length + 2)
                      << import.lief_info.name() << " 0x" << std::right
                      << std::setw(8) << std::setfill('0') << std::hex
                      << import.lief_info.hint_name_rva() << std::dec
                      << std::setfill(' ');
            if (import.is_interesting) {
                std::cout
                    << "\tPotential point of interest: "
                    << InterestTypeName[static_cast<int>(import.interest_type)]
                    << " [" << import.category << "]";
            }
            if (!import.xrefs.empty()) {
                std::cout << "\t" << import.xrefs.size() << ((import.xrefs.size() == 1) ? " ref " : " refs ") << "found";
            }

            std::cout << "\n" << COLOR_RESET;
        }
    }
}
void PrintPOIDisas(const Target &target) {
    for (const auto &[addr, entry] : target.disassembler.entries) {
        if (entry.instructions.empty()) continue;
        std::cout << "== Disassembly at 0x" << std::hex << addr << " [" << target.name << "]\n";
        for (const auto& instr : entry.instructions) {
            std::cout << std::hex << instr->address() << ": " << instr->to_string() << "\n";
        }
    }
}
}  // namespace core::output
