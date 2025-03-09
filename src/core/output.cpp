#include "output.hpp"
#include <iostream>

#include <iomanip>

#include "../utils/logger.hpp"

namespace core::output {
void PrintImports(const Target &target) {
    std::cout << "=== Imports table [" << target.display_name << "] ===\n";

    for (const auto &[lib, imports] : target.imports) {
        std::cout << lib << ":\n";
        size_t max_name_length = 0;
        for (const auto &import : imports) {
            max_name_length =
                std::max(max_name_length, import.display_name.size());
        }

        for (const auto &import : imports) {
            if (import.tags & static_cast<u8>(Tag::Sink)) {
                std::cout << COLOR_GREEN;
            } else if (import.tags & static_cast<u8>(Tag::Source)) {
                std::cout << COLOR_YELLOW;
            }
            if (import.tags & (static_cast<u8>(Tag::Trigger) |
                               static_cast<u8>(Tag::Masking))) {
                std::cout << COLOR_RED;
            }
            std::cout << "\t" << std::left << std::setw(max_name_length + 2)
                      << import.display_name << " 0x" << std::right
                      << std::setw(8) << std::setfill('0') << std::hex
                      << import.address << std::dec << std::setfill(' ');
            if (import.tags) {
                std::cout << "\t[ ";
                for (u8 tag = 1; tag < static_cast<u8>(Tag::Count); tag <<= 1) {
                    if (import.tags & tag) {
                        std::cout << TagName.at(Tag(tag)) << " ";
                    }
                }
                std::cout << "]";
            }
            std::cout << "\n" << COLOR_RESET;
        }
    }
}

void PrintFunctions(const Target *target) {
    std::cout << "=== Functions table ===\n";
    for (const auto &[addr, func] : target->functions) {
        printf("@%s at 0x%llx %s%s%s\n", func->display_name.c_str(), addr,
               COLOR_GRAY, func->comment.c_str(), COLOR_RESET);
    }
}
}  // namespace core::output
