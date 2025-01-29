#include "output.hpp"
#include <iostream>

namespace core::output {
void PrintImports(const Target &target) {
    const auto imports = target.lief_info->imported_functions();
    std::cout << "Imports table [" << target.name << "]\n";
    size_t max_name_length = 0;
    for (const auto &import : imports) {
        max_name_length = std::max(max_name_length, import.name().size());
    }

    for (const auto &import : imports) {
        std::cout << std::left << std::setw(max_name_length + 2)
                  << import.name() << " 0x" << std::right << std::setw(8)
                  << std::setfill('0') << std::hex << import.address()
                  << std::dec << std::setfill(' ') << "\n";
    }
}
}  // namespace core::output
