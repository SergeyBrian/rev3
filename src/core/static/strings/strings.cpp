#include "strings.hpp"

namespace core::static_analysis {
bool IsASCII(char c) { return ((c != 0 && (c & ~0x7F) == 0)); }

void FindStrings(Target &target) {
    for (const auto &section : target.sections) {
        if (section.name.find("data") == std::string::npos) continue;
        auto data = target.bin_info->Data(section.address, section.size);
        std::string buf{};
        u64 cur_addr{};
        for (u64 i = 0; i < section.size; i++) {
            auto c = data[i];
            if (IsASCII(c)) {
                buf.push_back(c);
                continue;
            }
            if (c == 0 && buf.size() >= 2) {
                String string{
                    .type = String::Type::Data,
                    .content = buf,
                    .address = cur_addr + target.bin_info->ImageBase(),
                };
                target.strings.push_back(string);
                target.strings_map[cur_addr + target.bin_info->ImageBase()] =
                    string.content;
                target.references[cur_addr + target.bin_info->ImageBase()] = {{
                    .type = Reference::Type::String,
                    .address = cur_addr + target.bin_info->ImageBase(),
                    .direct = true,
                }};
            }
            buf.clear();
            cur_addr = section.address + i + 1;
        }
    }
}
}  // namespace core::static_analysis
