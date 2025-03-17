#include "strings.hpp"

#include "../../../utils/logger.hpp"
#include "../../../utils/utils.hpp"

namespace core::static_analysis {
bool IsASCII(char c) { return ((c != 0 && (c & ~0x7F) == 0)); }

static const usize MinStaticStringSize = 2;
static const usize MinStackStringSize = 2;

void FindStaticStrings(Target &target) {
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
            if (c == 0 && buf.size() >= MinStaticStringSize) {
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

void FindStackStrings(Target &target) {
    u64 mov_counter = 0;
    u64 first_mov_addr = 0;
    u64 offset{};
    u64 idx{};
    u64 scale{};
    for (const auto &[addr, instr] : target.disassembly.instr_map) {
        if (instr->id == X86_INS_MOV) {
            auto ops = instr->detail->x86.operands;
            if (ops[0].type == X86_OP_MEM && ops[1].type == X86_OP_IMM &&
                (ops[0].mem.base == X86_REG_EBP ||
                 ops[0].mem.base == X86_REG_RBP)) {
                mov_counter++;
                if (!first_mov_addr) {
                    first_mov_addr = addr;
                    offset = ops[0].mem.disp;
                    idx = ops[0].mem.index;
                    scale = ops[0].mem.scale;
                }
                continue;
            }
        } else if (mov_counter >= MinStackStringSize) {
            std::vector<u8> content;
            String str{
                .type = String::Type::Stack,
                .address = first_mov_addr,
                .offset = offset,
            };

            u64 last_mov_addr = first_mov_addr;
            logger::Okay("Stack string found at 0x%llx", first_mov_addr);
            for (auto it =
                     target.disassembly.instr_map.lower_bound(first_mov_addr);
                 it->second->address < addr; it++) {
                const auto [cur_addr, mov] = *it;
                logger::Debug("0x%llx %s %s", mov->address, mov->mnemonic,
                              mov->op_str);
                auto ops = mov->detail->x86.operands;
                i64 val = ops[1].imm;
                if (val && !IsASCII(val)) {
                    str.encrypted = true;
                }
                content.push_back(static_cast<u8>(val));
                last_mov_addr = mov->address;
            }

            for (auto it =
                     target.disassembly.instr_map.lower_bound(first_mov_addr);
                 it->second->address <= last_mov_addr; it++) {
                const auto [cur_addr, mov] = *it;
                str.address = mov->address;
                str.content = std::string(content.begin(), content.end());
                target.strings.push_back(str);
                target.strings_map[str.address] = str.content;
                content.erase(content.begin());
            }
        }

        mov_counter = 0;
        first_mov_addr = 0;
    }
}

void FindStrings(Target &target) {
    FindStaticStrings(target);
    FindStackStrings(target);
    for (const auto &str : target.strings) {
        logger::Debug("String at 0x%llx: %s", str.address,
                      utils::UnescapeString(str.content).c_str());
    }
}
}  // namespace core::static_analysis
