#include "disassembler.hpp"

#include "../../../utils/logger.hpp"

#include <regex>
#include <stdexcept>
#include <string>
#include <sstream>

#include <capstone/capstone.h>

#ifdef X86_BUILD
#define ACTIVE_CS_MODE CS_MODE_32
#else
#define ACTIVE_CS_MODE CS_MODE_64
#endif

namespace core::static_analysis::disassembler {
static const u64 MaxRegSearchOffset = 10;

u64 SolveMemAddress(const cs_insn *instr);

Err Disassembly::Disassemble(const byte *ptr, usize size) {
    Err err{};

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, ptr, size, 0x1000, 0, &instructions);
    if (count == 0) {
        return Err::DisassemblerError;
    }
    logger::Okay("Disassembly finished. %d instructions found", count);
    for (u64 i = 0; i < count; i++) {
        instr_map[instructions[i].address] = &instructions[i];
    }

    return err;
}

Disassembly::Disassembly() {
    if (cs_open(CS_ARCH_X86, ACTIVE_CS_MODE, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize capstone");
    }
}

void Disassembly::RegAccess(const cs_insn *instr, cs_regs reg_write,
                            u8 *reg_write_count, cs_regs reg_read,
                            u8 *reg_read_count) {
    if (reg_write == nullptr) {
        cs_regs dummy{};
        u8 dummy_count{};
        cs_regs_access(handle, instr, reg_read, reg_read_count, dummy,
                       &dummy_count);
    } else if (reg_read == nullptr) {
        cs_regs dummy{};
        u8 dummy_count{};
        cs_regs_access(handle, instr, dummy, &dummy_count, reg_write,
                       reg_write_count);
    } else {
        cs_regs_access(handle, instr, reg_read, reg_read_count, reg_write,
                       reg_write_count);
    }
}

void Disassembly::RegAccess(u64 instr_addr, cs_regs reg_write,
                            u8 *reg_write_count, cs_regs reg_read,
                            u8 *reg_read_count) {
    assert(reg_write != nullptr || reg_read != nullptr && "WTF are you doing");
    RegAccess(instr_map.at(instr_addr), reg_write, reg_write_count, reg_read,
              reg_read_count);
}

void Print(const cs_insn *instr, u64 count) {
    while (count--) {
        logger::Printf("0x%" PRIx64 ":\t%s\t\t%s", instr->address,
                       instr->mnemonic, instr->op_str);
        instr++;
    }
}

i64 ParseOffsetPtr(const char *opstr) {
    try {
        std::string input(opstr);
        std::regex re(R"(\[\s*[^\[\]]*\s*([\+\-])\s*0x([0-9a-fA-F]+)\s*\])");
        std::smatch match;

        if (std::regex_search(input, match, re) && match.size() > 2) {
            char sign = match[1].str()[0];
            std::stringstream ss;
            ss << std::hex << match[2].str();
            i64 offset;
            ss >> offset;

            return (sign == '-') ? -offset : offset;
        }
    } catch (const std::exception &exception) {
        logger::Error("%s", exception.what());
    }

    return 0;
}

u64 FindRegValue(x86_reg reg, const cs_insn *instr) {
    for (u64 i = 0; i < MaxRegSearchOffset; i++, instr--) {
        if (!strstr(instr->mnemonic, "mov") &&
            !strstr(instr->mnemonic, "lea")) {
            continue;
        }
        auto x86 = instr->detail->x86;
        if (x86.operands[0].type != X86_OP_REG) continue;
        if (x86.operands[1].type != X86_OP_IMM &&
            x86.operands[1].type != X86_OP_REG) {
            continue;
        }
        if (x86.operands[0].reg != reg) continue;
        if (x86.operands[1].type == X86_OP_IMM) {
            return x86.operands[1].imm;
        }
        return FindRegValue(x86.operands[1].reg, instr - 1);
    }

    return 0;
}

u64 SolveMemAddress(const cs_insn *instr) {
    cs_x86_op op{};
    for (u8 i = 0; i < instr->detail->x86.op_count; i++) {
        op = instr->detail->x86.operands[i];
        if (op.type == X86_OP_MEM) break;
    }
    auto reg = op.mem.base;
    auto disp = op.mem.disp;
    auto index = op.mem.index;
    auto scale = op.mem.scale;

    u64 reg_val{};
    u64 index_val{};

    if (reg == X86_REG_INVALID) {
        reg_val = 0;
    } else if (reg == X86_REG_RIP) {
        reg_val = instr->address + instr->size;
    } else {
        reg_val = FindRegValue(reg, instr);
        if (!reg_val) return 0;
    }

    if (index == X86_REG_INVALID) {
        index_val = 0;
    } else if (index == X86_REG_RIP) {
        index_val = instr->address + instr->size;
    } else {
        index_val = FindRegValue(index, instr);
        if (!index_val) return 0;
    }

    u64 res = reg_val + index_val * scale + disp;
    return res;
}

u64 SolveMemValue(const cs_insn *instr, BinInfo *bin) {
    u64 mem_addr = SolveMemAddress(instr);

    const u8 *mem = bin->Data(mem_addr, 8);
    if (!mem) {
        logger::Warn("Failed to read memory at 0x%llx", mem_addr);
        return 0;
    }
    return *reinterpret_cast<const u64 *>(mem);
}

u64 GetJmpAddress(const cs_insn *instr, BinInfo *bin) {
    auto op = instr->detail->x86.operands[0];
    switch (op.type) {
        case X86_OP_INVALID:
            logger::Warn("Invalid jmp operand");
            return 0;
        case X86_OP_REG: {
            auto reg = op.reg;
            return FindRegValue(reg, instr);
        }
        case X86_OP_IMM:
            return op.imm;
        case X86_OP_MEM:
            return SolveMemValue(instr, bin);
        default:
            return 0;
    }
}

u64 GetCallAddress(const cs_insn *instr, BinInfo *bin) {
    auto op = instr->detail->x86.operands[0];
    switch (op.type) {
        case X86_OP_INVALID:
            logger::Warn("Invalid call operand");
            return 0;
        case X86_OP_REG: {
            auto reg = op.reg;
            return FindRegValue(reg, instr);
        }
        case X86_OP_IMM:
            return op.imm;
        case X86_OP_MEM:
            return SolveMemValue(instr, bin);
        default:
            return 0;
    }
}
}  // namespace core::static_analysis::disassembler
