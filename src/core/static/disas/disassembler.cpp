#include "disassembler.hpp"

#include "../../../utils/logger.hpp"

#include <regex>
#include <stdexcept>
#include <string>
#include <sstream>

#include <capstone/capstone.h>

namespace core::static_analysis::disassembler {
static const u64 MaxRegSearchOffset = 4;

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
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize capstone");
    }
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
        Print(instr, 1);
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
        if (x86.operands[1].type == X86_OP_IMM) return x86.operands[1].imm;
        return FindRegValue(x86.operands[1].reg, instr);
    }
    logger::Warn("Failed to find reg value within %d instructions",
                 MaxRegSearchOffset);

    return 0;
}

u64 GetJmpAddress(const cs_insn *instr) {
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
            logger::Warn("Mem-based jmp not supported");
            return 0;
        default:
            return 0;
    }
}

u64 GetCallAddress(const cs_insn *instr) {
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
            logger::Warn("Mem-based call not supported");
            return 0;
        default:
            return 0;
    }
}
}  // namespace core::static_analysis::disassembler
