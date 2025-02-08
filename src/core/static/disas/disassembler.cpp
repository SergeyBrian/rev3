#include "disassembler.hpp"

#include "../../../utils/logger.hpp"

#include <regex>
#include <stdexcept>
#include <string>
#include <sstream>

#include <capstone/capstone.h>

namespace core::static_analysis::disassembler {
Err Disassembly::Disassemble(const byte *ptr, usize size) {
    Err err{};

    count = cs_disasm(handle, ptr, size, 0x1000, 0, &instructions);
    if (count == 0) {
        return Err::DisassemblerError;
    }
    logger::Okay("Disassembly finished. %d instructions found", count);

    return err;
}

Disassembly::Disassembly() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize capstone");
    }
}
void Print(const cs_insn *instr, u64 count) {
    while (count--) {
        logger::Printf("0x%" PRIx64 ":\t%s\t\t%s\n", instr->address, instr->mnemonic,
               instr->op_str);
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
}  // namespace core::static_analysis::disassembler
