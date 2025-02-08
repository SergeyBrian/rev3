#ifndef CORE_STATIC_DISASSEMBLER_HPP
#define CORE_STATIC_DISASSEMBLER_HPP

#include <capstone/capstone.h>

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis::disassembler {
struct Disassembly {
    u64 address;
    cs_insn *instructions;
    usize count;

    Err Disassemble(const byte *ptr, usize size);

    Disassembly();

private:
    csh handle;
};

void Print(const cs_insn *instr, u64 count = 1);
i64 ParseOffsetPtr(const char *opstr);
}  // namespace core::static_analysis::disassembler

#endif
