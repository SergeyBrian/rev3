#ifndef CORE_STATIC_DISASSEMBLER_HPP
#define CORE_STATIC_DISASSEMBLER_HPP

#include <capstone/capstone.h>
#include <map>

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis::disassembler {
struct Disassembly {
    u64 address;
    cs_insn *instructions;
    std::map<u64, cs_insn *> instr_map;
    usize count;

    Err Disassemble(const byte *ptr, usize size);

    Disassembly();

private:
    csh handle;
};

void Print(const cs_insn *instr, u64 count = 1);
i64 ParseOffsetPtr(const char *opstr);
u64 GetJmpAddress(const cs_insn *instr);
u64 GetCallAddress(const cs_insn *instr);
}  // namespace core::static_analysis::disassembler

#endif
