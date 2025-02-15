#ifndef CORE_STATIC_DISASSEMBLER_HPP
#define CORE_STATIC_DISASSEMBLER_HPP

#include <capstone/capstone.h>
#include <map>

#include "../../bin.hpp"

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis::disassembler {
struct Disassembly {
    u64 address;
    cs_insn *instructions;
    std::map<u64, cs_insn *> instr_map;
    usize count;

    Err Disassemble(const byte *ptr, usize size);
    std::string GetString(u64 addr, usize size = 0,
                          std::map<u64, std::string> strings = {});
    void RegAccess(u64 instr_addr, cs_regs reg_write, u8 *reg_write_count,
                   cs_regs reg_read, u8 *reg_read_count);
    void RegAccess(const cs_insn *instr, cs_regs reg_write, u8 *reg_write_count,
                   cs_regs reg_read, u8 *reg_read_count);

    Disassembly();

private:
    csh handle;
};

void Print(const cs_insn *instr, u64 count = 1);
i64 ParseOffsetPtr(const char *opstr);
u64 GetJmpAddress(const cs_insn *instr, BinInfo *bin);
u64 GetCallAddress(const cs_insn *instr, BinInfo *bin);
u64 SolveMemAddress(const cs_insn *instr);
u64 SolveMemValue(const cs_insn *instr, BinInfo *bin);
}  // namespace core::static_analysis::disassembler

#endif
