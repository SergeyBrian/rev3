#ifndef CORE_STATIC_DISASSEMBLER_HPP
#define CORE_STATIC_DISASSEMBLER_HPP

#include <capstone/capstone.h>
#include <map>

#include "../../bin.hpp"

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis::disassembler {
struct Conflict {
    enum class Accept : u8 {
        Unknown,
        Ours,
        Theirs,
    } accept;
    u64 addr{};
    u64 size{};
    usize ours_size{};
    usize theirs_size{};
    cs_insn *ours{};
    cs_insn *theirs{};
    std::map<u64, bool> bad_instructions{};

    void GuessResolution(BinInfo *bin);
    void Print();

private:
    void FindSuspiciousInstructions(cs_insn *insn, usize size, BinInfo *bin);
};

struct Disassembly {
    u64 address;
    std::map<u64, cs_insn *> instr_map;
    usize count;
    std::map<u64, u64> covered_bytes{};

    Err Disassemble(const byte *ptr, usize size, BinInfo *bin);
    void RegAccess(u64 instr_addr, cs_regs reg_write, u8 *reg_write_count,
                   cs_regs reg_read, u8 *reg_read_count);
    void RegAccess(const cs_insn *instr, cs_regs reg_write, u8 *reg_write_count,
                   cs_regs reg_read, u8 *reg_read_count);
    bool IsCovered(u64 addr);
    void Print(u64 addr, u64 count = 1);

    Disassembly();
    void PrintCoverage(size_t expected_size);

private:
    csh handle;
    cs_insn *instructions;
    Err deep_disassemble(const byte *ptr, usize size, BinInfo *bin);
    void ApplyConflictResolution(const Conflict &conflict);
};

i64 ParseOffsetPtr(const char *opstr);
u64 GetTargetAddress(const cs_insn *instr, BinInfo *bin);
u64 SolveMemAddress(const cs_insn *instr);
u64 SolveMemValue(const cs_insn *instr, BinInfo *bin);
void ResetCache();
}  // namespace core::static_analysis::disassembler

#endif
