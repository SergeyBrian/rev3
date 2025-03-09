#include "patterns.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analysis {

bool InstrMatchesPattern(cs_insn *instr, std::vector<Pattern> &pattern,
                         u64 *step) {
    auto detail = instr->detail->x86;
    if (*step >= pattern.size()) return false;
    auto &cur_pattern = pattern.at(*step);
    bool skip_instructions = false;
    if (*step > 0 &&
        pattern.at(*step - 1).stmt.type == Pattern::Stmt::Type::Any) {
        skip_instructions = true;
    }
    switch (cur_pattern.stmt.type) {
        case Pattern::Stmt::Type::Any:
            *step += 1;
            return true;
        case Pattern::Stmt::Type::Insn:
            if (cur_pattern.stmt.insn.id != instr->id) {
                return skip_instructions;
            }
            if (cur_pattern.stmt.insn.left_op.type != X86_OP_INVALID &&
                cur_pattern.stmt.insn.left_op.type != detail.operands[0].type) {
                return skip_instructions;
            }
            if (cur_pattern.stmt.insn.right_op.type != X86_OP_INVALID &&
                cur_pattern.stmt.insn.right_op.type !=
                    detail.operands[1].type) {
                return skip_instructions;
            }
            *step += 1;
            cur_pattern.stmt.satisfied_by = instr->address;
            return true;
        case Pattern::Stmt::Type::Jump:
            if (!disassembler::CreatesBranch(
                    static_cast<x86_insn>(instr->id))) {
                logger::Debug("%s is not good instruction for Jump statement",
                              instr->mnemonic);
                return skip_instructions;
            }
            u64 jump_target{};
            switch (cur_pattern.stmt.jump.relative) {
                case Pattern::Stmt::Jump::Relative::ToSelf:
                    jump_target =
                        instr->address + cur_pattern.stmt.jump.address;
                    break;
                case Pattern::Stmt::Jump::Relative::ToStmt:
                    jump_target = pattern.at(cur_pattern.stmt.jump.address)
                                      .stmt.satisfied_by;
                    break;
                case Pattern::Stmt::Jump::Relative::Absolute:
                    jump_target = cur_pattern.stmt.jump.address;
                    break;
            }

            switch (cur_pattern.stmt.jump.type) {
                case Pattern::Stmt::Jump::Type::Equal:
                    if (static_cast<u64>(detail.operands[0].imm) ==
                        jump_target) {
                        *step += 1;
                        cur_pattern.stmt.satisfied_by = instr->address;
                        return true;
                    } else {
                        return skip_instructions;
                    }
                case Pattern::Stmt::Jump::Type::Before:
                    if (static_cast<u64>(detail.operands[0].imm) <
                        jump_target) {
                        *step += 1;
                        cur_pattern.stmt.satisfied_by = instr->address;
                        return true;
                    } else {
                        logger::Debug("0x%llx >= 0x%llx",
                                      static_cast<u64>(detail.operands[0].imm),
                                      jump_target);
                        return skip_instructions;
                    }
                case Pattern::Stmt::Jump::Type::After:
                    if (static_cast<u64>(detail.operands[0].imm) >
                        jump_target) {
                        *step += 1;
                        cur_pattern.stmt.satisfied_by = instr->address;
                        return true;
                    } else {
                        return skip_instructions;
                    }
            }
    }
}

bool MatchPattern(const Target *target, const Function *function,
                  std::vector<Pattern> &pattern) {
    auto it = target->disassembly.instr_map.lower_bound(function->address);

    u64 pattern_step = 0;
    for (; it != target->disassembly.instr_map.end(); it = std::next(it)) {
        const auto &[addr, instr] = *it;
        if (!InstrMatchesPattern(instr, pattern, &pattern_step)) {
            logger::Debug("Pattern statement %d not satisfied", pattern_step);
            return false;
        }
        logger::Debug("Pattern statement %d satisfied", pattern_step - 1);
        if (pattern_step >= pattern.size()) break;
        if (instr->id == X86_INS_RET) break;
    }

    bool res = pattern_step >= pattern.size();
    if (!res) {
        logger::Debug("Not all statements satisfied");
    }
    return res;
}
}  // namespace core::static_analysis
