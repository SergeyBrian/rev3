#include "calls.hpp"

#include "../../../utils/logger.hpp"
#include "capstone/x86.h"

namespace core::static_analysis {
[[maybe_unused]] const u64 MaxArgSearchOffset = 10;
const u64 MagicHashNumber = 0x9e3779b97f4a7c15;

void FindCallArgs(const Target &target, Xref *call) {
    logger::Debug("Searching for args at 0x%llx", call->address);
    auto node = target.cfg.FindNodeContaining(call->address);
    if (!node) return;

    auto it = target.disassembly.instr_map.lower_bound(node->block.address);
    for (; it != target.disassembly.instr_map.end(); it = std::next(it)) {
        const auto &[address, instr] = *it;
        if (instr->address >= node->block.next_address) break;
        if (instr->id != X86_INS_MOV && instr->id != X86_INS_LEA &&
            instr->id != X86_INS_PUSH)
            continue;

        if (instr->id == X86_INS_MOV || instr->id == X86_INS_LEA) {
            switch (static_cast<x86_reg>(instr->detail->x86.operands[0].reg)) {
                case X86_REG_RCX:
                case X86_REG_RDX:
                case X86_REG_R8:
                case X86_REG_R9:
                case X86_REG_XMM0:
                case X86_REG_XMM1:
                case X86_REG_XMM2:
                case X86_REG_XMM3:
                    break;
                default:
                    continue;
            }
        }

        if (target.references.contains(instr->address)) {
            logger::Debug("Reference ok. +1 arg");
#ifdef X86_BUILD

            call->args.insert(call->args.begin(), 1,
                              target.references.at(instr->address)[0]);
#else
            for (const auto &ref : target.references.at(instr->address)) {
                if (ref.direct) {
                    call->args.insert(call->args.begin(), 1, ref);
                }
            }
#endif
        } else {
            logger::Debug("Reference not ok. +1 arg");
            call->args.insert(call->args.begin(), 1,
                              {
                                  .type = Reference::Type::Unknown,
                                  .address = instr->address,
                              });
        }
    }
}

struct ReferenceHolder {
    enum class Type : u8 {
        Register,
        Address,
        Stack,
    } type;

    x86_reg reg{};
    u64 address{};
    u64 offset{};

    Reference ref{};

    u64 Hash() {
        u64 res = static_cast<u64>(type);
        switch (type) {
            case Type::Register:
                res ^= (static_cast<u64>(reg) * MagicHashNumber);
                break;
            case Type::Address:
                res ^= (address * MagicHashNumber);
                break;
            case Type::Stack:
                res ^= (offset * MagicHashNumber);
                break;
        }
        return res;
    }

    static u64 RegHash(x86_reg reg) {
        return static_cast<u64>(Type::Register) ^
               (static_cast<u64>(reg) * MagicHashNumber);
    }

    static u64 Hash(cs_x86_op op) {
        switch (op.type) {
            case X86_OP_REG:
                return static_cast<u64>(Type::Register) ^
                       (static_cast<u64>(op.reg) * MagicHashNumber);
            case X86_OP_MEM:
                switch (op.mem.base) {
                    case X86_REG_EBP:
                    case X86_REG_RBP:
                        return static_cast<u64>(Type::Stack) ^
                               (op.mem.disp * MagicHashNumber);
                    default:
                        return 0;
                }
            default:
                return 0;
        }
    }

    static ReferenceHolder FromInsn(cs_insn *instr, Err *err) {
        u8 op_count = instr->detail->x86.op_count;
        auto ops = instr->detail->x86.operands;
        ReferenceHolder res{};

        if (op_count < 1) {
            *err = Err::InvalidOperand;
            return res;
        }

        switch (static_cast<x86_insn>(instr->id)) {
            case X86_INS_LEA:
            case X86_INS_MOV:
                switch (ops[0].type) {
                    case X86_OP_REG:
                        res.type = Type::Register;
                        res.reg = ops[0].reg;
                        return res;
                        break;
                    case X86_OP_MEM: {
                        auto mem = ops[0].mem;
                        if (mem.base != X86_REG_EBP &&
                            mem.base != X86_REG_RBP) {
                            *err = Err::InvalidOperand;
                            return res;
                        }
                        res.type = Type::Stack;
                        res.offset = mem.disp;
                        return res;
                    } break;
                    default:
                        *err = Err::InvalidOperand;
                        return res;
                }
            default:
                *err = Err::InvalidOperand;
                return res;
        }
    }
};

void FindReferences(Target &target) {
    std::map<u64, ReferenceHolder> refs;

    for (const auto &[addr, instr] : target.disassembly.instr_map) {
        if (instr->id == X86_OP_INVALID) continue;
        logger::Debug("Ref search in 0x%llx", addr);
        u8 op_count = instr->detail->x86.op_count;
        auto ops = instr->detail->x86.operands;
        bool call_processed = false;
        Err err{};

        cs_regs reg_write{};
        u8 reg_write_count{};

        target.disassembly.RegAccess(instr, reg_write, &reg_write_count,
                                     nullptr, nullptr);

        for (u8 i = 0; i < reg_write_count; i++) {
            refs.erase(
                ReferenceHolder::RegHash(static_cast<x86_reg>(reg_write[i])));
        }

        if (instr->id == X86_INS_MOV &&
            (ops[0].reg == X86_REG_EBP || ops[0].reg == X86_REG_RBP)) {
            for (auto it = refs.begin(); it != refs.end();) {
                if (it->second.type == ReferenceHolder::Type::Stack) {
                    it = refs.erase(it);
                } else {
                    it++;
                }
            }
        }

        // cur_ref represents the ReferenceHolder assigned to current
        // instruction due to the specifics of ReferenceHolder, one instruction
        // can only hold one reference. i.e. if instruction is mov reg, <ref>;
        // it obviously can hold only one reference. since pointers are not
        // valid reference holder, only one operand can possibly be a reference
        // in a ReferenceHolder instruction, so we can safely ignore every
        // reference except for the one in the last operand.
        auto cur_ref = ReferenceHolder::FromInsn(instr, &err);
        bool persistent_ref = true;
        Reference final_ref{};

        if (err != Err::Ok) {
            logger::Debug("ReferenceHolder not ok");
            persistent_ref = false;
        }

        for (u8 i = 0; i < op_count; i++) {
            u64 ref_addr{};
            if (target.strings_map.contains(addr)) {
                // For strings located on stack
                ref_addr = addr;
            } else if (ops[i].type == X86_OP_MEM) {
                ref_addr =
                    static_analysis::disassembler::SolveMemAddress(instr);
                if (ops[i].mem.base == X86_REG_RIP) {
                    ref_addr += target.bin_info->ImageBase();
                }
            } else if (ops[i].type == X86_OP_IMM) {
                ref_addr = ops[i].imm;
            }

            u64 ref_id = ReferenceHolder::Hash(ops[i]);
            logger::Debug("Check 0x%llx (0x%llx)", ref_id, ops[i].mem.disp);
            if (ref_id && refs.contains(ref_id)) {
                auto ref = refs.at(ref_id);
                logger::Debug("Reference to existing holder found");
                final_ref = ref.ref;
                final_ref.direct = false;
                target.references[addr].push_back(final_ref);
                continue;
            } else if (target.strings_map.contains(ref_addr)) {
                logger::Debug("String found!");
                final_ref = {
                    .type = Reference::Type::String,
                    .address = ref_addr,
                    .direct = true,
                };
                target.references[addr].push_back(final_ref);
            } else if (instr->id == X86_INS_PUSH && ops[0].type == X86_OP_IMM &&
                       !target.strings_map.contains(ref_addr) &&
                       !target.functions.contains(ref_addr) &&
                       !target.strings_map.contains(
                           ref_addr - target.bin_info->ImageBase()) &&
                       !target.functions.contains(
                           ref_addr - target.bin_info->ImageBase())) {
                target.references[addr].push_back({
                    .type = Reference::Type::Immediate,
                    .value = ops[0].imm,
                    .direct = true,
                });
            } else if (instr->id == X86_INS_LEA && ops[1].type == X86_OP_MEM) {
                final_ref = {
                    .type = Reference::Type::Memory,
                    .mem = ops[1].mem,
                    .address = 0,
                    .direct = true,
                };
                target.references[addr].push_back(final_ref);
                continue;
            }

            if (call_processed) {
                continue;
            }
            call_processed = true;
            if (ref_addr > target.bin_info->ImageBase())
                ref_addr -= target.bin_info->ImageBase();
            if (target.functions.contains(ref_addr)) {
                logger::Okay("Valid direct call to 0x%llx", ref_addr);
                final_ref = {
                    .type = Reference::Type::Function,
                    .address = ref_addr,
                    .direct = true,
                };
                target.references[addr].push_back(final_ref);
            } else {
                for (const auto &[func_addr, func] : target.functions) {
                    if (func->xrefs.contains(ref_addr)) {
                        logger::Okay("Valid call to 0x%llx", func->address);
                        final_ref = {
                            .type = Reference::Type::Function,
                            .address = func->address,
                            .direct = true,
                        };
                        target.references[addr].push_back(final_ref);
                        break;
                    }
                }
            }
        }
        if (persistent_ref) {
            if (final_ref.type != Reference::Type::Unknown) {
                logger::Debug("Saving ref! (id: 0x%llx; disp: 0x%llx)",
                              cur_ref.Hash(), cur_ref.offset);
                cur_ref.ref = final_ref;
                refs[cur_ref.Hash()] = cur_ref;
            } else {
                refs.erase(cur_ref.Hash());
            }
        }

        if (instr->id == X86_INS_CALL) {
            refs.erase(ReferenceHolder::RegHash(X86_REG_EAX));
            refs.erase(ReferenceHolder::RegHash(X86_REG_RAX));
        }
    }
}

void FindCallsArgs(Target &target) {
    std::set<u64> visited;
    for (const auto &[_, func] : target.functions) {
        logger::Debug("Call args search candidate: 0x%llx", func->address);
        for (auto &[xref_addr, xref] : func->xrefs) {
            if (visited.contains(xref_addr)) continue;
            visited.insert(xref_addr);
            FindCallArgs(target, &xref);
        }
    }
}
}  // namespace core::static_analysis
