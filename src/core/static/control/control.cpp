#include "control.hpp"

#include <algorithm>
#include <cassert>
#include <deque>
#include <set>

#include "capstone/capstone.h"

#include "../../../utils/utils.hpp"
#include "../../../utils/logger.hpp"

namespace core::static_analysis {
static const u64 SectionBase = 0x1000;

std::string EdgeTypeStr(CFGEdgeType type) {
    switch (type) {
        case CFGEdgeType::Jmp:
            return "jmp";
        case CFGEdgeType::Jcc:
            return "jcc";
        case CFGEdgeType::Call:
            return "call";
        case CFGEdgeType::Ret:
            return "ret";
        default:
            return "invalid";
    }
}

enum class BlockDelimiter : u16 {
    Jo = X86_INS_JO,
    Jno = X86_INS_JNO,
    Jb = X86_INS_JB,
    Jae = X86_INS_JAE,
    Je = X86_INS_JE,
    Jne = X86_INS_JNE,
    Jbe = X86_INS_JBE,
    Ja = X86_INS_JA,
    Js = X86_INS_JS,
    Jns = X86_INS_JNS,
    Jp = X86_INS_JP,
    Jnp = X86_INS_JNP,
    Jl = X86_INS_JL,
    Jge = X86_INS_JGE,
    Jle = X86_INS_JLE,
    Ljmp = X86_INS_LJMP,
    Jmp = X86_INS_JMP,
    Call = X86_INS_CALL,
    Lcall = X86_INS_LCALL,
    Ret = X86_INS_RET,
    Retf = X86_INS_RETF,
    Retfq = X86_INS_RETFQ,
    Int = X86_INS_INT,
    Syscall = X86_INS_SYSCALL,
    Sysenter = X86_INS_SYSENTER,
    Iret = X86_INS_IRET,
    Hlt = X86_INS_HLT,
    Into = X86_INS_INTO,
    Int1 = X86_INS_INT1,
    Int3 = X86_INS_INT3,
};

bool IsDelimiter(u16 opcode) {
    switch (static_cast<BlockDelimiter>(opcode)) {
        case BlockDelimiter::Jo:
        case BlockDelimiter::Jno:
        case BlockDelimiter::Jb:
        case BlockDelimiter::Jae:
        case BlockDelimiter::Je:
        case BlockDelimiter::Jne:
        case BlockDelimiter::Jbe:
        case BlockDelimiter::Ja:
        case BlockDelimiter::Js:
        case BlockDelimiter::Jns:
        case BlockDelimiter::Jp:
        case BlockDelimiter::Jnp:
        case BlockDelimiter::Jl:
        case BlockDelimiter::Jge:
        case BlockDelimiter::Jle:
        case BlockDelimiter::Ljmp:
        case BlockDelimiter::Jmp:
        case BlockDelimiter::Call:
        case BlockDelimiter::Lcall:
        case BlockDelimiter::Ret:
        case BlockDelimiter::Retf:
        case BlockDelimiter::Retfq:
        case BlockDelimiter::Int:
        case BlockDelimiter::Syscall:
        case BlockDelimiter::Sysenter:
        case BlockDelimiter::Iret:
        case BlockDelimiter::Hlt:
        case BlockDelimiter::Into:
        case BlockDelimiter::Int1:
        case BlockDelimiter::Int3:
            return true;
        default:
            return false;
    }
}

CFGEdgeType GetEdgeType(u16 opcode) {
    switch (static_cast<BlockDelimiter>(opcode)) {
        case BlockDelimiter::Jo:
        case BlockDelimiter::Jno:
        case BlockDelimiter::Jb:
        case BlockDelimiter::Jae:
        case BlockDelimiter::Je:
        case BlockDelimiter::Jne:
        case BlockDelimiter::Jbe:
        case BlockDelimiter::Ja:
        case BlockDelimiter::Js:
        case BlockDelimiter::Jns:
        case BlockDelimiter::Jp:
        case BlockDelimiter::Jnp:
        case BlockDelimiter::Jl:
        case BlockDelimiter::Jge:
        case BlockDelimiter::Jle:
            return CFGEdgeType::Jcc;
        case BlockDelimiter::Ljmp:
        case BlockDelimiter::Jmp:
            return CFGEdgeType::Jmp;
        case BlockDelimiter::Call:
        case BlockDelimiter::Lcall:
            return CFGEdgeType::Call;
        case BlockDelimiter::Ret:
        case BlockDelimiter::Retf:
        case BlockDelimiter::Retfq:
            return CFGEdgeType::Ret;
        case BlockDelimiter::Int:
        case BlockDelimiter::Syscall:
        case BlockDelimiter::Sysenter:
        case BlockDelimiter::Iret:
        case BlockDelimiter::Hlt:
        case BlockDelimiter::Into:
        case BlockDelimiter::Int1:
        case BlockDelimiter::Int3:
            return CFGEdgeType::Int;
        default:
            return CFGEdgeType::Invalid;
    }
}

void CFGEdge::Log() const {
#ifndef NDEBUG
    logger::Debug("0x%llx ==%s==> 0x%llx", source->block.address,
                  EdgeTypeStr(type).c_str(), target->block.address);
#endif
}

void Deduplicate(std::vector<CFGEdge> &edges) {
    std::sort(edges.begin(), edges.end(),
              [](const CFGEdge &a, const CFGEdge &b) {
                  if (a.source->block.address != b.source->block.address) {
                      return a.source->block.address < b.source->block.address;
                  }
                  return a.target->block.address < b.target->block.address;
              });
    auto last = std::unique(
        edges.begin(), edges.end(), [](const CFGEdge &a, const CFGEdge &b) {
            return a.source->block.address == b.source->block.address &&
                   a.target->block.address == b.target->block.address;
        });

    edges.erase(last, edges.end());
}

ControlFlowGraph::ControlFlowGraph() = default;
Err ControlFlowGraph::Build(disassembler::Disassembly *disas, BinInfo *bin,
                            const std::vector<u64> &targets,
                            const std::vector<std::string> labels) {
    Err err{};

    logger::Info("Building control flow graph");
    logger::Debug("Using %d target addresses", targets.size());
    logger::Debug("Mapping base blocks...");

    MapBaseBlocks(disas, bin);

    for (u64 i = 0; i < targets.size(); i++) {
        auto node = FindNodeContaining(targets[i]);
        if (node) {
            logger::Okay("Found path to target 0x%llx (%s)", targets[i],
                         labels[i].c_str());
            node->label = labels[i];
        }
    }

    logger::Debug("Cleaning up edges");
    for (auto &[addr, node] : nodes) {
        Deduplicate(node->in_edges);
        Deduplicate(node->out_edges);
    }

    logger::Debug("Checking graph");

    for (const auto &[addr, node] : nodes) {
        if (node->returns && node->block.address >= SectionBase &&
            node->callers.empty()) {
            logger::Warn("Node 0x%llx returns but is never called", addr);
        }
        if (node->returns && node->out_edges.empty()) {
            logger::Warn(
                "Node 0x%llx is marked returning but has no outgoing edges",
                node->block.address);
        }
    }

    logger::Okay("Control flow graph build finished");
    logger::Info("%d Nodes found", nodes.size());
    logger::Info("%d Fake nodes found", 0xFFF - fake_node_counter);

    return err;
}

CFGNode *ControlFlowGraph::FindNode(u64 address) const {
    auto it = nodes.find(address);
    if (it != nodes.end()) return it->second.get();
    for (u64 i = 0; i < SectionBase; i++) {
        if (nodes.contains(i) && nodes.at(i)->block.real_address == address) {
            return (it != nodes.end()) ? it->second.get() : nullptr;
        }
    }
    return nullptr;
}

CFGNode *ControlFlowGraph::FindNodeContaining(u64 address) const {
    for (const auto &[addr, node] : nodes) {
        if (((node->block.address <= address &&
              address < node->block.address + node->block.size) ||
             (node->block.address == address && node->block.size == 0)) ||
            ((node->block.real_address <= address &&
              address < node->block.real_address + node->block.size) ||
             (node->block.real_address == address && node->block.size == 0))) {
            return node.get();
        }
    }

    return nullptr;
}

void ControlFlowGraph::AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type,
                               Condition condition) {
    logger::Debug("\t0x%llx ==%s==> 0x%llx", from->block.address,
                  EdgeTypeStr(type).c_str(), to->block.address);
#ifndef NDEBUG
    u64 from_before = from->out_edges.size();
    u64 to_before = to->in_edges.size();
#endif
    from->out_edges.push_back({
        .type = type,
        .target = to,
        .source = from,
        .condition = condition,
    });
    to->in_edges.push_back({
        .type = type,
        .target = to,
        .source = from,
        .condition = condition,
    });
#ifndef NDEBUG
    u64 from_after = from->out_edges.size();
    u64 to_after = to->in_edges.size();
#endif

    assert(from_before < from_after);
    assert(to_before < to_after);
}

u64 GetNextNodeAddress(u64 addr, disassembler::Disassembly *disas,
                       BinInfo *bin) {
    auto it = disas->instr_map.lower_bound(addr);
    auto &[_, instr] = *it;

    CFGEdgeType type = GetEdgeType(instr->id);

    switch (type) {
        case CFGEdgeType::Jmp:
        case CFGEdgeType::Jcc:
        case CFGEdgeType::Call:
            return disassembler::GetTargetAddress(instr, bin);
        case CFGEdgeType::Ret:
        case CFGEdgeType::Int:
        case CFGEdgeType::Invalid:
        default:
            return 0;
    }
}

CFGNode *ControlFlowGraph::InsertFakeNode(u64 real_address) {
    if (fake_node_counter == 0) {
        logger::Error("Too many unknown nodes.");
        return nullptr;
    }

    u64 fake_address{};
    if (real_address != 0) {
        if (fake_nodes.contains(real_address)) {
            fake_address = fake_nodes.at(real_address);
            logger::Okay("Reference to existing fake address 0x%llx (0x%llx)",
                         real_address, fake_address);
            return FindNode(fake_address);
        } else {
            fake_address = fake_node_counter--;
            fake_nodes[real_address] = fake_address;
        }
    } else {
        fake_address = fake_node_counter--;
    }

    logger::Debug("Inserting fake node 0x%llx", fake_address);

    auto node = std::make_unique<CFGNode>();
    node->block.address = fake_address;
    node->block.real_address = real_address;
    node->returns = true;
    nodes[fake_address] = std::move(node);

    return nodes[fake_address].get();
}

CFGNode *ControlFlowGraph::InsertNode(u64 address) {
    CFGNode *return_node{};
    if (nodes.contains(address)) {
        return_node = nodes.at(address).get();
        logger::Okay("+++ Existing node 0x%llx +++", address);
    } else {
        logger::Okay("+++ Inserted node 0x%llx +++", address);
        auto tmp = std::make_unique<CFGNode>();
        tmp->block.address = address;
        tmp->block.real_address = address;
        return_node = tmp.get();
        nodes[address] = std::move(tmp);
    }

    return return_node;
}

Flag GetFlagsTested(const cs_insn *instr) {
    Flag res{};
    if (X86_EFLAGS_TEST_CF & instr->detail->x86.eflags) {
        res |= Flag::CF;
    }
    if (X86_EFLAGS_TEST_PF & instr->detail->x86.eflags) {
        res |= Flag::PF;
    }
    if (X86_EFLAGS_TEST_AF & instr->detail->x86.eflags) {
        res |= Flag::AF;
    }
    if (X86_EFLAGS_TEST_ZF & instr->detail->x86.eflags) {
        res |= Flag::ZF;
    }
    if (X86_EFLAGS_TEST_SF & instr->detail->x86.eflags) {
        res |= Flag::SF;
    }
    if (X86_EFLAGS_TEST_OF & instr->detail->x86.eflags) {
        res |= Flag::OF;
    }

    return res;
}

Flag GetFlagsWritten(const cs_insn *instr) {
    Flag res{};
    if ((X86_EFLAGS_MODIFY_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_SET_CF) &
        instr->detail->x86.eflags) {
        res |= Flag::CF;
    }
    if ((X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_SET_PF) &
        instr->detail->x86.eflags) {
        res |= Flag::PF;
    }
    if ((X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_SET_AF) &
        instr->detail->x86.eflags) {
        res |= Flag::AF;
    }
    if ((X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_SET_ZF) &
        instr->detail->x86.eflags) {
        res |= Flag::ZF;
    }
    if ((X86_EFLAGS_MODIFY_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_SET_SF) &
        instr->detail->x86.eflags) {
        res |= Flag::SF;
    }
    if ((X86_EFLAGS_MODIFY_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_SET_OF) &
        instr->detail->x86.eflags) {
        res |= Flag::OF;
    }

    return res;
}

// Assumes comparison type from conditional jump alone
Operator OperatorFromInstr(const cs_insn *instr) {
    switch (static_cast<x86_insn>(instr->id)) {
        case X86_INS_JE:
            return Operator::Equal;
        case X86_INS_JGE:
            return Operator::GreaterThanOrEqual;
        case X86_INS_JG:
        case X86_INS_JNS:
            return Operator::GreaterThan;
        case X86_INS_JLE:
            return Operator::LessThanOrEqual;
        case X86_INS_JL:
        case X86_INS_JS:
            return Operator::LessThan;
        case X86_INS_JNE:
            return Operator::NotEqual;
        default:
            return Operator::Invalid;
    }
}

RegCmpCondition MakeRegCmpCondition(Operator op, const cs_insn *instr,
                                    disassembler::Disassembly *disas,
                                    BinInfo *bin, Err *err) {
    RegCmpCondition res{};
    if (instr->detail->x86.op_count == 1) {
        auto operand = instr->detail->x86.operands[0];
        switch (operand.type) {
            case X86_OP_INVALID:
                logger::Error("Invalid operand in %s %s", instr->mnemonic,
                              instr->op_str);
                *err = Err::InvalidOperand;
                return {};
            case X86_OP_REG:
                res.lhs = operand.reg;
            case X86_OP_IMM:
                res.lhs = operand.imm;
            case X86_OP_MEM:
                res.lhs.type = Operand::Type::Mem;
                res.lhs.mem_address = disassembler::SolveMemValue(instr, bin);
                break;
        }

        res.rhs = 0;
        res.op = op;

        return res;
    }

    cs_regs reg_write{};
    u8 reg_write_count{};
    cs_regs reg_read{};
    u8 reg_read_count{};
    auto lhs = instr->detail->x86.operands[0];
    auto rhs = instr->detail->x86.operands[1];

    if (lhs.type == X86_OP_INVALID || rhs.type == X86_OP_INVALID) {
        logger::Error("Invalid operand in %s %s", instr->mnemonic,
                      instr->op_str);
        *err = Err::InvalidOperand;
        return {};
    }

    disas->RegAccess(instr, reg_write, &reg_write_count, reg_read,
                     &reg_read_count);

    // Handle initial setup common for all operands
    switch (lhs.type) {
        case X86_OP_REG:
            res.lhs = lhs.reg;
            break;
        case X86_OP_IMM:
            res.lhs = lhs.imm;
            break;
        case X86_OP_MEM: {
            res.lhs = disassembler::SolveMemValue(instr, bin);
            res.lhs.type = Operand::Type::Mem;
        } break;
        default:
            UNREACHABLE
    }
    switch (rhs.type) {
        case X86_OP_REG:
            res.rhs = rhs.reg;
            break;
        case X86_OP_IMM:
            res.rhs = rhs.imm;
            break;
        case X86_OP_MEM: {
            res.rhs = disassembler::SolveMemValue(instr, bin);
            res.rhs.type = Operand::Type::Mem;
        } break;
        default:
            UNREACHABLE
    }
    res.op = op;

    switch (static_cast<x86_insn>(instr->id)) {
        case X86_INS_CMP: {
        } break;
        case X86_INS_TEST: {
            if (lhs.type == X86_OP_REG && rhs.type == X86_OP_REG) {
                if ((op == Operator::Equal || op == Operator::NotEqual) &&
                    lhs.reg == rhs.reg) {
                    res.lhs = lhs.reg;
                    res.rhs = 0;
                }
            }
        } break;
        default:
            break;
    }

    return res;
}

Condition MakeCondition(cs_insn *instr, disassembler::Disassembly *disas,
                        BinInfo *bin) {
    logger::Debug("Analyzing %s at 0x%llx", instr->mnemonic, instr->address);
    Condition res{};
    res.flags = GetFlagsTested(instr);
    switch (instr->id) {
        case X86_INS_JCXZ:
            res.type = Condition::Type::RegCmp;
            res.reg_cmp.lhs.reg = X86_REG_CX;
            res.reg_cmp.rhs.constant = 0;
            res.reg_cmp.op = Operator::Equal;
            break;
        case X86_INS_JECXZ:
            res.type = Condition::Type::RegCmp;
            res.reg_cmp.lhs.reg = X86_REG_ECX;
            res.reg_cmp.rhs.constant = 0;
            res.reg_cmp.op = Operator::Equal;
            break;
        case X86_INS_JRCXZ:
            res.type = Condition::Type::RegCmp;
            res.reg_cmp.lhs.reg = X86_REG_RCX;
            res.reg_cmp.rhs.constant = 0;
            res.reg_cmp.op = Operator::Equal;
            break;
        default:
            break;
    }

    // Only J*CXZ case
    if (res.type == Condition::Type::RegCmp) return res;

    u8 effective_instr_idx{};
    Flag active_flags = res.flags;

    // TODO: EXTREMELLY unsafe, need to set lower bound for instr
    auto it = disas->instr_map.lower_bound(instr->address);
    while (it != disas->instr_map.begin() && static_cast<u8>(active_flags)) {
        auto [_, tmp] = *it--;
        assert(
            effective_instr_idx < 3 &&
            "Programming error. No more than two instructions can affect JCC");
        Flag flags_written = GetFlagsWritten(tmp);
        logger::Debug("Inspecting %s %s", tmp->mnemonic, tmp->op_str);
        if (!static_cast<u8>(flags_written & active_flags)) continue;
        logger::Okay("Instruction sets required flags");
        res.affected_by_instr[effective_instr_idx++] = tmp->address;
        active_flags &= ~flags_written;
    }

    // Now that we have found all instructions that affect the condition, the
    // only thing left to do is extraction of affected registers
    for (u8 i = 0; i < 2; i++) {
        auto effective_instr = disas->instr_map.at(res.affected_by_instr[i]);
        Operator op = OperatorFromInstr(instr);
        Err err{};
        RegCmpCondition cond =
            MakeRegCmpCondition(op, effective_instr, disas, bin, &err);
        if (err != Err::Ok) {
            logger::Warn("%s in %s %s", ErrorText[static_cast<u8>(err)],
                         instr->mnemonic, instr->op_str);
            continue;
        }
        res.reg_cmp = cond;
        break;
    }

    return res;
}

u64 depth = 0;
CFGNode *ControlFlowGraph::AddNode(CFGNode *node,
                                   disassembler::Disassembly *disas,
                                   BinInfo *bin) {
    depth++;
    logger::Debug("Recursion depth: %d", depth);
    // Processes a node and returns pointer to the next node to process
    if (!disas->instr_map.contains(node->block.address)) {
        logger::Debug("Reference to invalid address 0x%llx!",
                      node->block.address);
        if (node->returns) {
            for (auto caller : node->callers) {
                AddEdge(node, caller, CFGEdgeType::Ret);
            }
        }
        depth--;
        return nullptr;
    } else {
        logger::Okay("Processing block at 0x%llx", node->block.address);
    }
    auto it = disas->instr_map.lower_bound(node->block.address);
    auto last_addr = it->first;
    auto last_instr = it->second;
    for (const auto &[addr, instr] :
         std::ranges::subrange(it, disas->instr_map.end())) {
        logger::Debug("> %s %s", instr->mnemonic, instr->op_str);
        bool is_code = bin->IsCode(addr);
        if (is_code) {
            last_instr = instr;
            last_addr = addr;
        }
        if (IsDelimiter(instr->id) || !is_code) {
            break;
        }
    }
    if (it == disas->instr_map.end()) {
        logger::Error("Reached end of instructions (weird)");
        depth--;
        return nullptr;
    }
    logger::Debug("Ending block on instr %s with size %d", last_instr->mnemonic,
                  last_instr->size);

    node->block.size = last_addr + last_instr->size - node->block.address;
    node->block.next_address = node->block.real_address + node->block.size;

    CFGEdgeType type = GetEdgeType(last_instr->id);

    u64 new_address = GetNextNodeAddress(last_addr, disas, bin);
    logger::Debug("Next node address: 0x%llx", new_address);

    // new_address = 0 means that algorithm was unable to resolve the next
    // address (or that there is no next address, e.g. ret)
    // if there was supposed to be an address, a fake node is inserted
    if ((new_address == 0 && type != CFGEdgeType::Ret &&
         type != CFGEdgeType::Int && type != CFGEdgeType::Invalid) ||
        (new_address != 0 && !disas->instr_map.contains(new_address))) {
        if (type == CFGEdgeType::Call) {
            auto tmp = InsertFakeNode(new_address);
            if (!tmp) {
                logger::Error("Insert fake node returned 0");
                depth--;
                return nullptr;
            }
            new_address = tmp->block.address;
        } else {
            logger::Debug("Node 0x%llx skipped", new_address);
            depth--;
            return nullptr;
        }
    } else {
        logger::Okay("Found next node address: 0x%llx", new_address);
    }

    CFGNode *new_node_ptr{};
    bool target_exists = false;

    // since there might be multiple references to a single node, we check
    // whether the target address was already processed. If target node is fake,
    // it's assumed that it is already processed and that is does end with ret
    if (new_address != 0) {
        if (!nodes.contains(new_address)) {
            new_node_ptr = InsertNode(new_address);
        } else {
            logger::Debug("Found %s reference to existing node 0x%llx",
                          last_instr->mnemonic, new_address);
            new_node_ptr = nodes.at(new_address).get();
            target_exists = true;
        }
    }

    // if we do jmp into next block before returning to current node's caller,
    // the caller propagates to the next nodes so that when one of them
    // eventually returns, corresponding edge is correctly added.
    if (type == CFGEdgeType::Jmp || type == CFGEdgeType::Jcc) {
        for (const auto caller : node->callers) {
            if (!utils::contains(new_node_ptr->callers, caller)) {
                new_node_ptr->callers.push_back(caller);
            }
        }
        logger::Debug("New callers:");
        for (const auto caller : new_node_ptr->callers) {
            logger::Debug("0x%llx", caller->block.address);
        }
    }

    switch (type) {
        case CFGEdgeType::Jmp:
            AddEdge(node, new_node_ptr, type);
            break;
        case CFGEdgeType::Jcc: {
            auto cond = MakeCondition(last_instr, disas, bin);
            logger::Okay("========= CONSTRUCTED CONDITION =========");

            AddEdge(node, new_node_ptr, type, cond);

            u64 next_addr = last_addr + last_instr->size;
            auto second_node = InsertNode(next_addr);

            for (const auto caller : node->callers) {
                if (!utils::contains(second_node->callers, caller)) {
                    second_node->callers.push_back(caller);
                }
            }

            cond.inverted = true;
            AddEdge(node, second_node, type, cond);

            logger::Debug("Processing branch without jump first (0x%llx)",
                          next_addr);
            auto tmp = AddNode(second_node, disas, bin);
            while (tmp) {
                tmp = AddNode(tmp, disas, bin);
            }
        } break;
        case CFGEdgeType::Call: {
            AddEdge(node, new_node_ptr, type);
            // If a new call is found to a node that is already parsed and
            // marked as returning, we need to build returning edges from it to
            // current node

            u64 return_addr = last_addr + last_instr->size;
            auto return_node = InsertNode(return_addr);
            logger::Debug("Setting return address 0x%llx (current: 0x%llx)",
                          return_addr, last_addr);
            new_node_ptr->callers.push_back(return_node);
            if (new_node_ptr->returns) {
                logger::Debug("Found call to returning node");
                for (const auto caller : node->callers) {
                    AddEdge(new_node_ptr, caller, CFGEdgeType::Ret);
                }
            }
            for (const auto caller : node->callers) {
                if (!utils::contains(return_node->callers, caller)) {
                    return_node->callers.push_back(caller);
                }
            }

            logger::Debug("Processing return address first (0x%llx)",
                          return_addr);
            auto tmp = AddNode(return_node, disas, bin);
            while (tmp) {
                tmp = AddNode(tmp, disas, bin);
            }
            logger::Debug("Processing call address now (0x%llx)", new_address);
            logger::Debug("target_exists: %s",
                          target_exists ? "true" : "false");
        } break;
        case CFGEdgeType::Ret:
            node->returns = true;
            logger::Debug("Block 0x%llx returns", node->block.address);
            for (auto caller : node->callers) {
                logger::Debug("Caller 0x%llx", caller->block.address);
                AddEdge(node, caller, type);
            }
            depth--;
            return nullptr;
            break;
        case CFGEdgeType::Int:
        case CFGEdgeType::Invalid:
            depth--;
            return nullptr;
    }

    depth--;
    return (target_exists && new_node_ptr->block.size != 0) ? nullptr
                                                            : new_node_ptr;
}

CFGNode *ControlFlowGraph::MakeFirstNode(disassembler::Disassembly *disas,
                                         BinInfo *bin) {
    auto node = std::make_unique<CFGNode>();
    u64 addr{};
    for (auto &[a, instruction] : disas->instr_map) {
        if (instruction->address < bin->EntryPoint()) continue;
        addr = instruction->address;
        node->block.address = addr;
        node->block.real_address = addr;
        if (bin->IsCode(addr)) {
            break;
        }
    }
    logger::Debug("Making first node at 0x%llx", addr);

    nodes[addr] = std::move(node);
    return nodes[addr].get();
}

void ControlFlowGraph::MapBaseBlocks(disassembler::Disassembly *disas,
                                     BinInfo *bin) {
    auto node = MakeFirstNode(disas, bin);
    while (node) {
        node = AddNode(node, disas, bin);
    }

    if (nodes.contains(0)) {
        nodes.erase(0);
    }
}

std::unique_ptr<ControlFlowGraph> ControlFlowGraph::MakeCFG(
    std::vector<BaseBlock> blocks, std::vector<EdgeTemplate> edges) {
    auto res = std::make_unique<ControlFlowGraph>();

    for (const auto &block : blocks) {
        auto node = std::make_unique<CFGNode>();
        node->block = block;
        res->nodes[block.address] = std::move(node);
    }

    for (const auto &edge : edges) {
        auto from = res->FindNode(edge.from);
        auto to = res->FindNode(edge.to);

        if (!from) {
            std::cerr << "Bad edge source: 0x" << std::hex << edge.from
                      << std::dec << "\n";
            return nullptr;
        }

        if (!to) {
            std::cerr << "Bad edge target: 0x" << std::hex << edge.to
                      << std::dec << "\n";
            return nullptr;
        }

        CFGEdge new_edge{
            .type = edge.type,
            .target = to,
            .source = from,
        };
        from->out_edges.push_back(new_edge);
        to->in_edges.push_back(new_edge);
    }

    return res;
}

CFGNode::~CFGNode() = default;

// Vertex represents a node in a denormalized graph. A returning node, that has
// multiple callers, will create a Vertex for each caller and this vertex will
// only return to correcponding node
struct Vertex {
    CFGNode *node;

    std::vector<CFGNode *> in;
    std::vector<CFGNode *> out;

    Vertex(CFGNode *node) : node(node) {
        assert(node->callers.size() <= 1 &&
               "Vertex(CFGNode *) constructor can only be used on nodes with "
               "no more than one caller");
        for (const auto &edge : node->in_edges) {
            in.push_back(edge.source);
        }
        for (const auto &edge : node->out_edges) {
            in.push_back(edge.target);
        }
    }
};

std::vector<u64> ControlFlowGraph::FindXrefs(std::string label) {
    std::vector<u64> res{};

    for (const auto &[addr, node] : nodes) {
        if (node->label == label) {
            res.push_back(addr);
        }
    }

    return res;
}

std::vector<CFGNode *> ControlFlowGraph::FindPath(u64 start, u64 target) const {
    std::vector<CFGNode *> res{};

    auto start_node = FindNodeContaining(start);
    if (!start_node) {
        logger::Error("Unable to find starting node");
        return res;
    }

    auto target_node = FindNodeContaining(target);
    if (!target_node) {
        logger::Error("Unable to find target node");
        return res;
    }

    logger::Info("Searching for path 0x%llx -> 0x%llx",
                 start_node->block.address, target_node->block.address);

    std::deque<CFGNode *> stack{};
    std::set<CFGNode *> visited{};

    stack.push_back(start_node);

    while (!stack.empty()) {
        for (const auto &node : stack) {
            printf("0x%llx -> ", node->block.address);
        }
        printf("\n");
        auto node = stack.back();
        if (visited.contains(node)) {
            stack.pop_back();
            continue;
        }
        logger::Debug("Visiting 0x%llx", node->block.address);

        if (node == target_node) {
            logger::Okay("Success!");
            break;
        }

        bool fully_explored = true;
        for (const auto &edge : node->out_edges) {
            bool skip_edge = false;
            bool edge_found = false;
            if (edge.type == CFGEdgeType::Ret ||
                visited.contains(edge.target) || edge.target == node) {
                skip_edge = true;
            }

            edge.Log();
            if (!skip_edge && !utils::contains(stack, edge.target)) {
                fully_explored = false;
                stack.push_back(edge.target);
                edge_found = true;
            }

            // Because if we already fucking visited the fucking call target we
            // still need to fucking return from it bruh
            if (edge.type == CFGEdgeType::Call) {
                auto ret_node = FindNode(node->block.next_address);
                if (ret_node && !visited.contains(ret_node)) {
                    fully_explored = false;
                    logger::Debug("Will return to 0x%llx",
                                  ret_node->block.address);
                    stack.push_back(ret_node);
                }
            }

            if (edge_found) break;
        }
        if (fully_explored) {
            visited.insert(node);
            stack.pop_back();
        }
    }

    return res;
}
}  // namespace core::static_analysis
