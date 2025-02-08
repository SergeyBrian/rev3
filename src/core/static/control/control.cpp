#include "control.hpp"

#include "../parser/parser.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analysis {
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
            return CFGEdgeType::Int;
    }
}

Err ControlFlowGraph::Build(disassembler::Disassembly *disas,
                            LIEF::PE::Binary *bin,
                            const std::vector<u64> &targets) {
    Err err{};

    logger::Debug("Building control flow graph");
    logger::Debug("Using %d target addresses", targets.size());
    logger::Debug("Mapping base blocks...");

    MapBaseBlocks(disas, bin);

    return err;
}

CFGNode *ControlFlowGraph::FindNode(u64 address) const {
    auto it = nodes.find(address);
    return (it != nodes.end()) ? it->second.get() : nullptr;
}

void ControlFlowGraph::AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type) {
    from->out_edges.push_back({
        .type = type,
        .target = to,
        .source = from,
    });
    to->in_edges.push_back({
        .type = type,
        .target = to,
        .source = from,
    });
}

u64 GetNextNodeAddress(u64 addr, disassembler::Disassembly *disas) {
    u64 i = 0;
    for (; i < disas->count && disas->instructions[i].address != addr; i++);
    auto instr = &disas->instructions[i];

    CFGEdgeType type = GetEdgeType(instr->id);

    switch (type) {
        case CFGEdgeType::Jmp:
            return disassembler::GetJmpAddress(instr);
        case CFGEdgeType::Jcc:
        case CFGEdgeType::Call:
        case CFGEdgeType::Ret:
        case CFGEdgeType::Int:
            return 0;
    }
}

CFGNode *ControlFlowGraph::AddNode(CFGNode *node,
                                   disassembler::Disassembly *disas,
                                   LIEF::PE::Binary *bin) {
    // Processes a node and returns pointer to the next node to process
    auto it = disas->instr_map.lower_bound(node->block.address);
    for (const auto &[addr, instr] :
         std::ranges::subrange(it, disas->instr_map.end())) {
        if (IsDelimiter(instr->id) || !parser::IsCode(bin, addr)) {
            break;
        }
    }
    if (it == disas->instr_map.end()) {
        return nullptr;
    }
    auto [addr, instr] = *it;

    node->block.size = addr - node->block.address;

    u64 new_address = GetNextNodeAddress(addr, disas);

    auto new_node = std::make_unique<CFGNode>();
    nodes[new_address] = std::move(new_node);
    auto new_node_ptr = nodes[new_address].get();

    CFGEdgeType type = GetEdgeType(instr->id);

    switch (type) {
        case CFGEdgeType::Jmp:
            AddEdge(node, new_node_ptr, type);
            break;
        case CFGEdgeType::Jcc: {
            AddEdge(node, new_node_ptr, type);

            auto [next_addr, _] = *std::next(it);
            auto second_node = std::make_unique<CFGNode>();
            second_node->block.address = next_addr;

            AddEdge(node, second_node.get(), type);

            nodes[next_addr] = std::move(second_node);
            auto tmp = AddNode(nodes[next_addr].get(), disas, bin);
            while (tmp) {
                tmp = AddNode(tmp, disas, bin);
            }
            break;
        }
        case CFGEdgeType::Call: {
            AddEdge(node, new_node_ptr, type);

            auto [return_addr, _] = *std::next(it);
            auto return_node = std::make_unique<CFGNode>();
            return_node->block.address = return_addr;

            new_node_ptr->callers.push_back(return_node.get());
            for (const auto caller : node->callers) {
                new_node_ptr->callers.push_back(caller);
            }

            nodes[return_addr] = std::move(return_node);
            auto tmp = AddNode(nodes[return_addr].get(), disas, bin);
            while (tmp) {
                tmp = AddNode(tmp, disas, bin);
            }
            break;
        }
        case CFGEdgeType::Ret:
            for (const auto caller : node->callers) {
                AddEdge(node, caller, type);
                return nullptr;
            }
        case CFGEdgeType::Int:
            return nullptr;
    }

    return new_node_ptr;
}

CFGNode *ControlFlowGraph::MakeFirstNode(disassembler::Disassembly *disas,
                                         LIEF::PE::Binary *bin) {
    auto node = std::make_unique<CFGNode>();
    for (u64 i = 0; i < disas->count; i++) {
        auto instruction = disas->instructions[i];
        node->block.address = instruction.address;
        if (parser::IsCode(bin, instruction.address)) {
            break;
        }
    }

    nodes[node->block.address] = std::move(node);
    return nodes[node->block.address].get();
}

void ControlFlowGraph::MapBaseBlocks(disassembler::Disassembly *disas,
                                     LIEF::PE::Binary *bin) {
    auto node = MakeFirstNode(disas, bin);
    while (node) {
        node = AddNode(node, disas);
    }
}
}  // namespace core::static_analysis
