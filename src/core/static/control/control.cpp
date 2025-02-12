#include "control.hpp"

#include <algorithm>

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
            logger::Okay("Found path to target 0x%x (%s)", targets[i],
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
            logger::Warn("Node 0x%x returns but is never called", addr);
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

void ControlFlowGraph::AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type) {
    assert(from != to);
    assert(from->block.address != to->block.address);
    logger::Debug("\t0x%x >>[%s]>> 0x%x", from->block.address,
                  EdgeTypeStr(type).c_str(), to->block.address);
    u64 from_before = from->out_edges.size();
    u64 to_before = to->in_edges.size();
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
    u64 from_after = from->out_edges.size();
    u64 to_after = to->in_edges.size();

    assert(from_before < from_after);
    assert(to_before < to_after);
}

u64 GetNextNodeAddress(u64 addr, disassembler::Disassembly *disas,
                       BinInfo *bin) {
    u64 i = 0;
    for (; i < disas->count && disas->instructions[i].address != addr; i++);
    auto instr = &disas->instructions[i];

    CFGEdgeType type = GetEdgeType(instr->id);

    switch (type) {
        case CFGEdgeType::Jmp:
        case CFGEdgeType::Jcc:
            return disassembler::GetJmpAddress(instr, bin);
        case CFGEdgeType::Call:
            return disassembler::GetCallAddress(instr, bin);
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
            logger::Okay("Reference to existing fake address 0x%x (0x%x)",
                         real_address, fake_address);
            return FindNode(fake_address);
        } else {
            fake_address = fake_node_counter--;
            fake_nodes[real_address] = fake_address;
        }
    } else {
        fake_address = fake_node_counter--;
    }

    logger::Warn("Inserting fake node 0x%x", fake_address);

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
        logger::Okay("+++ Existing node 0x%x +++", address);
    } else {
        logger::Okay("+++ Inserted node 0x%x +++", address);
        auto tmp = std::make_unique<CFGNode>();
        tmp->block.address = address;
        tmp->block.real_address = address;
        return_node = tmp.get();
        nodes[address] = std::move(tmp);
    }

    return return_node;
}

CFGNode *ControlFlowGraph::AddNode(CFGNode *node,
                                   disassembler::Disassembly *disas,
                                   BinInfo *bin) {
    // Processes a node and returns pointer to the next node to process
    if (!disas->instr_map.contains(node->block.address)) {
        logger::Warn("Reference to invalid address 0x%x!", node->block.address);
        if (node->returns) {
            for (auto caller : node->callers) {
                AddEdge(node, caller, CFGEdgeType::Ret);
            }
        }
        return nullptr;
    } else {
        logger::Okay("Processing block at 0x%x", node->block.address);
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
        return nullptr;
    }
    logger::Debug("Ending block on instr %s with size %d", last_instr->mnemonic,
                  last_instr->size);

    node->block.size = last_addr + last_instr->size - node->block.address;

    CFGEdgeType type = GetEdgeType(last_instr->id);

    u64 new_address = GetNextNodeAddress(last_addr, disas, bin);
    logger::Debug("Next node address: 0x%x", new_address);

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
                return nullptr;
            }
            new_address = tmp->block.address;
        } else {
            logger::Warn("Node 0x%x skipped", new_address);
            return nullptr;
        }
    } else {
        logger::Okay("Found next node address: 0x%x", new_address);
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
            logger::Debug("Found %s reference to existing node 0x%x",
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
            new_node_ptr->callers.push_back(caller);
        }
        logger::Debug("New callers:");
        for (const auto caller : new_node_ptr->callers) {
            logger::Debug("0x%x", caller->block.address);
        }
    }

    switch (type) {
        case CFGEdgeType::Jmp:
            AddEdge(node, new_node_ptr, type);
            break;
        case CFGEdgeType::Jcc: {
            AddEdge(node, new_node_ptr, type);

            u64 next_addr = last_addr + last_instr->size;
            auto second_node = InsertNode(next_addr);
            AddEdge(node, second_node, type);

            auto tmp = AddNode(nodes.at(next_addr).get(), disas, bin);
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
            logger::Debug("Setting return address 0x%x (current: 0x%x)",
                          return_addr, last_addr);
            new_node_ptr->callers.push_back(return_node);
            if (new_node_ptr->returns) {
                logger::Debug("Found call to returning node");
                for (const auto caller : node->callers) {
                    AddEdge(new_node_ptr, caller, CFGEdgeType::Ret);
                }
            }
            if (!new_node_ptr->returns) {
                for (const auto caller : node->callers) {
                    return_node->callers.push_back(caller);
                }
            }

            logger::Debug("Processing return address first (0x%x)",
                          return_addr);
            auto tmp = AddNode(return_node, disas, bin);
            while (tmp) {
                tmp = AddNode(tmp, disas, bin);
            }
            logger::Debug("Processing call address now (0x%x)", new_address);
            logger::Debug("target_exists: %s",
                          target_exists ? "true" : "false");
        } break;
        case CFGEdgeType::Ret:
            node->returns = true;
            logger::Debug("Block 0x%x returns", node->block.address);
            for (auto caller : node->callers) {
                logger::Debug("Caller 0x%x", caller->block.address);
                AddEdge(node, caller, type);
            }
            return nullptr;
            break;
        case CFGEdgeType::Int:
        case CFGEdgeType::Invalid:
            return nullptr;
    }

    return (target_exists && new_node_ptr->block.size != 0) ? nullptr
                                                            : new_node_ptr;
}

CFGNode *ControlFlowGraph::MakeFirstNode(disassembler::Disassembly *disas,
                                         BinInfo *bin) {
    auto node = std::make_unique<CFGNode>();
    u64 addr{};
    for (u64 i = 0; i < disas->count; i++) {
        auto instruction = disas->instructions[i];
        addr = instruction.address;
        node->block.address = addr;
        node->block.real_address = addr;
        if (bin->IsCode(addr)) {
            break;
        }
    }

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

    for (const auto &[address, node] : nodes) {
        logger::Debug("Node 0x%x (%d) [%d callers] <- %d; -> %d", address,
                      node->block.size, node->callers.size(),
                      node->in_edges.size(), node->out_edges.size());
        if (!node->callers.empty() && node->in_edges.empty()) {
            logger::Warn(
                "Callers not empty, but not incoming connections. ???");
        }
        for (const auto &caller : node->callers) {
            logger::Debug("\t0x%x", caller->block.address);
        }
        logger::Debug("Incoming edges:");
        for (const auto &edge : node->in_edges) {
            logger::Debug("\t0x%x -> 0x%x (%s)", edge.source->block.address,
                          edge.target->block.address,
                          EdgeTypeStr(edge.type).c_str());
        }
        logger::Debug("Outgoing edges:");
        for (const auto &edge : node->out_edges) {
            logger::Debug("\t0x%x -> 0x%x (%s)", edge.source->block.address,
                          edge.target->block.address,
                          EdgeTypeStr(edge.type).c_str());
        }
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

    return std::move(res);
}

CFGNode::~CFGNode() = default;
}  // namespace core::static_analysis
