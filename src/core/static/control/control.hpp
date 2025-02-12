#ifndef CORE_STATIC_CONTROL_HPP
#define CORE_STATIC_CONTROL_HPP

#include <vector>
#include <memory>

#include "../disas/disassembler.hpp"
#include "../../bin.hpp"

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis {
struct BaseBlock {
    u64 address;
    u64 real_address;
    usize size{};
};

enum class CFGEdgeType : u8 {
    Invalid,
    Jmp,
    Jcc,
    Call,
    Ret,
    Int,
};

std::string EdgeTypeStr(CFGEdgeType type);

struct CFGNode;

struct CFGEdge {
    CFGEdgeType type;
    CFGNode *target;
    CFGNode *source;
};

struct CFGNode {
    BaseBlock block{};

    std::vector<CFGEdge> out_edges;
    std::vector<CFGEdge> in_edges;
    std::vector<CFGNode *> callers;

    bool returns{};

    ~CFGNode();
};
struct EdgeTemplate {
    u64 from;
    u64 to;
    CFGEdgeType type;
};

struct ControlFlowGraph {
    std::map<u64, std::unique_ptr<CFGNode>> nodes;

    CFGNode *FindNode(u64 address) const;

    CFGNode *FindNodeContaining(u64 address) const;

    ControlFlowGraph();

    Err Build(disassembler::Disassembly *disas, BinInfo *bin,
              const std::vector<u64> &targets);

    ControlFlowGraph(const ControlFlowGraph &) = delete;
    ControlFlowGraph &operator=(const ControlFlowGraph &) = delete;

    ControlFlowGraph(ControlFlowGraph &&) noexcept = default;
    ControlFlowGraph &operator=(ControlFlowGraph &&) noexcept = default;

    static std::unique_ptr<ControlFlowGraph> MakeCFG(
        std::vector<core::static_analysis::BaseBlock> blocks,
        std::vector<EdgeTemplate> edges);

private:
    u64 fake_node_counter = 0x1000 - 1;
    std::map<u64, u64> fake_nodes;

    void AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type);
    CFGNode *AddNode(CFGNode *node, disassembler::Disassembly *disas,
                     BinInfo *bin);
    CFGNode *MakeFirstNode(disassembler::Disassembly *disas, BinInfo *bin);
    CFGNode *InsertFakeNode(u64 real_address);
    CFGNode *InsertNode(u64 address);
    void MapBaseBlocks(disassembler::Disassembly *disas, BinInfo *bin);
};
}  // namespace core::static_analysis

#endif
