#ifndef CORE_STATIC_CONTROL_HPP
#define CORE_STATIC_CONTROL_HPP

#include <vector>
#include <unordered_map>
#include <memory>

#include "../disas/disassembler.hpp"
#include "../../bin.hpp"

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis {
struct BaseBlock {
    u64 address;
    usize size;
};

enum class CFGEdgeType : u8 {
    Invalid,
    Jmp,
    Jcc,
    Call,
    Ret,
    Int,
};

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
};
struct EdgeTemplate {
    u64 from;
    u64 to;
    CFGEdgeType type;
};

struct ControlFlowGraph {
    std::map<u64, std::unique_ptr<CFGNode>> nodes;

    CFGNode *FindNode(u64 address) const;

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

    void AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type);
    CFGNode *AddNode(CFGNode *node, disassembler::Disassembly *disas,
                     BinInfo *bin);
    CFGNode *MakeFirstNode(disassembler::Disassembly *disas, BinInfo *bin);
    CFGNode *InsertFakeNode();
    void MapBaseBlocks(disassembler::Disassembly *disas, BinInfo *bin);
};
}  // namespace core::static_analysis

#endif
