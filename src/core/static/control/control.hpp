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

enum class Flag : u8 {
    ZF = 0x1,
    SF = 0x1 << 1,
    OF = 0x1 << 2,
    CF = 0x1 << 3,
    PF = 0x1 << 4,
    AF = 0x1 << 5,
};

constexpr Flag operator|(Flag lhs, Flag rhs) {
    return static_cast<Flag>(static_cast<u8>(lhs) | static_cast<u8>(rhs));
}

constexpr Flag operator&(Flag lhs, Flag rhs) {
    return static_cast<Flag>(static_cast<u8>(lhs) & static_cast<u8>(rhs));
}

constexpr Flag operator^(Flag lhs, Flag rhs) {
    return static_cast<Flag>(static_cast<u8>(lhs) ^ static_cast<u8>(rhs));
}

constexpr Flag operator~(Flag flag) {
    return static_cast<Flag>(~static_cast<u8>(flag));
}

inline Flag &operator|=(Flag &lhs, Flag rhs) {
    lhs = lhs | rhs;
    return lhs;
}

inline Flag &operator&=(Flag &lhs, Flag rhs) {
    lhs = lhs & rhs;
    return lhs;
}

inline Flag &operator^=(Flag &lhs, Flag rhs) {
    lhs = lhs ^ rhs;
    return lhs;
}

enum class Operator : u8 {
    Invalid,
    Equal,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    NotEqual,
};

using Register = x86_reg;
struct Operand {
    enum class Type : u8 { Register, Constant, Mem };
    Type type{};
    Register reg{};
    u64 constant{};
    u64 mem_address{};

    Operand() = default;
    Operand(Register reg) : type(Type::Register), reg(reg){};
    Operand(u64 constant) : type(Type::Constant), constant(constant){};
};

struct RegCmpCondition {
    Operand lhs;
    Operand rhs;
    Operator op;
};

struct Condition {
    // The Flag type is only used when analyzer was unable to find a register
    // comparison operation, which should never happen when analyzing normal
    // code
    enum class Type : u8 { Flag, RegCmp };
    Type type{};
    bool inverted{};

    // Addresses of instructions affecting condition
    u64 affected_by_instr[2]{};

    // Specifies, which flags participate in condition
    Flag flags;
    RegCmpCondition reg_cmp{};
};

std::string EdgeTypeStr(CFGEdgeType type);

struct CFGNode;

struct CFGEdge {
    CFGEdgeType type;
    CFGNode *target;
    CFGNode *source;

    Condition condition;
};

struct CFGNode {
    BaseBlock block{};
    std::string label;

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
              const std::vector<u64> &targets = {},
              const std::vector<std::string> labels = {});

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

    void AddEdge(CFGNode *from, CFGNode *to, CFGEdgeType type,
                 Condition condition = {});
    CFGNode *AddNode(CFGNode *node, disassembler::Disassembly *disas,
                     BinInfo *bin);
    CFGNode *MakeFirstNode(disassembler::Disassembly *disas, BinInfo *bin);
    CFGNode *InsertFakeNode(u64 real_address);
    CFGNode *InsertNode(u64 address);
    void MapBaseBlocks(disassembler::Disassembly *disas, BinInfo *bin);
};
}  // namespace core::static_analysis

#endif
