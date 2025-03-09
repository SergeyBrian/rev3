#ifndef CORE_STATIC_PATTERNS_HPP
#define CORE_STATIC_PATTERNS_HPP

#include "../../target.hpp"

namespace core::static_analysis {
struct Pattern {
    enum class Type : u8 {
        Equal,
        NotEqual,
        LessThan,
        MoreThan,
    } type;

    struct Stmt {
        enum class Type : u8 {
            Any,
            Insn,
            Jump,
        } type;

        struct Insn {
            x86_insn id;
            cs_x86_op left_op{};
            cs_x86_op right_op{};
        } insn{};

        struct Jump {
            enum class Type : u8 {
                Equal,
                Before,
                After,
            } type;

            enum class Relative : u8 {
                ToSelf,
                ToStmt,
                Absolute,
            } relative;

            u64 address;
        } jump{};

        u64 satisfied_by{};
    } stmt;
    i64 count;
};

bool MatchPattern(const Target *target, const Function *function,
                  std::vector<Pattern> &pattern);
void ScanFunctionPatterns(Target *target);
}  // namespace core::static_analysis

#endif
