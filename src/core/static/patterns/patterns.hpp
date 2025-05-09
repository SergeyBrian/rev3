#ifndef CORE_STATIC_PATTERNS_HPP
#define CORE_STATIC_PATTERNS_HPP

#include "../../target.hpp"

namespace core::static_analysis {
const i64 InvalidImm = static_cast<int64_t>(u64_max);
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
            Call,
        } type;

        struct Insn {
            x86_insn id;
            cs_x86_op left_op{};
            cs_x86_op right_op{};
            cs_x86_op third_op{};
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

        std::string call_func;
    } stmt;
    i64 count;
};

bool MatchPattern(const Target *target, u64 address,
                  std::vector<Pattern> &pattern);
void ScanFunctionPatterns(Target *target);
}  // namespace core::static_analysis

#endif
