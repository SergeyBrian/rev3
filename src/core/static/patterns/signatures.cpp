#include "signatures.hpp"

#include "patterns.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analysis {
static const std::vector<std::pair<std::string, std::vector<Pattern>>>
    signatures{
        {
            "___acrt_iob_func",
            {
                {
                    .stmt = {.type = Pattern::Stmt::Type::Insn,
                             .insn =
                                 {
                                     .id = X86_INS_MOV,
                                     .left_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_EDI,
                                         },
                                     .right_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_EDI,
                                         },
                                 }},
                },
                {
                    .stmt = {.type = Pattern::Stmt::Type::Insn,
                             .insn =
                                 {
                                     .id = X86_INS_PUSH,
                                     .left_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_EBP,
                                         },
                                 }},
                },
                {
                    .stmt = {.type = Pattern::Stmt::Type::Insn,
                             .insn =
                                 {
                                     .id = X86_INS_MOV,
                                     .left_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_EBP,
                                         },
                                     .right_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_ESP,
                                         },
                                 }},
                },
                {
                    .stmt = {.type = Pattern::Stmt::Type::Insn,
                             .insn =
                                 {
                                     .id = X86_INS_IMUL,
                                     .third_op =
                                         {
                                             .type = X86_OP_IMM,
                                             .imm = 0x38,
                                         },
                                 }},
                },
                {
                    .stmt = {.type = Pattern::Stmt::Type::Insn,
                             .insn =
                                 {
                                     .id = X86_INS_ADD,
                                     .left_op =
                                         {
                                             .type = X86_OP_REG,
                                             .reg = X86_REG_EAX,
                                         },
                                 }},
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_POP,
                                    .left_op =
                                        {
                                            .type = X86_OP_REG,
                                            .reg = X86_REG_EBP,
                                        },
                                },
                        },
                },
            },

        },
        {
            "printf",
            {
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = 10,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_PUSH,
                                    .left_op =
                                        {
                                            .type = X86_OP_IMM,
                                            .imm = 0x1,
                                        },
                                },
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Call,
                            .call_func = "___acrt_iob_func",
                        },
                },
            },
        },
        {
            "scanf",
            {
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = 10,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_PUSH,
                                    .left_op =
                                        {
                                            .type = X86_OP_IMM,
                                            .imm = 0x0,
                                        },
                                },
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Call,
                            .call_func = "___acrt_iob_func",
                        },
                },
            },
        },
    };

void ScanForKnownFunctionSignatures(Target *target) {
    for (const auto &[name, pattern] : signatures) {
        for (auto [_, func] : target->functions) {
            std::vector<Pattern> tmp = pattern;
            if (MatchPattern(target, func, tmp)) {
                logger::Okay("Recognized function %s at 0x%llx", name.c_str(),
                             func->address);
                func->display_name = name;
            }
        }
    }
}
}  // namespace core::static_analysis
