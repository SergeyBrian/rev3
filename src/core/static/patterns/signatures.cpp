#include "signatures.hpp"

#include "patterns.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analysis {
#ifdef X86_BUILD
static const i64 WindowsDefaultSecurityCookie = 0x0BB40E64E;
#else
static const i64 WindowsDefaultSecurityCookie = 0x2B992DDFA232;
#endif

static const std::vector<std::pair<std::string, std::vector<Pattern>>>
    signatures{
        {
            "_acrt_iob_func",
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
            "_security_init_cookie",
            {
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = 7,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
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
                                            .type = X86_OP_IMM,
                                            .imm = WindowsDefaultSecurityCookie,
                                        },
                                },
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_MOV,
                                    .left_op =
                                        {
                                            .type = X86_OP_REG,
                                            .reg = X86_REG_ESI,
                                        },
                                    .right_op =
                                        {
                                            .type = X86_OP_IMM,
                                            .imm = 0x0FFFF0000,
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
                            .call_func = "_acrt_iob_func",
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
                            .call_func = "_acrt_iob_func",
                        },
                },
            },
        },
        {
            "_scrt_is_managed_app",
            {
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
                            .call_func = "GetModuleHandleW",
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = -1,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_MOV,
                                    .right_op =
                                        {
                                            .type = X86_OP_IMM,
                                            .imm = 0x5A4D,
                                        },
                                },
                        },
                },
            },
        },
        {
            "_scrt_is_managed_app",
            {
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
                            .call_func = "GetModuleHandleW",
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_MOV,
                                },
                        },
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = -1,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_MOV,
                                    .right_op =
                                        {
                                            .type = X86_OP_IMM,
                                            .imm = 0x5A4D,
                                        },
                                },
                        },
                },
            },
        },

        {
            "_check_cookie",
            {
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Any,
                        },
                    .count = -1,
                },
                {
                    .stmt =
                        {
                            .type = Pattern::Stmt::Type::Insn,
                            .insn =
                                {
                                    .id = X86_INS_CMP,
                                    .left_op =
                                        {
                                            .type = X86_OP_REG,
                                            .reg = X86_REG_ECX,
                                        },
                                    .right_op =
                                        {
                                            .type = X86_OP_MEM,
                                            .imm = WindowsDefaultSecurityCookie,
                                        },
                                },
                        },
                },
            },
        },
    };

static const std::vector<Pattern> main_sig{
    {
        {
            .stmt = {.type = Pattern::Stmt::Type::Any},
            .count = -1,
        },
        {
            .stmt = {.type = Pattern::Stmt::Type::Insn,
                     .insn =
                         {
                             .id = X86_INS_PUSH,
                             .left_op =
                                 {
                                     .type = X86_OP_REG,
                                     .reg = X86_REG_EAX,
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
                                     .type = X86_OP_MEM,
                                     .mem = {.base = X86_REG_EDI},
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
                                     .type = X86_OP_MEM,
                                     .mem = {.base = X86_REG_ESI},
                                 },
                         }},
        },
        {
            .stmt = {.type = Pattern::Stmt::Type::Insn,
                     .insn =
                         {
                             .id = X86_INS_CALL,
                         }},
        },
    },
};

void ScanForKnownFunctionSignatures(Target *target) {
    for (const auto &[name, pattern] : signatures) {
        for (auto [_, func] : target->functions) {
            std::vector<Pattern> tmp = pattern;
            if (MatchPattern(target, func->address, tmp)) {
                logger::Okay("Recognized function %s at 0x%llx", name.c_str(),
                             func->address);
                func->display_name = name;
            }
        }
    }
}
}  // namespace core::static_analysis
