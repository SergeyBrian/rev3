#include "strings.hpp"

#include <vector>

#include "../../static/patterns/patterns.hpp"

#include "../../../utils/logger.hpp"
#include "../../../utils/utils.hpp"

using core::static_analysis::Pattern;

namespace core::dynamic {
void DecryptStrings(Target *target) {
    logger::Debug("Trying to decrypt strings");
    std::map<Function *, std::vector<Xref *>> potential_decrypt_calls;
    for (const auto &[_, func] : target->functions) {
        for (auto &[_, xref] : func->xrefs) {
            for (auto &arg : xref.args) {
                if (arg.type == Reference::Type::String) {
                    potential_decrypt_calls[func].push_back(&xref);
                    break;
                }
            }
        }
    }

    logger::Debug("Decryption call candidates:");

    std::vector<Function *> matched_funcs;
    std::map<Function *, u64> xor_addresses;
    for (const auto &[func, _] : potential_decrypt_calls) {
        std::vector<static_analysis::Pattern> pattern = {
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
                                .id = X86_INS_XOR,
                                .right_op =
                                    {
                                        .type = X86_OP_IMM,
                                        .imm = static_analysis::InvalidImm,
                                    },
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
                        .type = Pattern::Stmt::Type::Jump,
                        .jump =
                            {
                                .type = Pattern::Stmt::Jump::Type::Before,
                                .relative =
                                    Pattern::Stmt::Jump::Relative::ToStmt,
                                .address = 1,
                            },
                    },
            }};

        if (static_analysis::MatchPattern(target, func->address, pattern)) {
            matched_funcs.push_back(func);
            xor_addresses[func] = pattern.at(1).stmt.satisfied_by;
            func->display_name += "_decryption";
        }
    }

    for (auto it = potential_decrypt_calls.begin();
         it != potential_decrypt_calls.end();) {
        if (!utils::contains(matched_funcs, it->first)) {
            it = potential_decrypt_calls.erase(it);
        } else {
            it++;
        }
    }

    for (const auto &[func, calls] : potential_decrypt_calls) {
        u64 key = target->disassembly.instr_map.at(xor_addresses.at(func))
                      ->detail->x86.operands[1]
                      .imm;
        logger::Debug("%s", func->display_name.c_str());
        logger::Okay(
            "Function %s satisfied the decrypt pattern! (found key: 0x%llx)",
            func->display_name.c_str(), key);
        for (const auto &call : calls) {
            for (auto &arg : call->args) {
                if (arg.type != Reference::Type::String) continue;
                for (char &c : target->strings_map[arg.address]) {
                    c ^= key;
                }
            }
            std::cout << target->GetString(call->address);
        }
    }
}
}  // namespace core::dynamic
