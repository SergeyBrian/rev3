#include "core.hpp"

#include <iostream>
#include <sstream>

#include "../utils/logger.hpp"
#include "../config/config.hpp"

#include "../common/pre_checks.hpp"

#include "static/calls/calls.hpp"
#include "target.hpp"
#include "output.hpp"
#include "static/parser/parser.hpp"
#include "static/control/control.hpp"
#include "static/strings/strings.hpp"
#include "static/patterns/signatures.hpp"
#include "dynamic/strings/strings.hpp"

namespace core {
static std::vector<Target> targets{};

Err Init() {
    logger::Debug("Initializing targets...");
    auto filenames = config::Get().input_files;
    Err err{};

    for (const auto &filename : filenames) {
        err = pre_checks::FileExists(filename.c_str());
        if (err != Err::Ok) {
            return err;
        }

        targets.emplace_back(filename);
        logger::Okay("Found target '%s'", filename.c_str());
    }

    return err;
}

const Function *SelectTargetFunction(Target &target, Tag filter) {
    logger::Info("Choose one of sink functions below:");
    u64 func_idx{};
    std::vector<const Function *> active_funcs{};
    for (const auto &[_, funcs] : target.imports) {
        for (const auto &func : funcs) {
            if (func.tags & static_cast<u8>(filter)) {
                logger::Info("%d:\t%s", ++func_idx, func.display_name.c_str());
                active_funcs.push_back(&func);
            }
        }
    }

    if (filter != Tag::Any) {
        std::cout << "If your function of interest is not in list, type in 0 "
                     "to view full list\n";
    }
    std::cout << "Enter number 1-" << func_idx << ": ";
    std::cin >> func_idx;
    if (func_idx == 0) {
        return SelectTargetFunction(target, Tag::Any);
    }

    if (func_idx > active_funcs.size()) {
        logger::Error("Option not found, please select valid option");
        return SelectTargetFunction(target, filter);
    }

    func_idx -= 1;

    logger::Okay("You have selected target function `%s`",
                 active_funcs[func_idx]->display_name.c_str());
    return active_funcs[func_idx];
}

Err AnalyzeImports(Target &target) {
    Err err{};

    logger::Debug("Mapping IAT to .rdata");

    for (auto &[_, entries] : target.imports) {
        for (auto &entry : entries) {
            logger::Debug("%s", entry.display_name.c_str());
            auto xrefs = target.bin_info->FindImportsXrefs(entry.address, &err);
            if (err != Err::Ok) {
                logger::Warn("Error searching for static xrefs to `%s`",
                             entry.display_name.c_str());
                continue;
            }

            for (const auto xref : xrefs) {
                entry.xrefs[xref] = {
                    .address = xref,
                    .args = {},
                };
            }
        }
    }

    return err;
}

Err DoIATXrefsSearch(Target &target) {
    Err err{};

    logger::Debug("Performing IAT xrefs search");
    std::vector<u64> calls{};

    u64 i = 1;
    auto prev_instr_it = target.disassembly.instr_map.begin();
    auto [_, prev_instr] = *prev_instr_it;
    for (const auto &[addr, instr] : target.disassembly.instr_map) {
        u64 offset = (i >= 4) ? i - 4 : 0;

        if (strstr(instr->mnemonic, "call"))
            logger::Debug("+ call %s %s", instr->mnemonic, instr->op_str);
        if (((!strcmp(prev_instr->mnemonic, "lea") ||
              !strcmp(prev_instr->mnemonic, "mov")) &&
             (instr->id == X86_INS_CALL || instr->id == X86_INS_LCALL) &&
             strstr(instr->op_str, "qword") &&
             (strstr(instr->op_str, "[rip") ||
              strstr(instr->op_str, "[eip"))) ||
            ((instr->id == X86_INS_CALL || instr->id == X86_INS_LCALL) &&
             instr->detail->x86.operands[0].type == X86_OP_IMM) ||
            ((instr->id == X86_INS_CALL || instr->id == X86_INS_LCALL) &&
             instr->detail->x86.operands[0].type == X86_OP_MEM)) {
            calls.push_back(instr->address);

            logger::Okay("[%d] Found call at 0x%llx", i, instr->address);
            logger::log << "Context: \n";
            target.disassembly.Print(instr->address - offset, 5);
        }
        prev_instr = instr;
    }

    logger::Debug("Searching through %d calls", calls.size());
    u64 idx = 0;
    for (auto i : calls) {
        idx++;
        auto [_, mov_instr] = *target.disassembly.instr_map.lower_bound(i - 1);
        auto call_instr = target.disassembly.instr_map[i];
        u64 call_addr{};

        if (call_instr->detail->x86.operands[0].type == X86_OP_IMM) {
            logger::Debug("immediate call found");
            call_addr = call_instr->detail->x86.operands[0].imm;
        } else if (call_instr->detail->x86.operands[0].type == X86_OP_MEM) {
            logger::Debug("call to data degment found");
            call_addr =
                static_analysis::disassembler::SolveMemAddress(call_instr);
            logger::Debug("addr value: 0x%llx", call_addr);
        } else {
            if ((call_instr->address & 0xfffff) ==
                    config::Get().static_analysis.inspect_address ||
                (mov_instr->address & 0xfffff) ==
                    config::Get().static_analysis.inspect_address) {
                logger::Okay("[%d/%d]: 0x%llx", idx, calls.size(),
                             mov_instr->address);
            } else {
                logger::Debug("[%d/%d]: 0x%llx", idx, calls.size(),
                              mov_instr->address);
            }

            logger::log << "Context: \n" << COLOR_GRAY;
            for (u64 i = 0; i < 8; i++) {
                logger::log << "" << std::hex << std::uppercase
                            << std::setfill('0') << std::setw(2)
                            << static_cast<int>(mov_instr->bytes[i]) << " ";
            }
            logger::log << "\t" << mov_instr->mnemonic << " "
                        << mov_instr->op_str;
            logger::log << "\n";
            for (u64 i = 0; i < 8; i++) {
                logger::log << "" << std::hex << std::uppercase
                            << std::setfill('0') << std::setw(2)
                            << static_cast<int>(call_instr->bytes[i]) << " ";
            }
            logger::log << "\t" << call_instr->mnemonic << " "
                        << call_instr->op_str;
            logger::log << "\n" << COLOR_RESET;

            i64 offset = static_analysis::disassembler::ParseOffsetPtr(
                call_instr->op_str);
            logger::Debug("ParseOffsetPtr: 0x%llx", offset);
            call_addr = call_instr->address + call_instr->size + offset;
        }
        logger::Debug("Target address: 0x%llx", call_addr);
        for (auto &[_, funcs] : target.imports) {
            for (auto &func : funcs) {
                if (func.xrefs.contains(call_addr) ||
                    func.xrefs.contains(call_addr -
                                        target.bin_info->ImageBase())) {
                    func.xrefs[call_instr->address] = {
                        .address = call_instr->address,
                        .args = {},
                    };
                    logger::Okay(
                        "Found call to %s at 0x%llx", func.display_name.c_str(),
                        call_instr->address + target.bin_info->ImageBase());
                }
            }
        }
    }

    return err;
}

void FindInternalFunctions(Target &target) {
    auto prev_instr_it = target.disassembly.instr_map.begin();
    auto [_, prev_instr] = *prev_instr_it;
    std::map<u64, u64> tmp_refs;
    for (const auto &[addr, instr] : target.disassembly.instr_map) {
        if (instr->id == X86_INS_CALL) {
            if (instr->detail->x86.operands[0].type == X86_OP_IMM) {
                u64 call_addr = instr->detail->x86.operands[0].imm;
                tmp_refs[addr] = call_addr;
            }
        } else if (instr->id == X86_INS_MOV && prev_instr->id == X86_INS_PUSH) {
            auto mov_ops = instr->detail->x86.operands;
            auto push_ops = prev_instr->detail->x86.operands;
            if (push_ops[0].reg == X86_REG_EBP &&
                (mov_ops[0].reg == X86_REG_EBP &&
                 mov_ops[1].reg == X86_REG_ESP)) {
                u64 func_addr = prev_instr->address;
                // Processing case when MSVC inserts a 2-byte nop before prolog
                if (target.disassembly.instr_map.contains(func_addr - 2)) {
                    const auto nop_instr =
                        target.disassembly.instr_map.at(func_addr - 2);
                    auto nop_ops = nop_instr->detail->x86.operands;
                    if (nop_instr->id == X86_INS_MOV &&
                        nop_ops[0].reg == nop_ops[1].reg) {
                        func_addr = nop_instr->address;
                    }
                }
                if (!target.functions.contains(func_addr)) {
                    auto func = new Function();
                    func->address = func_addr;
                    func->display_name =
                        (std::ostringstream()
                         << "sub_" << std::hex << func->address)
                            .str();
                    target.functions[func_addr] = func;
                }
            }
        }

        prev_instr = instr;
    }

    for (const auto &[ref_addr, call_addr] : tmp_refs) {
        if (target.functions.contains(call_addr)) {
            logger::Okay("Insert ref 0x%llx -> 0x%llx", ref_addr, call_addr);
            target.functions.at(call_addr)->xrefs[ref_addr] = {
                .address = ref_addr,
            };
        }
    }
}

Err DoXrefsSearch(Target &target) {
    Err err{};

    err = DoIATXrefsSearch(target);

    return err;
}

void Run() {
    if (targets.empty()) {
        logger::Error("No targets loaded");
        return;
    }

    for (auto &target : targets) {
        Err err = static_analysis::parser::ParseBinary(target);
        if (err != Err::Ok) {
            logger::Error("Parser failed for `%s`",
                          target.display_name.c_str());
            continue;
        }

        logger::Debug("Virtual entrypoint: 0x%llx",
                      target.bin_info->EntryPoint());

        if (config::Get().static_analysis.do_imports_print) {
            output::PrintImports(target);
            if (config::Get().verbose_logs) {
                continue;
            }
        }
        err = AnalyzeImports(target);
        if (err != Err::Ok) {
            logger::Error("Imports analysis failed for `%s`",
                          target.display_name.c_str());
            continue;
        }
        auto text =
            target.bin_info->Data(target.text.address, target.text.size);

        err = target.disassembly.Disassemble(text, target.text.size,
                                             target.bin_info.get());
        if (err != Err::Ok) {
            logger::Error(".text disassembly failed for `%s`",
                          target.display_name.c_str());
            continue;
        }
        target.disassembly.PrintCoverage(target.text.size);

        err = DoXrefsSearch(target);
        if (err != Err::Ok) {
            logger::Error("Xrefs search failed for `%s`",
                          target.display_name.c_str());
            continue;
        }

        std::vector<u64> cf_targets{};
        std::vector<std::string> cf_target_labels{};

        for (const auto &[_, funcs] : target.imports) {
            for (const auto &func : funcs) {
                if (!config::Get().static_analysis.sink_target.empty() &&
                    config::Get().static_analysis.sink_target !=
                        func.display_name) {
                    continue;
                }
                bool found = false;
                for (const auto &[xref_address, _] : func.xrefs) {
                    if (!target.bin_info->AddressInSection(xref_address,
                                                           ".text"))
                        continue;
                    found = true;
                    cf_targets.push_back(xref_address);
                    cf_target_labels.push_back(func.display_name);
                    logger::Debug("Reference in .text: 0x%llx", xref_address);
                }
                if (!found) {
                    logger::Warn("Skipping `%s`. No direct references found",
                                 func.display_name.c_str());
                    continue;
                } else {
                    logger::Okay("Adding `%s`", func.display_name.c_str());
                }
            }
        }

        err = target.cfg.Build(&target.disassembly, target.bin_info.get(),
                               cf_targets, cf_target_labels);
        if (err != Err::Ok) {
            logger::Error("Static control flow analysis failed for `%s`",
                          target.display_name.c_str());
            continue;
        }

        if (target.cfg.nodes.size() <= 1) {
            logger::Error(
                "Something went wrong during build of control flow graph");
        }
        target.MapFunctions();

        FindInternalFunctions(target);
        static_analysis::ScanForKnownFunctionSignatures(&target);

        static_analysis::FindStrings(target);
        static_analysis::FindReferences(target);
        static_analysis::FindCallsArgs(target);
        dynamic::DecryptStrings(&target);

        if (config::Get().static_analysis.inspect_address) {
            Inspect(&target, config::Get().static_analysis.inspect_address);
        }

        const Function *func{};
        if (config::Get().static_analysis.sink_target.empty()) {
            func = SelectTargetFunction(target, Tag::Sink);
        } else {
            for (const auto &[_, funcs] : target.imports) {
                for (const auto &f : funcs) {
                    if (f.display_name ==
                        config::Get().static_analysis.sink_target) {
                        func = &f;
                        goto outer_break;
                    }
                }
            }
        }
outer_break:

        if (!func) {
            logger::Error("Invalid target function selected: `%s`",
                          config::Get().static_analysis.sink_target.c_str());
            return;
        } else {
            logger::Okay("Active target function: `%s`",
                         func->display_name.c_str());
        }

        std::map<u64, std::vector<u64>> paths;
        auto xrefs = target.cfg.FindXrefs(func->display_name);
        if (xrefs.size() == 0) {
            logger::Error("No references found");
        } else {
            logger::Info("%d references found", xrefs.size());
        }

        for (const auto &xref : xrefs) {
            std::cout << target.GetNodeString(xref);
            std::cout << "-----------------\n";
        }

        xrefs = target.cfg.FindXrefs("ReadFile");
        if (xrefs.size() == 0) {
            logger::Error("No references found");
        } else {
            logger::Info("%d references found", xrefs.size());
        }

        for (const auto &xref : xrefs) {
            std::cout << target.GetNodeString(xref);
            std::cout << "-----------------\n";
        }
    }
    logger::Okay("All done. Closing");
}

Target *GetActiveTarget() {
    for (auto &target : targets) {
        if (target.bin_info != 0) {
            return &target;
        }
    }

    return nullptr;
}

void Inspect(const Target *target, u64 address) {
    auto node = target->cfg.FindNode(address);
    if (!node) {
        node = target->cfg.FindNodeContaining(address);
    }
    if (!node) {
        logger::Error("Can't inspect node at 0x%llx", address);
        if (target->disassembly.instr_map.contains(address)) {
            logger::Warn(
                "Given address is not included in any node of control flow "
                "graph, but is disassembled.\nThis indicates that there is no "
                "direct calls to this address.\nYou can view disassembly by "
                "executing the `ia <address>` command");
        }
    } else {
        printf("%s=== Inspecting node 0x%llx ===%s\n", COLOR_GREEN,
               node->block.address, COLOR_RESET);
        if (node->block.address != address) {
            logger::Warn(
                "There is no node starting at 0x%llx.\n"
                "Displaying node containing this address. If you "
                "expected to see something else, check the requested "
                "address.",
                address);
        }
        std::set<u64> visited;
        while (node) {
            if (visited.contains(node->block.address)) {
                logger::Warn("Loop found");
                break;
            }
            visited.insert(node->block.address);
            std::cout << target->GetString(node->block.real_address,
                                           node->block.size);
            if (node->out_edges.empty()) break;
            if (node->out_edges.begin()->type ==
                static_analysis::CFGEdgeType::Ret) {
                std::cout << "<<<<<<<<<<<<<<<<<<<<<\n";
                break;
            } else if (node->out_edges.begin()->type ==
                       static_analysis::CFGEdgeType::Jmp) {
                node = node->out_edges.begin()->target;
                std::cout << ">>>>>>>>>>>>>>>>>>>>>\n";
            } else {
                node = target->cfg.FindNode(node->block.next_address);
                std::cout << "---------------------\n";
            }
        }
    }
}

void Info(const Target *target) {
    printf("Image base: 0x%llx\n", target->bin_info->ImageBase());
    printf("Sections:\n");
    for (const auto &section : target->sections) {
        printf("\t%s: 0x%llx\n", section.name.c_str(), section.address);
    }
    printf("Entrypoint: 0x%llx\n", target->bin_info->EntryPoint());
}

void Solve(const Target *target, u64 address) {
    std::vector<static_analysis::CFGNode *> path =
        target->cfg.FindPath(target->bin_info->EntryPoint(), address);
}
}  // namespace core
