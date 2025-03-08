#include "core.hpp"
#include <iostream>

#include "../utils/logger.hpp"
#include "../config/config.hpp"

#include "../common/pre_checks.hpp"

#include "static/calls/calls.hpp"
#include "target.hpp"
#include "output.hpp"
#include "static/parser/parser.hpp"
#include "static/control/control.hpp"
#include "static/strings/strings.hpp"

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
}  // namespace core

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

        static_analysis::FindStrings(target);
        static_analysis::FindReferences(target);
        static_analysis::FindCallsArgs(target);

        if (config::Get().static_analysis.inspect_address) {
            auto node = target.cfg.FindNode(
                config::Get().static_analysis.inspect_address);
            if (!node) {
                logger::Error("Can't inspect node at 0x%llx",
                              config::Get().static_analysis.inspect_address);
            } else {
                printf("%s=== Inspecting node 0x%llx ===%s\n", COLOR_GREEN,
                       node->block.address, COLOR_RESET);
                if (node->block.address !=
                    config::Get().static_analysis.inspect_address) {
                    logger::Warn(
                        "!! There is no node starting at 0x%llx.\n"
                        "Displaying node containing this address. If you "
                        "expected to see something else, check the requested "
                        "address.",
                        config::Get().static_analysis.inspect_address);
                }
                while (node) {
                    std::cout << target.GetString(node->block.real_address,
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
                        node = target.cfg.FindNode(node->block.next_address);
                        std::cout << "---------------------\n";
                    }
                }
            }
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
            logger::Okay("%d references found", xrefs.size());
        }

        logger::Info("%d paths found", paths.size());

        for (const auto &[t, path] : paths) {
            logger::Info("=== PATH TO 0x%llx ===", t);
            std::cout << std::hex;
            for (const auto &vertex : path) {
                std::cout << "==============================\n";
                std::cout << target.GetString(
                    vertex, target.cfg.FindNode(vertex)->block.size);
            }
            std::cout << "\n\n";
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
}  // namespace core
