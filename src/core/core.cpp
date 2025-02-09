#include "core.hpp"
#include <iostream>

#include "../utils/logger.hpp"
#include "../config/config.hpp"

#include "../common/pre_checks.hpp"

#include "target.hpp"
#include "output.hpp"
#include "static/parser/parser.hpp"
#include "static/control/control.hpp"

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
                entry.xrefs.push_back(xref);
            }
        }
    }

    return err;
}

Err DoIATXrefsSearch(Target &target) {
    Err err{};

    logger::Debug("Performing IAT xrefs search");
    std::vector<u64> calls{};

    for (u64 i = 1; i < target.disassembly.count; i++) {
        auto prev_instr = target.disassembly.instructions[i - 1];
        auto instr = target.disassembly.instructions[i];
        u64 offset = (i >= 4) ? i - 4 : 0;

        if ((!strcmp(prev_instr.mnemonic, "lea") ||
             !strcmp(prev_instr.mnemonic, "mov")) &&
            !strcmp(instr.mnemonic, "call") && strstr(instr.op_str, "qword") &&
            strstr(instr.op_str, "[rip")) {
            calls.push_back(i);

            logger::Okay("[%d] Found call at 0x%x", i, instr.address);
            logger::log << "Context: \n";
            static_analysis::disassembler::Print(
                &target.disassembly.instructions[offset], 5);
        }
    }

    logger::Debug("Searching through %d calls", calls.size());
    u64 idx = 0;
    for (auto i : calls) {
        idx++;
        auto mov_instr = target.disassembly.instructions[i - 1];
        auto call_instr = target.disassembly.instructions[i];

        if ((call_instr.address & 0xfffff) ==
                config::Get().static_analysis.inspect_address ||
            (mov_instr.address & 0xfffff) ==
                config::Get().static_analysis.inspect_address) {
            logger::Okay("[%d/%d]: 0x%x", idx, calls.size(), mov_instr.address);
        } else {
            logger::Debug("[%d/%d]: 0x%x", idx, calls.size(),
                          mov_instr.address);
        }

        logger::log << "Context: \n" << COLOR_GRAY;
        for (u64 i = 0; i < 8; i++) {
            logger::log << "" << std::hex << std::uppercase << std::setfill('0')
                        << std::setw(2) << static_cast<int>(mov_instr.bytes[i])
                        << " ";
        }
        logger::log << "\t" << mov_instr.mnemonic << " " << mov_instr.op_str;
        logger::log << "\n";
        for (u64 i = 0; i < 8; i++) {
            logger::log << "" << std::hex << std::uppercase << std::setfill('0')
                        << std::setw(2) << static_cast<int>(call_instr.bytes[i])
                        << " ";
        }
        logger::log << "\t" << call_instr.mnemonic << " " << call_instr.op_str;
        logger::log << "\n" << COLOR_RESET;

        i64 offset =
            static_analysis::disassembler::ParseOffsetPtr(call_instr.op_str);
        logger::Debug("ParseOffsetPtr: 0x%x", offset);
        u64 call_addr = call_instr.address + call_instr.size + offset;
        logger::Debug("Target address: 0x%x", call_addr);
        if (!target.bin_info->AddressInSection(call_addr, ".rdata")) {
            continue;
        }
        for (auto &[_, funcs] : target.imports) {
            for (auto &func : funcs) {
                for (const auto &xref : func.xrefs) {
                    if (xref == call_addr) {
                        func.xrefs.push_back(call_instr.address);
                        logger::Okay(
                            "Found call to %s at 0x%x",
                            func.display_name.c_str(),
                            call_instr.address + target.bin_info->ImageBase());
                    }
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
        static_analysis::parser::ParseBinary(target);
        if (config::Get().static_analysis.do_imports_print) {
            output::PrintImports(target);
        }
        Err err = AnalyzeImports(target);
        if (err != Err::Ok) {
            logger::Error("Imports analysis failed for `%s`",
                          target.display_name.c_str());
            continue;
        }
        auto text =
            target.bin_info->Data(target.text.address, target.text.size);

        err = target.disassembly.Disassemble(text, target.text.size);
        if (err != Err::Ok) {
            logger::Error(".text disassembly failed for `%s`",
                          target.display_name.c_str());
            continue;
        }
        err = DoXrefsSearch(target);
        if (err != Err::Ok) {
            logger::Error("Xrefs search failed for `%s`",
                          target.display_name.c_str());
            continue;
        }

        std::vector<u64> cf_targets{};
        for (const auto &[_, funcs] : target.imports) {
            for (const auto &func : funcs) {
                if (!config::Get().static_analysis.sink_target.empty() &&
                    config::Get().static_analysis.sink_target !=
                        func.display_name) {
                    continue;
                }
                bool found = false;
                for (const auto xref : func.xrefs) {
                    if (!target.bin_info->AddressInSection(xref, ".text"))
                        continue;
                    found = true;
                }
                if (!found) {
                    logger::Warn("Skipping `%s`. No direct references found");
                    continue;
                }
                cf_targets.push_back(func.address);
            }
        }

        err = target.cfg.Build(&target.disassembly, target.bin_info.get(),
                               cf_targets);
        if (err != Err::Ok) {
            logger::Error("Static control flow analysis failed for `%s`",
                          target.display_name.c_str());
            continue;
        }
    }
    logger::Okay("All done. Closing");
}
}  // namespace core
