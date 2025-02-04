#include "core.hpp"

#include "../utils/logger.hpp"
#include "../config/config.hpp"

#include "../common/pre_checks.hpp"

#include "target.hpp"
#include "static/parser/parser.hpp"
#include "output.hpp"

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

    logger::Info("Analyzing imports");
    logger::Info("Searching for xrefs: Step 1");

    for (auto &[_, entries] : target.imports) {
        for (auto &entry : entries) {
            auto xrefs =
                static_analysis::parser::FindImportsXrefs(target.lief_bin.get(), entry.address, &err);
            if (err != Err::Ok) {
                logger::Warn("Error searching for static xrefs to `%s`",
                             entry.display_name.c_str());
                continue;
            }

            for (const auto &xref : xrefs) {
                entry.xrefs.push_back(xref);
            }
        }
    }

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
    }
}
}  // namespace core
