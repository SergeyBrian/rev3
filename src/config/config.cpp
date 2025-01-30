#include "config.hpp"

#include <iostream>
#include <vector>
#include <cxxopts.hpp>
#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "../utils/logger.hpp"
#include "../utils/system.hpp"
#include "../utils/errors.hpp"
#include "../utils/utils.hpp"

using json = nlohmann::json;

#ifndef NDEBUG
#define DEFAULT_VERBOSITY "true"
#else
#define DEFAULT_VERBOSITY "false"
#endif

namespace config {

Config &Get() {
    static Config instance;
    return instance;
}

Err LoadInterestingFunctions(const std::string &filename, Config &config) {
    Err err{};
    logger::Debug("Loading interesting imports config");
    std::ifstream in(filename);
    if (!in.is_open()) {
        return Err::FileNotFound;
    }

    json data;
    try {
        in >> data;
    } catch (const std::exception &e) {
        logger::Error("%s", e.what());
        return Err::InvalidConfigFormat;
    }

    if (!data.contains("interesting_imports") ||
        !data["interesting_imports"].is_array()) {
        logger::Error("`interesting_imports` array not found in %s",
                      filename.c_str());
        return Err::InvalidConfigFormat;
    }

    logger::Debug("Found %d interesting imports",
                  data["interesting_imports"].size());
    for (const auto &obj : data["interesting_imports"]) {
        if (!config.static_analysis.active_categories.empty() && !utils::contains(config.static_analysis.active_categories,
                             std::string(obj["category"]))) {
            continue;
        }

        core::InterestingFunction func{};
        func.name = obj["name"];
        func.lib_name = obj["lib_name"];
        func.category = obj["category"];

        std::string interest_type = obj["interest_type"];

        if (interest_type == "source") {
            func.interest_type = core::InterestType::Source;
        } else if (interest_type == "sink") {
            func.interest_type = core::InterestType::Sink;
        } else if (interest_type == "masking") {
            func.interest_type = core::InterestType::Masking;
        } else {
            logger::Error("Can't use `%s` as interest_type",
                          interest_type.c_str());
            return Err::UnknownConfigOption;
        }
        config.static_analysis.interesting_functions.push_back(func);
    }
    logger::Okay("Loaded %d interesting imports",
                 config.static_analysis.interesting_functions.size());

    return err;
}

void InitFromArgs(int argc, char **argv) {
    Config &config = Get();

    if (config.initialized) {
        return;
    }

    cxxopts::Options options("rev3", "Executable analyzer");

    // clang-format off
    options.add_options()
        ("files", "Input files to analyze", cxxopts::value<std::vector<std::string>>())
        ("h,help", "Print usage")
        ("v,verbose", "Enable verbose output", cxxopts::value<bool>()->default_value(DEFAULT_VERBOSITY))
        ("s,sink-search", "Search for potential sinks", cxxopts::value<bool>()->default_value("false"))
        ("i,imports", "Print imports table", cxxopts::value<bool>()->default_value("false"))
        ("interests-file", "Specify path to .json file with list of interesting symbols", cxxopts::value<std::string>()->default_value(utils::GetDefaultPath() + "\\interesting_imports.json"))
        ("c,categories",
         "Specify active interest categories (comma-separated, available values: "
         "privilege, services, crypto, process, gui, network, system, "
         "configuration, antianalysis, ipc, misc, user_input)",
         cxxopts::value<std::vector<std::string>>())
    ;
    // clang-format on

    options.positional_help("<input files...>");
    options.parse_positional({"files"});

    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (result.count("files")) {
            auto files = result["files"].as<std::vector<std::string>>();
            for (const auto &file : files) {
                std::filesystem::path relative_path(file);
                auto full_path = std::filesystem::absolute(relative_path);
                config.input_files.push_back(full_path.string());
            }
        }

        if (result.count("categories")) {
            config.static_analysis.active_categories =
                result["categories"].as<std::vector<std::string>>();
        }

        config.verbose_logs = result["verbose"].as<bool>();
        config.static_analysis.do_sink_search =
            result["sink-search"].as<bool>();
        config.static_analysis.do_imports_print = result["imports"].as<bool>();

        Err err = LoadInterestingFunctions(
            result["interests-file"].as<std::string>(), config);
        if (err != Err::Ok) {
            logger::Error("Load of interests file failed");
            logger::Error(ErrorText[static_cast<int>(err)]);
            exit(static_cast<int>(err));
        }

        config.initialized = true;
        logger::Debug("Input files:");
        for (const auto &file : config.input_files) {
            logger::Debug("%s", file.c_str());
        }
        logger::Debug("Do sink search: %s",
                      config.static_analysis.do_sink_search ? "true" : "false");

    } catch (const cxxopts::exceptions::parsing &e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << "Use -h to view available options\n";
        exit(1);
    }
}
}  // namespace config
