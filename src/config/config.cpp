#include "config.hpp"

#include <iostream>
#include <vector>
#include <cxxopts.hpp>
#include <filesystem>

#include "../utils/logger.hpp"

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
        config.verbose_logs = result["verbose"].as<bool>();
        config.static_analysis.do_sink_search =
            result["sink-search"].as<bool>();
        config.static_analysis.do_imports_print =
            result["imports"].as<bool>();

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
