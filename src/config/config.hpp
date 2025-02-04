#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <vector>
#include <string>

#include "../utils/alias.hpp"

namespace config {
struct InterestingFunction {
    std::string name;
    std::string lib_name;
    u16 tags;
    std::string category;
};

struct StaticAnalysisConfig {
    bool do_sink_search;
    bool do_imports_print;
    bool do_poi_disas_print;
    std::vector<InterestingFunction> interesting_functions;
    std::vector<std::string> active_categories;
};

class Config {
public:
    std::vector<std::string> input_files;
    bool verbose_logs;
    StaticAnalysisConfig static_analysis;

    Config(const Config &) = delete;
    Config &operator=(const Config &) = delete;

    friend void InitFromArgs(int argc, char **argv);
    friend Config &Get();

private:
    bool initialized = false;

    Config() = default;
};

void InitFromArgs(int argc, char **argv);
Config &Get();

}  // namespace config

#endif  // CONFIG_HPP
