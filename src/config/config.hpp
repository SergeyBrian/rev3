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
    std::string sink_target;
    bool do_imports_print;
    bool do_poi_disas_print;
    std::vector<InterestingFunction> interesting_functions;
    std::vector<std::string> active_categories;
    u64 inspect_address;
    bool do_executable_check;
};

struct DynamicAnalysisConfig {
    u64 target;
};

class Config {
public:
    std::vector<std::string> input_files;
    bool verbose_logs;
    StaticAnalysisConfig static_analysis;
    DynamicAnalysisConfig dynamic_analysis;
    bool ui;
    bool do_disasm_fixes;

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
