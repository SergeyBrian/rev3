#ifndef CLI_CLI_HPP
#define CLI_CLI_HPP

#include <functional>

#include "../core/core.hpp"
#include "../core/target.hpp"

namespace cli {
enum class ArgType : u8 {
    Number,
    String,
};

struct ArgValue {
    long long number;
    std::string string;
};

struct CommandDef {
    std::string usage;
    std::vector<ArgType> arg_types;
    std::function<int(const std::vector<ArgValue> &)> func;
};
void Run(core::Target *target);
}  // namespace cli

#endif
