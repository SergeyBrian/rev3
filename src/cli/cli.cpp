#include "cli.hpp"

#include <map>
#include <iostream>

#include "../core/core.hpp"
#include "../core/output.hpp"

#include "../utils/logger.hpp"

namespace cli {
static core::Target *target = nullptr;

auto InspectFunc = [](const std::vector<ArgValue> &args) -> int {
    u64 address = args[0].number;
    core::Inspect(target, address);
    return 0;
};

auto InspectAddressFunc = [](const std::vector<ArgValue> &args) -> int {
    u64 address = args[0].number;
    u64 size = args[1].number;
    std::cout << target->GetString(address, size);
    return 0;
};

auto InfoFunc = [](const std::vector<ArgValue> &args) -> int {
    (void)args;
    core::Info(target);
    return 0;
};

auto ImportsFunc = [](const std::vector<ArgValue> &args) -> int {
    (void)args;
    core::output::PrintImports(*target);
    return 0;
};

auto FuncsFunc = [](const std::vector<ArgValue> &args) -> int {
    (void)args;
    core::output::PrintFunctions(target);
    return 0;
};

auto SolveFunc = [](const std::vector<ArgValue> &args) -> int {
    u64 address = args[0].number;
    core::Solve(target, address);
    return 0;
};

auto RefsFunc = [](const std::vector<ArgValue> &args) -> int {
    u64 address = args[0].number;
    core::output::PrintRefs(target, address);
    return 0;
};

auto ExitFunc = [](const std::vector<ArgValue> &args) -> int {
    (void)args;
    std::cout << "Bye :)\n";
    return -1;
};

static std::map<std::string, CommandDef> commands = {
    {
        "i",
        {
            "i <address> - inspect disassembly of block starting at <address>",
            {ArgType::Number},
            InspectFunc,
        },

    },
    {
        "ia",
        {
            "ia <address> <size> - inspect disassembly from specific <address>",
            {ArgType::Number, ArgType::Number},
            InspectAddressFunc,
        },
    },
    {
        "info",
        {
            "info - view general info about PE",
            {},
            InfoFunc,
        },
    },
    {
        "imports",
        {
            "imports - view imports table",
            {},
            ImportsFunc,
        },
    },
    {
        "solve",
        {
            "solve <address> - find solution leading to <address>",
            {ArgType::Number},
            SolveFunc,
        },
    },
    {
        "funcs",
        {
            "funcs - view functions table",
            {},
            FuncsFunc,
        },
    },
    {
        "refs",
        {
            "refs <address> - find references to function at <address>",
            {ArgType::Number},
            RefsFunc,
        },
    },
    {
        "exit",
        {
            "exit - quit program",
            {},
            ExitFunc,
        },
    },
};

u64 parseNumber(const std::string &arg) {
    int base = 10;
    std::string numberString = arg;

    if (arg.size() > 2 && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
        base = 16;
        numberString = arg.substr(2);
    }

    return std::stoll(numberString, nullptr, base);
}

void Run(core::Target *t) {
    target = t;
    std::cout << COLOR_GREEN << "~~Interactive mode~~\n" << COLOR_RESET;
    while (true) {
        std::cout << "[" << target->display_name << "] >> ";

        std::string line;
        if (!std::getline(std::cin, line)) {
            break;
        }

        auto trim = [](std::string &s) {
            while (!s.empty() &&
                   std::isspace(static_cast<unsigned char>(s.front()))) {
                s.erase(s.begin());
            }
            while (!s.empty() &&
                   std::isspace(static_cast<unsigned char>(s.back()))) {
                s.pop_back();
            }
        };
        trim(line);

        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::vector<std::string> tokens;
        {
            std::string t;
            while (iss >> t) {
                tokens.push_back(t);
            }
        }

        if (tokens.empty()) {
            continue;
        }

        std::string cmdName = tokens[0];
        std::vector<std::string> rawArgs(tokens.begin() + 1, tokens.end());

        auto cmdIt = commands.find(cmdName);
        if (cmdIt == commands.end()) {
            logger::Error("Unknown command: %s", cmdName.c_str());
            std::cout << "\nAvailable commands:\n";
            for (const auto &kv : commands) {
                std::cout << "\t" << kv.first << ": " << kv.second.usage
                          << "\n";
            }
            continue;
        }

        const CommandDef &cmd = cmdIt->second;
        size_t expectedCount = cmd.arg_types.size();
        if (rawArgs.size() < expectedCount) {
            logger::Error("Not enough arguments.\nUsage: %s",
                          cmd.usage.c_str());
            continue;
        }

        if (rawArgs.size() > expectedCount) {
            logger::Error("Too many arguments.\nUsage: %s", cmd.usage.c_str());
            continue;
        }

        std::vector<ArgValue> parsedArgs;
        parsedArgs.reserve(expectedCount);

        bool parseError = false;
        for (size_t i = 0; i < expectedCount; ++i) {
            ArgValue val{};
            const auto &argStr = rawArgs[i];
            switch (cmd.arg_types[i]) {
                case ArgType::Number:
                    try {
                        val.number = parseNumber(argStr);
                        val.string = argStr;
                    } catch (const std::exception &e) {
                        logger::Error("Invalid integer format: %s",
                                      argStr.c_str());
                        parseError = true;
                    }
                    break;
                case ArgType::String:
                    val.string = argStr;
                    break;
            }
            if (parseError) {
                break;
            }
            parsedArgs.push_back(val);
        }

        if (parseError) {
            continue;
        }

        int code = cmd.func(parsedArgs);
        if (code == -1) break;
    }
}
}  // namespace cli
