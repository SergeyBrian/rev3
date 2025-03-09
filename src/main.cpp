#include "config/config.hpp"
#include "core/core.hpp"
#include "cli/cli.hpp"

int main(int argc, char **argv) {
    config::InitFromArgs(argc, argv);
    Err err = core::Init();
    if (err != Err::Ok) {
        return static_cast<int>(err);
    }

    core::Run();
    if (config::Get().ui) {
        cli::Run(core::GetActiveTarget());
    }
    return 0;
}
