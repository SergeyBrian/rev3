#include "parser.hpp"

#include <LIEF/LIEF.hpp>

#include "../../../utils/logger.hpp"
#include "LIEF/PE/enums.hpp"
#include "lief_bin.hpp"

namespace core::static_analysis::parser {
Err ParseBinary(Target &target) {
    Err err{};
    logger::Debug("Running LIEF parser on target '%s'",
                  target.display_name.c_str());
    auto result = LIEF::PE::Parser::parse(target.filename);
    if (!result) {
        logger::Error("Parsing error");
        return Err::ParsingError;
    }

#ifdef X86_BUILD
    if (result->type() == LIEF::PE::PE_TYPE::PE32_PLUS) {
        logger::Error("Use rev3 for x64 binaries");
        return Err::ArchitectureMismatch;
    }
#else
    if (result->type() == LIEF::PE::PE_TYPE::PE32) {
        logger::Error("Use rev3x32 for x32 binaries");
        return Err::ArchitectureMismatch;
    }
#endif

    if (!result->has_exceptions()) {
        logger::Warn("No .pdata section found");
    }

    if (!result->has_relocations()) {
        logger::Warn("No .reloc section found");
    }

    logger::Debug("Entrypoint: 0x%llx", result->entrypoint());
    logger::Debug("Image base: 0x%llx", result->imagebase());

    logger::Debug("Range for valid pointers: from 0x%llx to 0x%llx",
                  result->imagebase(),
                  result->imagebase() + result->virtual_size());
    logger::Okay("Parsing done");

    for (const auto &section : result->sections()) {
        logger::Debug("Found section %s at 0x%llx", section.name().c_str(),
                      section.virtual_address());
        target.sections.push_back(Section{
            .name = section.name(),
            .address = section.virtual_address(),
            .size = section.size(),
            .virtual_size = section.virtual_size(),
        });
        if (section.name() == ".text") {
            logger::Okay(".text found at 0x%llx", section.virtual_address());
            target.text = {
                .name = section.name(),
                .address = section.virtual_address(),
                .size = section.size(),
                .virtual_size = section.virtual_size(),
            };
        }
    }

    auto libs = result->imports();
    for (const auto &lib : libs) {
        for (const auto &entry : lib.entries()) {
            target.imports[lib.name()].push_back(Function{
                .address = entry.hint_name_rva(),
                .display_name = entry.name(),
            });
        }
    }

    if (result->has_delay_imports()) {
        logger::Info("Reading delayed imports");
        auto delayed_imports = result->delay_imports();
        for (const auto &lib : delayed_imports) {
            for (const auto &entry : lib.entries()) {
                target.imports[lib.name()].push_back(Function{
                    .address = entry.hint_name_rva(),
                    .display_name = entry.name(),
                });
            }
        }
    }

    logger::Debug("Searching for interesting imports");
    auto interests = config::Get().static_analysis.interesting_functions;
    for (auto &[lib_name, entries] : target.imports) {
        std::string lower_lib_name = lib_name;
        std::transform(lower_lib_name.begin(), lower_lib_name.end(),
                       lower_lib_name.begin(), ::tolower);
        for (auto &entry : entries) {
            std::string lower_name = entry.display_name;
            std::transform(lower_name.begin(), lower_name.end(),
                           lower_name.begin(), ::tolower);
            for (const auto &interest : interests) {
                if (interest.lib_name == lower_lib_name &&
                    interest.name == lower_name) {
                    entry.tags = interest.tags;
                    break;
                }
            }
        }
    }

    target.bin_info =
        std::make_unique<static_analyis::parser::LiefBin>(std::move(result));

    return err;
}
std::vector<u64> FindImportsXrefs(LIEF::PE::Binary *bin, u64 address,
                                  Err *err) {
    if (!bin) {
        *err = Err::UnparsedBinary;
        return {};
    }
    auto res = bin->xref(address);
    for (const auto &xref : res) {
        logger::Debug("\t0x%llx -> ...", xref);
    }
    return res;
}
}  // namespace core::static_analysis::parser
