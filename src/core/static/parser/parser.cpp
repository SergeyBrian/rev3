#include "parser.hpp"

#include <LIEF/LIEF.hpp>

#include "../../../utils/logger.hpp"

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

    if (!result->has_exceptions()) {
        logger::Warn("No .pdata section found");
    }

    if (!result->has_relocations()) {
        logger::Warn("No .reloc section found");
    }

    logger::Okay("Parsing done");

    for (const auto &section : result->sections()) {
        logger::Debug("Found section %s at 0x%x", section.name().c_str(),
                      section.virtual_address());
        target.sections.push_back(Section{
            .name = section.name(),
            .address = section.virtual_address(),
            .size = section.size(),
            .virtual_size = section.virtual_size(),
        });
        if (section.name() == ".text") {
            logger::Okay(".text found at 0x%x", section.virtual_address());
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

    target.lief_bin = std::move(result);

    return err;
}
std::vector<u64> FindImportsXrefs(LIEF::PE::Binary *bin, u64 address,
                                  Err *err) {
    auto res = bin->xref(address);
    for (const auto &xref : res) {
        logger::Debug("\t0x%x -> ...", xref);
    }
    return res;
}

bool IsCode(const LIEF::PE::Binary *bin, u64 addr) {
    if (!bin->has_relocations() && !bin->has_exceptions()) {
        logger::Warn("Can't verify that code is executable");
        return true;
    }

    for (const auto &func : bin->exception_functions()) {
        if (func.address() <= addr && addr <= func.address() + func.size()) {
            return true;
        }
    }

    for (const auto &reloc : bin->relocations()) {
        auto base_rva = reloc.virtual_address();
        if (!(base_rva <= addr && addr < base_rva + 0x1000)) continue;
        for (const auto &entry : reloc.entries()) {
            if (addr - base_rva == entry.address()) return true;
        }
    }

    return false;
}
}  // namespace core::static_analysis::parser
