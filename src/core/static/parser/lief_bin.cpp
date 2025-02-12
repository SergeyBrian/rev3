#include "lief_bin.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analyis::parser {
LiefBin::LiefBin(std::unique_ptr<LIEF::PE::Binary> lief_bin)
    : bin(std::move(lief_bin)) {}

std::vector<u64> LiefBin::FindImportsXrefs(u64 addr, Err *err) {
    auto res = bin->xref(addr);
    for (const auto &xref : res) {
        logger::Debug("\t0x%llx -> ...", xref);
    }
    return res;
}

bool LiefBin::IsCode(u64 addr) {
    if (!config::Get().static_analysis.do_executable_check) return true;
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

bool LiefBin::AddressInSection(u64 addr, const std::string &name) const {
    auto section = bin->section_from_rva(addr);
    return section && section->name() == name;
}

std::string LiefBin::SectionFromRva(u64 addr) const {
    return bin->section_from_rva(addr)->name();
}

u64 LiefBin::ImageBase() const { return bin->imagebase(); }

const byte *LiefBin::Data(u64 addr, usize size) const {
    return bin
        ->get_content_from_virtual_address(addr,
                                           std::min(size, bin->virtual_size()))
        .data();
}

u64 LiefBin::EntryPoint() const { return bin->entrypoint() - bin->imagebase(); }
}  // namespace core::static_analyis::parser
