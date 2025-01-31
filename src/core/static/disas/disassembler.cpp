#include "disassembler.hpp"

#include "../../../utils/logger.hpp"

namespace core::static_analysis::disassembler {
Err Disassembler::DisassembleNearby(const LIEF::PE::Binary *binary,
                                    u64 address) {
    Err err{};

    auto text_section = binary->get_section(".text");
    if (!text_section) {
        logger::Error("Failed to find .text section");
        return Err::TextSectionNotFound;
    }

    u64 text_base = text_section->virtual_address();
    u64 offset = address - text_base;

    const u64 range = 32;

    u64 effective_address = address - range;

    auto instructions = binary->disassemble(effective_address, range * 2);

    if (instructions.empty()) {
        logger::Error("Failed to disassemble at address: 0x%x", address);
        return Err::DisassemblerError;
    }

    Entry entry{
        .address = effective_address,
        .instructions = instructions,
    };

    return err;
}
}  // namespace core::static_analysis::disassembler
