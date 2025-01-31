#ifndef CORE_STATIC_DISASSEMBLER_HPP
#define CORE_STATIC_DISASSEMBLER_HPP

#include <map>

#include <LIEF/LIEF.hpp>

#include "../../../utils/alias.hpp"
#include "../../../utils/errors.hpp"

namespace core::static_analysis::disassembler {
struct Entry {
    u64 address;
    LIEF::PE::Binary::instructions_it instructions;
};
struct Disassembler {
    std::map<u64, Entry> entries;

    Err DisassembleNearby(const LIEF::PE::Binary *binary, u64 address);
};
}  // namespace core::static_analysis::disassembler

#endif
