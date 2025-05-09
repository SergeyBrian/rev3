#ifndef CORE_STATIC_PARSER_LIEF_BIN_HPP
#define CORE_STATIC_PARSER_LIEF_BIN_HPP

#include <LIEF/LIEF.hpp>

#include "../../bin.hpp"

namespace core::static_analyis::parser {

class LiefBin : public BinInfo {
public:
    explicit LiefBin(std::unique_ptr<LIEF::PE::Binary> lief_bin);
    std::vector<u64> FindImportsXrefs(u64 addr, Err *err) override;
    bool IsCode(u64 addr) override;
    bool IsValidPtr(u64 addr) override;
    bool AddressInSection(u64 addr, const std::string &name) const override;
    std::string SectionFromRva(u64 addr) const override;
    u64 ImageBase() const override;
    const byte *Data(u64 addr, usize size) const override;
    std::vector<u8> DataVec(u64 addr, usize size) const override;
    u64 EntryPoint() const override;

private:
    std::unique_ptr<LIEF::PE::Binary> bin;
};
}  // namespace core::static_analyis::parser

#endif
