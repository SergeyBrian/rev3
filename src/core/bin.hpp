#ifndef CORE_STATIC_BIN_HPP
#define CORE_STATIC_BIN_HPP

#include <vector>
#include <string>

#include "../utils/alias.hpp"
#include "../utils/errors.hpp"

namespace core {
class BinInfo {
public:
    virtual std::vector<u64> FindImportsXrefs(u64 addr, Err *err) = 0;
    virtual bool IsCode(u64 addr) = 0;
    virtual bool IsValidPtr(u64 addr) = 0;
    virtual bool AddressInSection(u64 addr, const std::string &name) const = 0;
    virtual std::string SectionFromRva(u64 addr) const = 0;
    virtual u64 ImageBase() const = 0;
    virtual std::vector<u8> DataVec(u64 addr, usize size) const = 0;
    virtual const byte *Data(u64 addr, usize size) const = 0;
    virtual u64 EntryPoint() const = 0;
    virtual ~BinInfo() = default;
};
}  // namespace core

#endif
