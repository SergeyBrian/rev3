#ifndef TESTS_BIN_MOCK_HPP
#define TESTS_BIN_MOCK_HPP

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../src/core/bin.hpp"

class MockBinInfo : public core::BinInfo {
public:
    MOCK_METHOD2(FindImportsXrefs, std::vector<u64>(u64 addr, Err *err));
    MOCK_METHOD1(IsCode, bool(u64 addr));
    MOCK_CONST_METHOD2(AddressInSection,
                       bool(u64 addr, const std::string &name));
    MOCK_CONST_METHOD1(SectionFromRva, std::string(u64 addr));
    MOCK_CONST_METHOD0(ImageBase, u64(void));
    MOCK_CONST_METHOD2(Data, const byte *(u64 addr, usize size));
    MOCK_CONST_METHOD0(EntryPoint, u64(void));
};

#endif
