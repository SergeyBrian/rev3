#include <gtest/gtest.h>
#include <map>

#include "../../../src/core/static/disas/disassembler.hpp"
#include "../../../src/config/config.hpp"

#include "../../bin_mock.hpp"

using namespace core::static_analysis::disassembler;

void TestDisassembler(const std::map<u64, std::string> &expected,
                      const byte *code, usize size) {
    auto &conf = config::Get();
    conf.do_disasm_fixes = true;
    Disassembly disas{};
    ResetCache();
    ::testing::NiceMock<MockBinInfo> bin;
    ON_CALL(bin, IsCode(testing::_)).WillByDefault(testing::Return(true));
    ON_CALL(bin, IsValidPtr(testing::_))
        .WillByDefault(testing::Invoke(
            [](u64 addr) { return addr >= 0x1000 && addr <= 0x5000; }));
    ON_CALL(bin, EntryPoint()).WillByDefault(testing::Return(0x1000));
    disas.Disassemble(code, size, &bin);

    for (const auto &[addr, insn] : disas.instr_map) {
        std::string insn_str =
            std::string(insn->mnemonic) + " " + std::string(insn->op_str);
        std::cout << "\t" << std::hex << addr << " " << insn_str << "\n";
        EXPECT_TRUE(expected.contains(addr));
        if (expected.contains(addr)) {
            EXPECT_EQ(insn_str, expected.at(addr));
        }
    }
}

TEST(DisassemblerTest, TestJzJnzTechniqueDetection) {
    const byte code[] = {
        /*
.text:00409AB0                 jnz     short loc_409AB4
.text:00409AB2                 jmp     short loc_409AC5
.text:00409AB4
---------------------------------------------------------------------------
.text:00409AB4
.text:00409AB4 loc_409AB4:
.text:00409AB4                 jz      short loc_409ABB
.text:00409AB6                 jnz     short loc_409ABB
.text:00409AB6
---------------------------------------------------------------------------
.text:00409AB8                 db 0E8h
.text:00409AB9                 db 0A3h
.text:00409ABA                 db 0BBh
.text:00409ABB
---------------------------------------------------------------------------
.text:00409ABB
.text:00409ABB loc_409ABB:
.text:00409ABB
.text:00409ABB                 mov     dword_435FB8, 1
        */
        0x75, 0x02, 0xEB, 0x11, 0x74, 0x05, 0x75, 0x03, 0xE8, 0xA3, 0xBB,
        0xC7, 0x05, 0xB8, 0x5F, 0x43, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    std::map<u64, std::string> expected = {
        {0x1000, "jne 0x1004"},
        {0x1002, "jmp 0x1015"},
        {0x1004, "je 0x100b"},
        {0x1006, "jne 0x100b"},
        {0x100b, "mov dword ptr [0x435fb8], 1"}};

    TestDisassembler(expected, code, sizeof(code));
}
