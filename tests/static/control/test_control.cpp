#include <gtest/gtest.h>
#include <vector>

#include "../../../src/core/static/control/control.hpp"
#include "../../../src/config/config.hpp"
#include "../../../src/utils/logger.hpp"

#include "../../bin_mock.hpp"

using namespace core::static_analysis;

void CompareGraphs(core::static_analysis::ControlFlowGraph *g1,
                   core::static_analysis::ControlFlowGraph *g2) {
    EXPECT_EQ(g1->nodes.size(), g2->nodes.size());
    for (const auto &[addr, node] : g1->nodes) {
        ASSERT_TRUE(g2->nodes.contains(addr))
            << "Block " << std::hex << addr << " not found" << std::dec;
        auto node2 = g2->FindNode(addr);
        ASSERT_NE(node2, nullptr)
            << "Block " << std::hex << addr << " is nullptr" << std::dec;
        EXPECT_EQ(node->block.address, node2->block.address);
        EXPECT_EQ(node->block.size, node2->block.size);

        EXPECT_EQ(node->in_edges.size(), node2->in_edges.size())
            << "Incoming edges count mismatch for block " << std::hex << addr
            << std::dec;
        EXPECT_EQ(node->out_edges.size(), node2->out_edges.size())
            << "Outgoing edges count mismatch for block " << std::hex << addr
            << std::dec;

        for (const auto &edge : node->in_edges) {
            bool edge_found = false;
            bool duplicate_edge = false;
            for (const auto &edge2 : node2->in_edges) {
                if (edge.source->block.address == edge2.source->block.address &&
                    edge.target->block.address == edge2.target->block.address) {
                    duplicate_edge = edge_found;
                    EXPECT_FALSE(duplicate_edge);
                    EXPECT_EQ(edge.type, edge2.type);
                    edge_found = true;
                }
            }
            EXPECT_TRUE(edge_found);
        }
        for (const auto &edge : node->out_edges) {
            bool edge_found = false;
            bool duplicate_edge = false;
            for (const auto &edge2 : node2->out_edges) {
                if (edge.source->block.address == edge2.source->block.address &&
                    edge.target->block.address == edge2.target->block.address) {
                    duplicate_edge = edge_found;
                    EXPECT_FALSE(duplicate_edge);
                    EXPECT_EQ(edge.type, edge2.type);
                    edge_found = true;
                }
            }
            EXPECT_TRUE(edge_found);
        }
    }
}

void DoCfgTest(ControlFlowGraph *expected, const u8 code[], usize size) {
    config::Get().verbose_logs = true;
    ::testing::NiceMock<MockBinInfo> bin;
    logger::Okay("Starting test");
    ON_CALL(bin, IsCode(testing::_)).WillByDefault(testing::Return(true));
    ON_CALL(bin, EntryPoint()).WillByDefault(testing::Return(0x1000));

    core::static_analysis::disassembler::Disassembly disas;
    disas.Disassemble(code, size);
    ASSERT_NE(disas.count, 0);
    core::static_analysis::ControlFlowGraph cfg;
    cfg.Build(&disas, &bin, std::vector<u64>{});
    CompareGraphs(expected, &cfg);
}

TEST(CFGTest, SimpleJmpImm) {
    const u8 code[] = {
        /*
        0:  e9 00 00 00 00          jmp    5 <_main+0x5>
        5:  48 c7 c0 34 12 00 00    mov    rax,0x1234
         */
        0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
    };
    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 5,
            },
            {
                .address = 0x1000 + 5,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 5,
                .type = CFGEdgeType::Jmp,
            },
        });

    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, SimpleJmpThreeNodes) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        7:  e9 00 00 00 00          jmp    c <_main+0xc>
        c:  48 c7 c3 21 43 00 00    mov    rbx,0x4321
        13: e9 00 00 00 00          jmp    18 <_main+0x18>
        18: 48 c7 c1 34 12 00 00    mov    rcx,0x1234
        */
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00,
        0x00, 0x48, 0xC7, 0xC3, 0x21, 0x43, 0x00, 0x00, 0xE9, 0x00, 0x00,
        0x00, 0x00, 0x48, 0xC7, 0xC1, 0x34, 0x12, 0x00, 0x00,
    };
    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5,
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5 + 7 + 5,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 7 + 5,
                .type = CFGEdgeType::Jmp,
            },
            {
                .from = 0x1000 + 7 + 5,
                .to = 0x1000 + 7 + 5 + 7 + 5,
                .type = CFGEdgeType::Jmp,
            },
        });
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestGarbageStop) {
    const u8 code[] = {
        /*
        0:  e9 00 00 00 00          jmp    5 <_main+0x5>
        5:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        c:  48 85 c0                test   rax,rax
        */
        0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0,
        0x34, 0x12, 0x00, 0x00, 0x48, 0x85, 0xC0,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 5,
            },
            {
                .address = 0x1000 + 5,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 5,
                .type = CFGEdgeType::Jmp,
            },
        });

    config::Get().verbose_logs = true;
    ::testing::NiceMock<MockBinInfo> bin;
    ON_CALL(bin, IsCode(testing::_))
        .WillByDefault(
            testing::Invoke([](u64 addr) { return addr != 0x100c; }));

    core::static_analysis::disassembler::Disassembly disas;
    disas.Disassemble(code, sizeof(code));
    ASSERT_NE(disas.count, 0);
    core::static_analysis::ControlFlowGraph cfg;
    cfg.Build(&disas, &bin, std::vector<u64>{});
    CompareGraphs(expected.get(), &cfg);
}

TEST(CFGTest, TestJmpReg) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 09 10 00 00    mov    rax,0x1009
        7:  ff e0                   jmp    rax
        9:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        */
        0x48, 0xC7, 0xC0, 0x09, 0x10, 0x00, 0x00, 0xFF,
        0xE0, 0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 2,
            },
            {
                .address = 0x1000 + 7 + 2,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 7 + 2,
                .type = CFGEdgeType::Jmp,
            },
        });
    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestJmpRegDistantReg) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 13 10 00 00    mov    rax,0x1013
        7:  48 31 db                xor    rbx,rbx
        a:  48 c7 c2 01 01 01 00    mov    rdx,0x10101
        11: ff e0                   jmp    rax
        13: 48 c7 c0 34 12 00 00    mov    rax,0x1234
        */
        0x48, 0xC7, 0xC0, 0x13, 0x10, 0x00, 0x00, 0x48, 0x31,
        0xDB, 0x48, 0xC7, 0xC2, 0x01, 0x01, 0x01, 0x00, 0xFF,
        0xE0, 0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
    };
    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 3 + 7 + 2,
            },
            {
                .address = 0x1000 + 7 + 3 + 7 + 2,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 7 + 3 + 7 + 2,
                .type = CFGEdgeType::Jmp,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestJmpRegIndirect) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 0f 10 00 00    mov    rax,0x100f
        7:  48 31 db                xor    rbx,rbx
        a:  48 89 c3                mov    rbx,rax
        d:  ff e3                   jmp    rbx
        f:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        */
        0x48, 0xC7, 0xC0, 0x0F, 0x10, 0x00, 0x00, 0x48, 0x31, 0xDB, 0x48,
        0x89, 0xC3, 0xFF, 0xE3, 0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 3 + 3 + 2,
            },
            {
                .address = 0x1000 + 7 + 3 + 3 + 2,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 7 + 3 + 3 + 2,
                .type = CFGEdgeType::Jmp,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestSimpleCall) {
    const u8 code[] = {
        /*
        0:  e8 01 00 00 00          call   6 <block2>
        5:  cc                      int3
        0000000000000006 <block2>:
        6:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        */
        0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x48,
        0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 5,
            },
            {
                .address = 0x1000 + 5,
                .size = 1,
            },
            {
                .address = 0x1000 + 5 + 1,
                .size = 7,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestSingleCallWithReturn) {
    const u8 code[] = {
        /*
        0:  e8 01 00 00 00          call   6 <block2>
        5:  cc                      int3
        0000000000000006 <block2>:
        6:  48 c7 c0 34 12 00 00    mov    rax,0x1234
        d:  c3                      ret
        */
        0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x48,
        0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, 0xC3,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 5,
            },
            {
                .address = 0x1000 + 5,
                .size = 1,
            },
            {
                .address = 0x1000 + 5 + 1,
                .size = 7 + 1,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 5 + 1,
                .to = 0x1000 + 5,
                .type = CFGEdgeType::Ret,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestMultipleCalls) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        7:  e8 0d 00 00 00          call   19 <block2>
        000000000000000c <block3>:
        c:  48 c7 c0 03 00 00 00    mov    rax,0x3
        13: e8 01 00 00 00          call   19 <block2>
        0000000000000018 <block4>:
        18: cc                      int3
        0000000000000019 <block2>:
        19: 48 c7 c0 02 00 00 00    mov    rax,0x2
        20: c3                      ret
        */
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x0D, 0x00, 0x00,
        0x00, 0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00,
        0x00, 0x00, 0xCC, 0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, 0xC3,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,  // block1
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5,  // block3
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5 + 7 + 5,  // block4
                .size = 1,
            },
            {
                .address = 0x1000 + 7 + 5 + 7 + 5 + 1,  // block2
                .size = 7 + 1,
            },
        },
        {
            {
                .from = 0x1000,  // 1 -> 2
                .to = 0x1000 + 7 + 5 + 7 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 7 + 5,  // 3 -> 2
                .to = 0x1000 + 7 + 5 + 7 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 7 + 5 + 7 + 5 + 1,  // 2 -> 4
                .to = 0x1000 + 7 + 5 + 7 + 5,
                .type = CFGEdgeType::Ret,
            },
            {
                .from = 0x1000 + 7 + 5 + 7 + 5 + 1,  // 2 -> 3
                .to = 0x1000 + 7 + 5,
                .type = CFGEdgeType::Ret,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestCallersListPropagation) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        7:  e8 01 00 00 00          call   d <block2>
        000000000000000c <block5>:
        c:  cc                      int3
        000000000000000d <block2>:
        d:  48 c7 c0 02 00 00 00    mov    rax,0x2
        14: eb 00                   jmp    16 <block3>
        0000000000000016 <block3>:
        16: 48 c7 c0 03 00 00 00    mov    rax,0x3
        1d: eb 00                   jmp    1f <block4>
        000000000000001f <block4>:
        1f: 48 c7 c0 04 00 00 00    mov    rax,0x4
        26: c3                      ret
        */
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00,
        0x00, 0x00, 0xCC, 0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,
        0xEB, 0x00, 0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00, 0xEB,
        0x00, 0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, 0xC3,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,  // block1
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5 + 1,  // block2
                .size = 7 + 2,
            },
            {
                .address = 0x1000 + 7 + 5 + 1 + 7 + 2,  // block3
                .size = 7 + 2,
            },
            {
                .address = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 2,  // block4
                .size = 7 + 1,
            },
            {
                .address = 0x1000 + 7 + 5,  // block5
                .size = 1,
            },
        },
        {
            {
                .from = 0x1000,  // 1 -> 2
                .to = 0x1000 + 7 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 7 + 5 + 1,  // 2 -> 3
                .to = 0x1000 + 7 + 5 + 1 + 7 + 2,
                .type = CFGEdgeType::Jmp,
            },
            {
                .from = 0x1000 + 7 + 5 + 1 + 7 + 2,  // 3 -> 4
                .to = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 2,
                .type = CFGEdgeType::Jmp,
            },
            {
                .from = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 2,  // 4 -> 5
                .to = 0x1000 + 7 + 5,
                .type = CFGEdgeType::Ret,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestChainedCalls) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        7:  e8 01 00 00 00          call   d <block2>
        000000000000000c <block6>:
        c:  cc                      int3
        000000000000000d <block2>:
        d:  48 c7 c0 02 00 00 00    mov    rax,0x2
        14: eb 00                   jmp    16 <block3>
        0000000000000016 <block3>:
        16: 48 c7 c0 03 00 00 00    mov    rax,0x3
        1d: e8 01 00 00 00          call   23 <block4>
        0000000000000022 <block5>:
        22: c3                      ret
        0000000000000023 <block4>:
        23: 48 c7 c0 04 00 00 00    mov    rax,0x4
        2a: c3                      ret
        */
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00,
        0x00, 0xCC, 0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x00,
        0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00,
        0x00, 0xC3, 0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, 0xC3,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,  // block1
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5 + 1,  // block2
                .size = 7 + 2,
            },
            {
                .address = 0x1000 + 7 + 5 + 1 + 7 + 2,  // block3
                .size = 7 + 5,
            },
            {
                .address = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5 + 1,  // block4
                .size = 7 + 1,
            },
            {
                .address = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5,  // block5
                .size = 1,
            },
            {
                .address = 0x1000 + 7 + 5,  // block6
                .size = 1,
            },
        },
        {
            {
                .from = 0x1000,  // 1 -> 2
                .to = 0x1000 + 7 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 7 + 5 + 1,  // 2 -> 3
                .to = 0x1000 + 7 + 5 + 1 + 7 + 2,
                .type = CFGEdgeType::Jmp,
            },
            {
                .from = 0x1000 + 7 + 5 + 1 + 7 + 2,  // 3 -> 4
                .to = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5 + 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5 + 1,  // 4 -> 5
                .to = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5,
                .type = CFGEdgeType::Ret,
            },
            {
                .from = 0x1000 + 7 + 5 + 1 + 7 + 2 + 7 + 5,  // 5 -> 6
                .to = 0x1000 + 7 + 5,
                .type = CFGEdgeType::Ret,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestBadCall) {
    const u8 code[] = {
        /*
        0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        7:  ff 90 ff 00 00 00       call   QWORD PTR [rax+0xff]
        d:  48 c7 c0 02 00 00 00    mov    rax,0x2
        */
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x90, 0xFF,
        0x00, 0x00, 0x00, 0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 6,
            },
            {
                .address = 0x1000 + 7 + 6,
                .size = 7,
            },
            {
                .address = 0x1000 - 1,
                .size = 0,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 - 1,
                .type = CFGEdgeType::Call,
            },
            {
                .from = 0x1000 - 1,
                .to = 0x1000 + 7 + 6,
                .type = CFGEdgeType::Ret,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}

TEST(CFGTest, TestCallLoop) {
    /*
     * This is currently expected behaviour since blocks are created based
     * solely on call/jmp/ret instructions and edges can only lead to beginning
     * of a node
     */
    const u8 code[] = {
        /*
        0000000000000000 <block1>:
        0:  48 c7 c0 05 00 00 00    mov    rax,0x5
        0000000000000007 <block2>:
        7:  48 ff c8                dec    rax
        a:  48 85 c0                test   rax,rax
        d:  75 f8                   jne    7 <block1>
        000000000000000f <block3>:
        f:  cc                      int3
        */
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, 0x48,
        0xFF, 0xC8, 0x48, 0x85, 0xC0, 0x75, 0xF8, 0xCC,
    };

    auto expected = ControlFlowGraph::MakeCFG(
        {
            {
                .address = 0x1000,
                .size = 7 + 3 + 3 + 2,
            },
            {
                .address = 0x1000 + 7,
                .size = 3 + 3 + 2,
            },
            {
                .address = 0x1000 + 7 + 3 + 3 + 2,
                .size = 1,
            },
        },
        {
            {
                .from = 0x1000,
                .to = 0x1000 + 7,
                .type = CFGEdgeType::Jcc,
            },
            {
                .from = 0x1000,
                .to = 0x1000 + 7 + 3 + 3 + 2,
                .type = CFGEdgeType::Jcc,
            },
            {
                .from = 0x1000 + 7,
                .to = 0x1000 + 7,
                .type = CFGEdgeType::Jcc,
            },
            {
                .from = 0x1000 + 7,
                .to = 0x1000 + 7 + 3 + 3 + 2,
                .type = CFGEdgeType::Jcc,
            },
        });

    ASSERT_NE(expected, nullptr);
    DoCfgTest(expected.get(), code, sizeof(code));
}
