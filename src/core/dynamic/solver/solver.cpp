#include "solver.hpp"
#include "triton/archEnums.hpp"
#include "triton/cpuSize.hpp"
#include "triton/instruction.hpp"

#include <triton/context.hpp>
#include <triton/ast.hpp>
#include <triton/x8664Cpu.hpp>
#include <triton/x86Cpu.hpp>

#include "../../static/control/control.hpp"

#include "../../../utils/logger.hpp"
#include "../../../utils/utils.hpp"
#include "triton/register.hpp"

namespace core::dynamic::solver {
[[maybe_unused]] static const u64 MaxSymbolicMemorySize = 300;

static const std::map<std::string, bool> ImportantFunctions{
    {"_security_init_cookie", false},
    {"printf", false},
    {"scanf", false},
    {"puts", false},
    {"gets_s", false},
};

static u64 first_ip{};
static const Target *g_target = nullptr;
static std::map<u64, std::pair<triton::arch::register_e, u64>> reg_override{};

const static u8 memchr_impl[] = {
    0x4C, 0x89, 0x44, 0x24, 0x18, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89,
    0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x18, 0x48, 0x8B, 0x44, 0x24,
    0x20, 0x48, 0x89, 0x04, 0x24, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48,
    0x89, 0x44, 0x24, 0x08, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0xFF,
    0xC8, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x83, 0x7C, 0x24, 0x08,
    0x00, 0x74, 0x26, 0x48, 0x8B, 0x04, 0x24, 0x0F, 0xB6, 0x00, 0x0F,
    0xB6, 0x4C, 0x24, 0x28, 0x39, 0xC8, 0x75, 0x06, 0x48, 0x8B, 0x04,
    0x24, 0xEB, 0x12, 0x48, 0x8B, 0x04, 0x24, 0x48, 0xFF, 0xC0, 0x48,
    0x89, 0x04, 0x24, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x90,
};

void PrintSymMem(triton::Context *ctx) {
    return;
    logger::Debug("sym mem");
    for (const auto &[addr, mem] : ctx->getSymbolicMemory()) {
        logger::Debug("Sym mem 0x%llx", addr);
        auto data = ctx->getSymbolicMemoryAreaValue(addr, 1);
        logger::log << utils::UnescapeString({data.begin(), data.end()})
                    << "\n";
    }
    logger::Debug("sym mem over");
}

void CleanUpTrace(const Target *target,
                  std::vector<static_analysis::CFGNode *> &path) {
    for (auto it = path.begin(); it != path.end();) {
        auto node = *it;
        if (target->functions.contains(node->block.real_address)) {
            auto func = target->functions.at(node->block.real_address);
            if (ImportantFunctions.contains(func->display_name) &&
                !ImportantFunctions.at(func->display_name)) {
                it = path.erase(it);
                continue;
            }
        }
        it++;
    }
}

void PrintDebugInfo(triton::arch::Instruction &instr, triton::Context *ctx) {
    logger::Debug("===================");
    if (instr.isSymbolized()) logger::log << "syminstr: ";
    logger::log << COLOR_BLUE << instr << COLOR_RESET << "\n";
    auto regs = instr.getReadRegisters();

    for (const auto &[reg, expr] : regs) {
        if (!ctx->isRegisterSymbolized(reg)) continue;

        logger::Debug("%s", reg.getName().c_str());
    }

    for (const auto &[mem, expr] : instr.getLoadAccess()) {
        if (!ctx->isMemorySymbolized(mem)) {
            logger::Debug("Read concret memory: 0x%llx", mem.getAddress());
        } else {
            logger::Debug("0x%llx", mem.getAddress());
        }
    }

    for (const auto &expr : instr.symbolicExpressions) {
        logger::log << expr << "\n";
    }
}

using SourceHandler = void (*)(triton::Context *ctx,
                               triton::arch::Instruction *instruction,
                               Function *func);

u64 source_addr{};
u64 source_mem_size{};

void fgets_Handler(triton::Context *ctx, triton::arch::Instruction *instruction,
                   Function *func) {
    auto buf = u64(ctx->getConcreteRegisterValue(ctx->registers.x86_rcx));
    auto size = usize(ctx->getConcreteRegisterValue(ctx->registers.x86_edx));
    logger::Debug("fgets -> 0x%llx, size %u", buf, size);
    ctx->symbolizeMemory(buf, size);
    ctx->setConcreteRegisterValue(ctx->registers.x86_rax, buf);

    source_addr = buf;
    source_mem_size = size;
};

void strcpy_s_Handler(triton::Context *ctx,
                      triton::arch::Instruction *instruction, Function *func) {
    auto dest = ctx->registers.x86_rcx;
    auto src = ctx->registers.x86_r8;
    auto count_reg = ctx->registers.x86_edx;

    auto dest_ptr = static_cast<u64>(ctx->getConcreteRegisterValue(dest));
    auto src_ptr = static_cast<u64>(ctx->getConcreteRegisterValue(src));
    auto count = static_cast<u64>(ctx->getConcreteRegisterValue(count_reg));

    while (count--) {
        uint8_t byte = ctx->getConcreteMemoryAreaValue(src_ptr, 1).front();
        logger::Debug("cpy %c", byte);

        if (byte == '\0') {
            ctx->setConcreteMemoryAreaValue(dest_ptr, &byte, 1);
            ctx->symbolizeMemory(dest_ptr, 1);
            break;
        }

        ctx->setConcreteMemoryAreaValue(dest_ptr, &byte, 1);
        ctx->symbolizeMemory(dest_ptr, 1);

        dest_ptr++;
        src_ptr++;
    }
}

void memchr_Handler(triton::Context *ctx,
                    triton::arch::Instruction *instruction, Function *func) {
    auto buf = ctx->getConcreteRegisterValue(ctx->registers.x86_rcx);
    auto key = ctx->getConcreteRegisterValue(ctx->registers.x86_edx);
    auto maxcount = ctx->getConcreteRegisterValue(ctx->registers.x86_r8);

    for (u64 i = 0; i < maxcount; i++) {
        auto c = ctx->getConcreteMemoryValue(
            {static_cast<u64>(buf) + i, triton::size::byte});
        if (c == key) {
            ctx->setConcreteRegisterValue(ctx->registers.x86_rax,
                                          static_cast<u64>(buf) + i);
            return;
        }
    }
}

void gets_s_Handler(triton::Context *ctx,
                    triton::arch::Instruction *instruction, Function *func) {
    auto buf = u64(ctx->getConcreteRegisterValue(ctx->registers.x86_rcx));
    auto size = usize(ctx->getConcreteRegisterValue(ctx->registers.x86_edx));
    logger::Debug("gets_s -> 0x%llx, size %u", buf, size);
    ctx->symbolizeMemory(buf, size);

    source_addr = buf;
    source_mem_size = size;
};

void ReadFile_Handler(triton::Context *ctx,
                      triton::arch::Instruction *instruction, Function *func) {
    auto buf = u64(ctx->getConcreteRegisterValue(ctx->registers.x86_rdx));
    auto size = usize(ctx->getConcreteRegisterValue(ctx->registers.x86_r8d));
    logger::Debug("ReadFile -> 0x%llx, size %u", buf, size);
    ctx->symbolizeMemory(buf, size);

    source_addr = buf;
    source_mem_size = size;
};

void RegGetValueW_Handler(triton::Context *ctx,
                          triton::arch::Instruction *instruction,
                          Function *func) {
    ctx->symbolizeMemory({static_cast<u64>(ctx->getConcreteRegisterValue(
                              ctx->registers.x86_rsp)) +
                              0x60,
                          triton::size::byte});
    logger::Debug("RegGetValueW");
    source_addr = static_cast<u64>(
                      ctx->getConcreteRegisterValue(ctx->registers.x86_rsp)) +
                  0x60;
    source_mem_size = 1;
}

void RegOpenKeyExW_Handler(triton::Context *ctx,
                           triton::arch::Instruction *instruction,
                           Function *func) {
    ctx->symbolizeRegister(ctx->registers.x86_rax);
    logger::Debug("RegOpenKeyExW");
}

void GetModuleFileNameW_Handler(triton::Context *ctx,
                                triton::arch::Instruction *instruction,
                                Function *func) {
    auto buf = u64(ctx->getConcreteRegisterValue(ctx->registers.x86_rdx));
    auto size = usize(ctx->getConcreteRegisterValue(ctx->registers.x86_r8d));
    logger::Debug("GetModuleFileNameW -> 0x%llx, size %u", buf, size);
    ctx->symbolizeMemory(buf, size);

    source_addr = buf;
    source_mem_size = size;
};

void PrintRes(triton::Context *ctx) {
    auto res_bytes =
        ctx->getSymbolicMemoryAreaValue(source_addr, source_mem_size);
    std::string result{res_bytes.begin(), res_bytes.end()};
    logger::log << COLOR_GREEN << result << "\n" << COLOR_RESET;
}

static const std::map<std::string, SourceHandler> handlers{
    {"fgets", fgets_Handler},
    {"gets_s", gets_s_Handler},
    {"ReadFile", ReadFile_Handler},
    {"RegGetValueW", RegGetValueW_Handler},
    {"RegOpenKeyExW", RegOpenKeyExW_Handler},
    {"GetModuleFileNameW", GetModuleFileNameW_Handler},
    {"strcpy_s", strcpy_s_Handler},
    {"memchr", memchr_Handler},
};

bool DoInstrStuff(triton::Context *ctx, triton::arch::Instruction *instruction,
                  cs_insn *instr, u64 *ip) {
    bool step_over = false;
    if (instr->id == X86_INS_CALL && g_target->references.contains(*ip)) {
        logger::Info("Found call");
        step_over = true;
        if (!g_target->disassembly.instr_map.contains(
                instruction->getNextAddress())) {
            step_over = true;
        }
        for (const auto &ref : g_target->references.at(*ip)) {
            if (ref.type == Reference::Type::Function) {
                auto func = g_target->functions.at(ref.address);
                logger::Info("Call to %s", func->display_name.c_str());
                if (ImportantFunctions.contains(func->display_name) &&
                    !ImportantFunctions.at(func->display_name)) {
                    step_over = true;
                }
                if (handlers.contains(func->display_name)) {
                    handlers.at(func->display_name)(ctx, instruction, func);
                    PrintRes(ctx);
                }
            }
        }
    }
    if (step_over) {
        logger::Info("Stepping over 0x%llx", ip);
        auto it = g_target->disassembly.instr_map.lower_bound(*ip);
#ifdef X86_BUILD
        ctx->symbolizeRegister(ctx->registers.x86_eax);
        ctx->setConcreteRegisterValue(
            ctx->registers.x86_esp,
            ctx->getConcreteRegisterValue(ctx->registers.x86_esp) +
                triton::size::dword);
#else
        ctx->symbolizeRegister(ctx->registers.x86_rax);
        ctx->setConcreteRegisterValue(
            ctx->registers.x86_rsp,
            ctx->getConcreteRegisterValue(ctx->registers.x86_rsp) +
                triton::size::qword);
#endif
        it++;
        *ip = it->first;
    }
    return step_over;
}

bool IsAddressReachable(u64 from, u64 to,
                        const static_analysis::ControlFlowGraph *g) {
    return !g->FindPath(from, to).empty();
}

[[nodiscard]] std::unique_ptr<triton::Context> MakeDefaultContext() {
    auto ctx = std::make_unique<triton::Context>();
#ifdef X86_BUILD
    ctx->setArchitecture(triton::arch::ARCH_X86);
#else
    ctx->setArchitecture(triton::arch::ARCH_X86_64);
#endif
    for (const auto &section : g_target->sections) {
        auto data = g_target->bin_info->DataVec(section.address, section.size);
        if (data.empty()) {
            logger::Error("Bad memory");
            return nullptr;
        }

#ifdef X86_BUILD
        ctx->setConcreteMemoryAreaValue(
            section.address + g_target->bin_info->ImageBase(), data.data(),
            data.size());
#else
        ctx->setConcreteMemoryAreaValue(section.address, data.data(),
                                        data.size());
#endif
    }

    ctx->setConcreteRegisterValue(ctx->registers.x86_esp, 0x600000);
    // ctx->setConcreteMemoryAreaValue(0x600004, {0x00, 0x00, 0x70, 0x00});
    std::vector<u8> default_str = {
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'B', 0,
    };
    assert(default_str.size() == 39);
    // ctx->setConcreteMemoryAreaValue(0x700000, default_str.data(),
    //                                 default_str.size());
    //  This is memory where user input is assumed to be stored
    // ctx->symbolizeMemory(0x700000, 40);

    return ctx;
}

[[nodiscard]] std::unique_ptr<triton::Context> SnapshotContext(
    triton::Context *src, u64 step_count) {
    logger::Debug("Create snapshot. %u steps to make", step_count);
    auto ctx = MakeDefaultContext();
    /*ctx->setConcreteMemoryAreaValue(*/
    /*    0x700000, src->getSymbolicMemoryAreaValue(0x700000, 40));*/
    /*ctx->symbolizeMemory(0x700000, 40);*/
    /*auto data = src->getSymbolicMemoryAreaValue(0x700000, 40);*/
    /*logger::log << utils::UnescapeString({data.begin(), data.end()}) <<
     * "\n";*/
    auto old_data =
        src->getConcreteMemoryAreaValue(source_addr, source_mem_size);
    ctx->setConcreteMemoryAreaValue(source_addr, old_data.data(),
                                    old_data.size());
    ctx->symbolizeMemory(source_addr, source_mem_size);

    u64 ip = first_ip;

    while (step_count--) {
        if (!g_target->disassembly.instr_map.contains(ip)) return nullptr;
        PrintRes(ctx.get());
        triton::arch::Instruction instruction{};
        auto instr = g_target->disassembly.instr_map.at(ip);
        if (reg_override.contains(ip)) {
            auto &[reg, val] = reg_override.at(ip);
            ctx->setConcreteRegisterValue(ctx->getRegister(reg), val);
            ctx->symbolizeRegister(ctx->getRegister(reg));
        }

        if (instr->id == X86_INS_DIV &&
            instr->detail->x86.operands[0].reg == X86_REG_CH) {
            ip += instr->size;
            continue;
        }
        instruction.setAddress(instr->address);
        instruction.setSize(instr->size);
        instruction.setOpcode(instr->bytes, instr->size);
        ctx->processing(instruction);
        PrintDebugInfo(instruction, ctx.get());
        if (DoInstrStuff(ctx.get(), &instruction, instr, &ip)) continue;
#ifdef X86_BUILD
        ip = static_cast<u64>(
            ctx->getSymbolicRegisterValue(ctx->registers.x86_eip));
#else
        ip = static_cast<u64>(
            ctx->getSymbolicRegisterValue(ctx->registers.x86_rip));
#endif
    }

    logger::Debug("Snapshot created.");

    return std::move(ctx);
}

u64 GetLastInstrAddress(const static_analysis::CFGNode *node,
                        const Target *target) {
    auto it = target->disassembly.instr_map.lower_bound(node->block.address);
    while (it != target->disassembly.instr_map.end() &&
           it->first < node->block.address + node->block.size) {
        it++;
    }

    return it->first;
}

void GetRegisterValue(triton::Context *ctx, triton::arch::Register &reg,
                      u64 *val) {
    if (ctx->isRegisterSymbolized(reg)) {
        *val = static_cast<u64>(ctx->getSymbolicRegisterValue(reg));
    } else {
        *val = static_cast<u64>(ctx->getConcreteRegisterValue(reg));
    }
}

void SetRegisterValue(triton::Context *ctx, triton::arch::Register &reg,
                      u64 val) {
    ctx->setConcreteRegisterValue(reg, val);
}

void NegateInstructionFlags(triton::Context *ctx,
                            triton::arch::Instruction *triton_instruction) {
    switch (triton_instruction->getType()) {
        case triton::arch::x86::ID_INS_JA: {
            u64 cf;
            GetRegisterValue(ctx, ctx->registers.x86_cf, &cf);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (cf == 0 && zf == 0) {
                cf = 1;
                zf = 1;
            } else {
                cf = 0;
                zf = 0;
            }
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            SetRegisterValue(ctx, ctx->registers.x86_cf, cf);
            break;
        }
        case triton::arch::x86::ID_INS_JAE: {
            u64 cf;
            GetRegisterValue(ctx, ctx->registers.x86_cf, &cf);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (cf == 0 || zf == 0) {
                cf = 1;
                zf = 1;
            } else {
                cf = 0;
                zf = 0;
            }
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            SetRegisterValue(ctx, ctx->registers.x86_cf, cf);
            break;
        }
        case triton::arch::x86::ID_INS_JB: {
            u64 cf;
            GetRegisterValue(ctx, ctx->registers.x86_cf, &cf);
            cf = !cf;
            SetRegisterValue(ctx, ctx->registers.x86_cf, cf);
            break;
        }
        case triton::arch::x86::ID_INS_JBE: {
            u64 cf;
            GetRegisterValue(ctx, ctx->registers.x86_cf, &cf);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (cf == 1 || zf == 1) {
                cf = 0;
                zf = 0;
            } else {
                cf = 1;
                zf = 1;
            }
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            SetRegisterValue(ctx, ctx->registers.x86_cf, cf);
            break;
        }
        case triton::arch::x86::ID_INS_JE:
        case triton::arch::x86::ID_INS_JNE: {
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            zf = !zf;
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            break;
        }
        case triton::arch::x86::ID_INS_JG: {
            u64 sf;
            GetRegisterValue(ctx, ctx->registers.x86_sf, &sf);
            u64 of;
            GetRegisterValue(ctx, ctx->registers.x86_of, &of);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (sf == of && zf == 0) {
                sf = !of;
                zf = 1;
            } else {
                sf = of;
                zf = 0;
            }
            SetRegisterValue(ctx, ctx->registers.x86_sf, sf);
            SetRegisterValue(ctx, ctx->registers.x86_of, of);
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            break;
        }
        case triton::arch::x86::ID_INS_JGE: {
            u64 sf;
            GetRegisterValue(ctx, ctx->registers.x86_sf, &sf);
            u64 of;
            GetRegisterValue(ctx, ctx->registers.x86_of, &of);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (sf == of || zf == 1) {
                sf = !of;
                zf = 0;
            } else {
                sf = of;
                zf = 1;
            }
            SetRegisterValue(ctx, ctx->registers.x86_sf, sf);
            SetRegisterValue(ctx, ctx->registers.x86_of, of);
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            break;
        }
        case triton::arch::x86::ID_INS_JL: {
            u64 sf;
            GetRegisterValue(ctx, ctx->registers.x86_sf, &sf);
            u64 of;
            GetRegisterValue(ctx, ctx->registers.x86_of, &of);
            if (sf == of) {
                sf = !of;
            } else {
                sf = of;
            }
            SetRegisterValue(ctx, ctx->registers.x86_sf, sf);
            SetRegisterValue(ctx, ctx->registers.x86_of, of);
            break;
        }
        case triton::arch::x86::ID_INS_JLE: {
            u64 sf;
            GetRegisterValue(ctx, ctx->registers.x86_sf, &sf);
            u64 of;
            GetRegisterValue(ctx, ctx->registers.x86_of, &of);
            u64 zf;
            GetRegisterValue(ctx, ctx->registers.x86_zf, &zf);
            if (sf != of || zf == 1) {
                sf = of;
                zf = 0;
            } else {
                sf = !of;
                zf = 1;
            }
            SetRegisterValue(ctx, ctx->registers.x86_sf, sf);
            SetRegisterValue(ctx, ctx->registers.x86_of, of);
            SetRegisterValue(ctx, ctx->registers.x86_zf, zf);
            break;
        }
        case triton::arch::x86::ID_INS_JNO:
        case triton::arch::x86::ID_INS_JO: {
            u64 of;
            GetRegisterValue(ctx, ctx->registers.x86_of, &of);
            of = !of;
            SetRegisterValue(ctx, ctx->registers.x86_of, of);
            break;
        }
        case triton::arch::x86::ID_INS_JNP:
        case triton::arch::x86::ID_INS_JP: {
            u64 pf;
            GetRegisterValue(ctx, ctx->registers.x86_pf, &pf);
            pf = !pf;
            SetRegisterValue(ctx, ctx->registers.x86_pf, pf);
            break;
        }
        case triton::arch::x86::ID_INS_JNS:
        case triton::arch::x86::ID_INS_JS: {
            u64 sf;
            GetRegisterValue(ctx, ctx->registers.x86_sf, &sf);
            sf = !sf;
            SetRegisterValue(ctx, ctx->registers.x86_sf, sf);
            break;
        }
        default:
            logger::Error("Can't negate %s instruction\n",
                          triton_instruction->getDisassembly().c_str());
    }
}

bool SolveFormula(triton::Context *ctx, u64 ip,
                  const triton::arch::Instruction *instr) {
    auto pc = ctx->getPathConstraints().back();
    logger::Debug("0x%llx == 0x%llx", std::get<1>(pc.getBranchConstraints()[0]),
                  ip);
    assert(std::get<1>(pc.getBranchConstraints()[0]) == ip &&
           "Programming error. Path constraint does not match the "
           "instruction");

    auto ast = ctx->getAstContext();
    auto prev_constraints = ast->equal(ast->bvtrue(), ast->bvtrue());

    for (u64 i = 0; i < ctx->getPathConstraints().size() - 1; i++) {
        prev_constraints =
            ast->land(prev_constraints,
                      ctx->getPathConstraints().at(i).getTakenPredicate());
    }

    for (const auto &[taken, src, dest, constr] : pc.getBranchConstraints()) {
        if (!taken) {
            auto final_expr = ast->land(prev_constraints, constr);
            auto model = ctx->getModel(final_expr);
            logger::Debug("Done.");
            if (model.empty()) {
                logger::Debug("No solution found! Will never go to 0x%llx",
                              dest);
                return false;
            }
            for (const auto &[_, m] : model) {
                auto val = m.getValue();
                auto var = ctx->getSymbolicVariable(m.getVariable()->getId());
                m.getVariable()->setComment(instr->getDisassembly());

                logger::log << "Set " << var << " = " << val << "\n";
                switch (var->getType()) {
                    case triton::engines::symbolic::MEMORY_VARIABLE: {
                        auto addr = var->getOrigin();
                        auto size = var->getSize() / 8;
                        logger::log << "Update memory: 0x" << std::hex << addr
                                    << " = " << static_cast<u64>(val) << "\n";
                        ctx->setConcreteMemoryAreaValue(addr, &val, size);
                        ctx->symbolizeMemory(addr, size);
                    } break;
                    case triton::engines::symbolic::REGISTER_VARIABLE: {
                        logger::Error(
                            "Register concretized during model "
                            "calculation. I "
                            "think this should never happen");
                        auto reg = ctx->getRegister(
                            static_cast<triton::arch::register_e>(
                                var->getOrigin()));
                        logger::log << "Update register: " << reg << " = "
                                    << static_cast<u64>(val) << "\n";
                        ctx->setConcreteRegisterValue(reg, val);
                        ctx->symbolizeRegister(reg);
                        reg_override.insert(
                            {instr->getAddress(),
                             {static_cast<triton::arch::register_e>(
                                  var->getOrigin()),
                              static_cast<u64>(val)}});
                    } break;
                    default:
                        UNREACHABLE
                }
            }
        }
    }

    return true;
}

static std::vector<std::vector<u8>> used_inputs{{
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0,
}};
std::unique_ptr<triton::Context> ExploreAlternativeBranch(
    triton::arch::Instruction &instr, triton::Context *ctx, u64 step_count) {
    assert(instr.isBranch());
    assert(instr.isSymbolized());

    bool taken = instr.isConditionTaken();

    auto new_ctx = SnapshotContext(ctx, step_count);
    if (!new_ctx) return nullptr;

    auto constraints = new_ctx->getPathConstraints();
    if (constraints.empty()) {
        logger::Warn("No constraints in context. This should never happen");
        return nullptr;
    }

    auto path_constraint = constraints.back();
    if (!path_constraint.isMultipleBranches()) {
        logger::Debug("Constraint creates a single branch");
        return nullptr;
    }

    logger::Debug("Solving alternative model");
    if (!SolveFormula(new_ctx.get(), instr.getAddress(), &instr))
        return nullptr;
    PrintRes(new_ctx.get());

    NegateInstructionFlags(new_ctx.get(), &instr);

    u64 patched_addr{};

    triton::ast::SharedAbstractNode new_constraint = nullptr;
    for (const auto &[is_taken, src, dest, constr] :
         new_ctx->getPathConstraints().back().getBranchConstraints()) {
        logger::Debug("Visiting constraint 0x%llx", src);
        if (is_taken == taken) {
            logger::Debug("Skip %s (is visited by parent ctx)",
                          constr->str().c_str());
            continue;
        }
        if (dest == 0) {
            logger::Debug("No branching really happens here");
            return nullptr;
        }
        new_constraint = constr;
        break;
    }

    if (new_constraint) {
        new_ctx->popPathConstraint();
        new_ctx->pushPathConstraint(new_constraint);
    }

    PrintSymMem(ctx);
    PrintSymMem(new_ctx.get());

    return new_ctx;
}

struct ContextHolder {
    std::unique_ptr<triton::Context> ctx;
    u64 ip;
    u64 step_count;
};

std::string Solve(const Target *target,
                  const std::vector<static_analysis::CFGNode *> &path) {
    u64 dest = path.back()->block.address;
    first_ip = target->GetFunctionFirstAddress(path.front()->block.address);
    std::vector<u64> important;
    g_target = target;
    for (const auto node : path) {
        for (const auto &edge : node->out_edges) {
            if (node->out_edges.front().type !=
                static_analysis::CFGEdgeType::Jcc) {
                continue;
            }
            auto new_path =
                target->cfg.FindPath(edge.target->block.address, dest);
            if (new_path.empty()) {
                important.push_back(node->block.address);
                continue;
            }
        }
    }
    for (const auto addr : important) {
        logger::Info("Node 0x%llx is IMPORTANT", addr);
    }

    auto base_ctx = MakeDefaultContext();
    std::deque<ContextHolder> ctx_queue;
    ctx_queue.push_front({
        .ctx = std::move(base_ctx),
        .ip = first_ip,
        .step_count = 0,
    });
    triton::Context *final_ctx = nullptr;

    logger::Info("First address: 0x%llx", first_ip);
    logger::Info("Destination address: 0x%llx", dest);

    u64 step_count = 0;
    while (true) {
        if (ctx_queue.empty()) {
            logger::Warn("Ran out of context entries. Unable find solution");
            break;
        }

        u64 iter_step_count = 0;
        auto &it = ctx_queue.back();
        u64 local_step_count = it.step_count;
        auto ip = it.ip;
        auto ctx_ptr = std::move(it.ctx);
        ctx_queue.pop_back();
        auto ctx = ctx_ptr.get();
        u64 prev_ip = ip;
        bool solution_found = false;
        u64 ctx_id = ctx_queue.size();
        std::set<u64> touched{};

        logger::Okay("Enter context #%u at 0x%llx", ctx_id, ip);
        PrintSymMem(ctx);

        if (!target->disassembly.instr_map.contains(ip)) {
            logger::Error("There is no instruction at 0x%llx", ip);
            continue;
        }
        do {
            touched.insert(ip);
            triton::arch::Instruction instruction{};
            step_count++;
            local_step_count++;
            if (reg_override.contains(ip)) {
                auto &[reg, val] = reg_override.at(ip);
                ctx->setConcreteRegisterValue(ctx->getRegister(reg), val);
            }
            logger::Debug("Step %u Ctx %u", step_count, ctx_id);
            auto instr = target->disassembly.instr_map.at(ip);
            if (instr->id == X86_INS_DIV &&
                instr->detail->x86.operands[0].reg == X86_REG_CH) {
                ip += instr->size;
                continue;
            }
            instruction.setAddress(instr->address);
            instruction.setSize(instr->size);
            instruction.setOpcode(instr->bytes, instr->size);
            ctx->processing(instruction);

            if (ip == dest) {
                logger::Okay("Reached target! Enter");
                solution_found = true;
                PrintSymMem(ctx);
                auto res_bytes = ctx->getSymbolicMemoryAreaValue(
                    source_addr, source_mem_size);
                std::string result{res_bytes.begin(), res_bytes.end()};
                return utils::UnescapeString(result);
                break;
            }

            PrintDebugInfo(instruction, ctx);
            if (DoInstrStuff(ctx, &instruction, instr, &ip)) continue;
            PrintRes(ctx);
#ifdef X86_BUILD
            auto next_ip = static_cast<u64>(
                ctx->getSymbolicRegisterValue(ctx->registers.x86_eip));
#else
            auto next_ip = static_cast<u64>(
                ctx->getSymbolicRegisterValue(ctx->registers.x86_rip));
#endif
            if (!target->disassembly.instr_map.contains(next_ip)) {
                logger::Error(
                    "Tried to go to invalid address 0x%llx (from 0x%llx)",
                    next_ip, ip);
                for (const auto &addr : touched) {
                    // reg_override.erase(addr);
                }
                break;
            }

            prev_ip = ip;
            ip = next_ip;
            if (!instruction.isSymbolized() || !instruction.isBranch())
                continue;

            logger::Okay("New Symbolic branch found at 0x%llx", prev_ip);

            u64 addr1 = instruction.getNextAddress();
            u64 addr2 = instruction.operands[0].getImmediate().getValue();

            logger::Debug(
                "Symbolic branch: 0x%llx or 0x%llx. Will go to 0x%llx", addr1,
                addr2, (instruction.isConditionTaken() ? addr2 : addr1));

            auto cond_ctx =
                ExploreAlternativeBranch(instruction, ctx, local_step_count);

            if (cond_ctx) {
                logger::Debug("Push alternative ctx and switch to it");
                // Push current context because we want to return to it
                // later
                ctx_queue.push_back({
                    .ctx = std::move(ctx_ptr),
                    .ip = (instruction.isConditionTaken() ? addr2 : addr1),
                    .step_count = local_step_count,
                });
                // Invert address for new context because we want to explore
                // alternative branch
                ctx_queue.push_back({
                    .ctx = std::move(cond_ctx),
                    (instruction.isConditionTaken() ? addr1 : addr2),
                    .step_count = local_step_count,
                });
                break;
            }
        } while (true);

        if (solution_found) {
            final_ctx = ctx;
            break;
        }
    }
    logger::Debug("Ran %u instructions", step_count);

    logger::Error("Failed to find solution");
    return "";
}
}  // namespace core::dynamic::solver
