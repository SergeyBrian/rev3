#include "solver.hpp"
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
};

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

bool IsAddressReachable(u64 from, u64 to,
                        const static_analysis::ControlFlowGraph *g) {
    return !g->FindPath(from, to).empty();
}

void SnapshotContext(triton::Context *dst, triton::Context *src) {
    /* Synch concrete state */
    switch (src->getArchitecture()) {
        case triton::arch::ARCH_X86_64:
            *static_cast<triton::arch::x86::x8664Cpu *>(dst->getCpuInstance()) =
                *static_cast<triton::arch::x86::x8664Cpu *>(
                    src->getCpuInstance());
            break;
        case triton::arch::ARCH_X86:
            *static_cast<triton::arch::x86::x86Cpu *>(dst->getCpuInstance()) =
                *static_cast<triton::arch::x86::x86Cpu *>(
                    src->getCpuInstance());
            break;
        default:
            throw triton::exceptions::Engines(
                "SnapshotContext(): Invalid architecture");
    }

    /* Synch symbolic register */
    dst->concretizeAllRegister();
    for (const auto &item : src->getSymbolicRegisters()) {
        dst->assignSymbolicExpressionToRegister(item.second,
                                                dst->getRegister(item.first));
    }

    /* Synch symbolic memory */
    dst->concretizeAllMemory();
    for (const auto &item : src->getSymbolicMemory()) {
        dst->assignSymbolicExpressionToMemory(
            item.second,
            triton::arch::MemoryAccess(item.first, triton::size::byte));
    }

    /* Synch path predicate */
    dst->clearPathConstraints();
    for (const auto &pc : src->getPathConstraints()) {
        dst->pushPathConstraint(pc);
    }
}

[[nodiscard]] std::unique_ptr<triton::Context> MakeDefaultContext() {
    auto ctx = std::make_unique<triton::Context>();
    ctx->setArchitecture(triton::arch::ARCH_X86);

    std::vector<u8> data = {
        0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x47, 0x31, 0x45,
        0x43, 0x50, 0x4B, 0x4E, 0x3E, 0x43, 0x4E, 0x31, 0x38, 0x47, 0x3B, 0x45,
        0x44, 0x38, 0x52, 0x51, 0x44, 0x3A, 0x3D, 0x37, 0x3A, 0x40, 0x3B, 0x37,
        0x4D, 0x54, 0x45, 0x44, 0x51, 0x41, 0x4B, 0x32, 0x53, 0x47, 0x4D, 0x35,
        0x3A, 0x49, 0x48, 0x4E, 0x51, 0x3E, 0x41, 0x45, 0x4D, 0x32, 0x00};

    ctx->setConcreteMemoryAreaValue(0x41EDD0, data.data(), data.size());

    std::vector<u8> data2 = {
        0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x30, 0x31, 0x32, 0x33, 0x32,
        0x31, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x31, 0x33, 0x32,
        0x30, 0x33, 0x31, 0x33, 0x30, 0x33, 0x33, 0x30, 0x31, 0x31, 0x30,
        0x30, 0x30, 0x33, 0x31, 0x33, 0x33, 0x30, 0x31, 0x31, 0x33, 0x33,
        0x30, 0x30, 0x33, 0x32, 0x31, 0x32, 0x00, 0x00};

    ctx->setConcreteMemoryAreaValue(0x41EE0C, data2.data(), data2.size());

    std::vector<u8> data3 = {0x53, 0x8D, 0x51, 0x65, 0x72, 0x52, 0x98, 0x18,
                             0xA4, 0x65, 0xA7, 0x6E, 0x61, 0x62, 0x9D, 0x64,
                             0x37, 0x36, 0x72, 0x14, 0x08, 0x44, 0x73, 0x6D,
                             0x37, 0x5D, 0x64, 0x2E, 0x31, 0x07, 0x63, 0x34,
                             0x1A, 0x1B, 0x18, 0x17, 0x38, 0x00, 0x00, 0x00};

    ctx->setConcreteMemoryAreaValue(0x41EE40, data3.data(), data3.size());

    ctx->setConcreteRegisterValue(ctx->registers.x86_esp, 0x600000);
    ctx->setConcreteMemoryAreaValue(0x600004, {0x00, 0x00, 0x70, 0x00});
    std::vector<u8> default_str = {
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
        'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0,
    };
    assert(default_str.size() == 38);
    ctx->setConcreteMemoryAreaValue(0x700000, default_str.data(),
                                    default_str.size());
    // This is memory where user input is assumed to be stored
    ctx->symbolizeMemory(0x700000, 40);

    return ctx;
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

void PrintDebugInfo(triton::arch::Instruction &instr, triton::Context *ctx) {
    logger::Debug("===================");
    if (instr.isSymbolized()) logger::log << "syminstr: ";
    logger::log << COLOR_BLUE << instr << COLOR_RESET << "\n";
    auto regs = instr.getReadRegisters();
    if (!instr.isSymbolized()) return;

    for (const auto &[reg, expr] : regs) {
        if (!ctx->isRegisterSymbolized(reg)) continue;

        logger::Debug("%s", reg.getName().c_str());
    }

    for (const auto &[mem, expr] : instr.getLoadAccess()) {
        if (!ctx->isMemorySymbolized(mem)) continue;

        logger::Debug("0x%llx", mem.getAddress());
    }

    for (const auto &expr : instr.symbolicExpressions) {
        logger::log << expr << "\n";
    }
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

void SolveFormula(triton::Context *old_ctx, triton::Context *ctx, u64 ip) {
    auto pc = ctx->getPathConstraints().back();
    assert(std::get<1>(pc.getBranchConstraints()[0]) == ip &&
           "Programming error. Path constraint does not match the instruction");

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
                logger::Warn("No solution found! Will never go to 0x%llx",
                             dest);
                return;
            }
            for (const auto &[_, m] : model) {
                auto val = m.getValue();
                auto var =
                    old_ctx->getSymbolicVariable(m.getVariable()->getId());

                logger::log << "Set " << var << " = " << val << "\n";
                switch (var->getType()) {
                    case triton::engines::symbolic::MEMORY_VARIABLE: {
                        auto addr = var->getOrigin();
                        auto size = var->getSize() / 8;
                        logger::log << "Update memory: 0x" << std::hex << addr
                                    << "\n";
                        ctx->setConcreteMemoryAreaValue(addr, &val, size);
                    } break;
                    case triton::engines::symbolic::REGISTER_VARIABLE: {
                        logger::Error(
                            "Register concretized during model calculation. I "
                            "think this should never happen");
                        auto reg = ctx->getRegister(
                            static_cast<triton::arch::register_e>(
                                var->getOrigin()));
                        logger::log << "Update register: " << reg << "\n";
                        ctx->setConcreteRegisterValue(reg, val);
                    } break;
                    default:
                        UNREACHABLE
                }
            }
        }
    }
}

static std::vector<std::vector<u8>> used_inputs{{
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0,
}};
std::unique_ptr<triton::Context> ExploreAlternativeBranch(
    triton::arch::Instruction &instr, triton::Context *ctx) {
    assert(instr.isBranch());
    assert(instr.isSymbolized());

    auto constraints = ctx->getPathConstraints();
    if (constraints.empty()) {
        logger::Warn("No constraints in context. This should never happen");
        return nullptr;
    }

    auto path_constraint = constraints.back();
    if (!path_constraint.isMultipleBranches()) {
        logger::Debug("Constraint creates a single branch");
        return nullptr;
    }

    bool taken = instr.isConditionTaken();

    auto tmp_ctx = std::make_unique<triton::Context>(ctx->getArchitecture());
    SnapshotContext(tmp_ctx.get(), ctx);

    logger::Debug("Solving alternative model");
    SolveFormula(ctx, tmp_ctx.get(), instr.getAddress());

    NegateInstructionFlags(tmp_ctx.get(), &instr);

    u64 patched_addr{};

    triton::ast::SharedAbstractNode new_constraint;
    for (const auto &[is_taken, src, dest, constr] :
         tmp_ctx->getPathConstraints().back().getBranchConstraints()) {
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

    tmp_ctx->popPathConstraint();
    tmp_ctx->pushPathConstraint(new_constraint);

    ctx->clearPathConstraints();

    auto data = tmp_ctx->getSymbolicMemoryAreaValue(0x700000, 40);
    logger::log << COLOR_GREEN
                << utils::UnescapeString({data.begin(), data.end()})
                << COLOR_RESET << "\n";
    data = ctx->getSymbolicMemoryAreaValue(0x700000, 40);
    logger::log << COLOR_YELLOW
                << utils::UnescapeString({data.begin(), data.end()})
                << COLOR_RESET << "\n";
    if (utils::contains(used_inputs,
                        tmp_ctx->getSymbolicMemoryAreaValue(0x700000, 40))) {
        logger::Debug("Equivalent input was already explored");
        return nullptr;
    } else {
        logger::Debug("Patch applied 0x%llx", patched_addr);
    }
    used_inputs.push_back(tmp_ctx->getSymbolicMemoryAreaValue(0x700000, 40));

    return tmp_ctx;
}

std::string Solve(const Target *target,
                  const std::vector<static_analysis::CFGNode *> &path) {
    u64 dest = path.at(path.size() - 1)->block.address;
    std::vector<u64> important;
    /*std::vector<std::vector<static_analysis::CFGNode *>> alternative_paths{*/
    /*    path};*/
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
        logger::Debug("Node 0x%llx is IMPORTANT", addr);
    }

    u64 first_ip = 0x1450;

    auto base_ctx = MakeDefaultContext();
    std::deque<std::pair<u64, std::unique_ptr<triton::Context>>> ctx_queue;
    ctx_queue.push_front({first_ip, std::move(base_ctx)});
    triton::Context *final_ctx = nullptr;

    logger::Info("Destination address: 0x%llx", dest);

    u64 step_count = 0;
    while (true) {
        if (ctx_queue.empty()) {
            logger::Warn("Ran out of context entries. Unable find solution");
            break;
        }

        // auto &[ip, ctx_ptr] = ctx_queue.back();
        auto ctx_ptr = MakeDefaultContext();
        u64 ip = first_ip;
        auto ctx = ctx_ptr.get();
        u64 prev_ip = ip;
        bool solution_found = false;
        u64 ctx_id = ctx_queue.size();

        auto cur_input = used_inputs.front();
        ctx->setConcreteMemoryAreaValue(0x700000, cur_input);
        used_inputs.erase(used_inputs.begin());

        logger::Okay("Enter context #%u at 0x%llx", ctx_id, ip);
        auto data = ctx->getSymbolicMemoryAreaValue(0x700000, 40);
        ctx->symbolizeMemory(0x700000, 40);
        std::cout << "Trying " << COLOR_GREEN
                  << utils::UnescapeString({data.begin(), data.end()})
                  << COLOR_RESET << "\n";

        /*if (!IsAddressReachable(ip, dest, &target->cfg)) {*/
        /*    logger::Debug("Destination 0x%llx is unreachable from 0x%llx",
         * dest,*/
        /*                  ip);*/
        /*    ctx_stack.pop_back();*/
        /*    continue;*/
        /*}*/

        if (!target->disassembly.instr_map.contains(ip)) {
            logger::Error("There is no instruction at 0x%llx", ip);
            ctx_queue.pop_back();
            continue;
        }
        do {
            triton::arch::Instruction instruction{};
            step_count++;
            logger::Debug("Step %u Ctx %u", step_count, ctx_id);
            auto instr = target->disassembly.instr_map.at(ip);
            instruction.setAddress(instr->address);
            instruction.setSize(instr->size);
            instruction.setOpcode(instr->bytes, instr->size);
            ctx->processing(instruction);
            PrintDebugInfo(instruction, ctx);
            auto next_ip = static_cast<u64>(
                ctx->getSymbolicRegisterValue(ctx->registers.x86_eip));
            if (!target->disassembly.instr_map.contains(next_ip)) {
                logger::Error(
                    "Tried to go to invalid address 0x%llx (from 0x%llx)",
                    next_ip, ip);
                ctx_queue.pop_back();
                break;
            }

            if (ip == 0x15D9) {
                if (ctx->getSymbolicRegisterValue(ctx->registers.x86_eax)) {
                    logger::Okay("Reached target! Enter");
                    std::cout << "Success!\n"
                              << utils::UnescapeString(std::string{
                                     cur_input.begin(), cur_input.end()});
                    solution_found = true;
                } else {
                    logger::Error("Reached target with wrong result");
                    ctx_queue.pop_back();
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
            auto cond_ctx = ExploreAlternativeBranch(instruction, ctx);
            if (cond_ctx) {
                logger::Debug("Push alternative ctx");
                ctx_queue.push_front({addr2, std::move(cond_ctx)});
            }
            logger::Info("Symbolic branch: 0x%llx or 0x%llx. Will go to 0x%llx",
                         addr1, addr2,
                         (instruction.isConditionTaken() ? addr2 : addr1));
        } while (true);
        logger::Debug("Solution not found yet");

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
