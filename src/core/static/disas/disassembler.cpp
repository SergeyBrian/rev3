#include "disassembler.hpp"

#include "../../../utils/logger.hpp"
#include "capstone/x86.h"

#include <regex>
#include <stdexcept>
#include <string>
#include <sstream>
#include <queue>
#include <set>

#include <capstone/capstone.h>

#ifdef X86_BUILD
#define ACTIVE_CS_MODE CS_MODE_32
#else
#define ACTIVE_CS_MODE CS_MODE_64
#endif

namespace core::static_analysis::disassembler {
static const u64 MaxRegSearchOffset = 10;

u64 SolveMemAddress(const cs_insn *instr);
void PrintUnsafe(const cs_insn *instr, u64 count);

bool CreatesBranch(x86_insn instr) {
    switch (instr) {
        case X86_INS_JO:
        case X86_INS_JNO:
        case X86_INS_JB:
        case X86_INS_JAE:
        case X86_INS_JE:
        case X86_INS_JNE:
        case X86_INS_JBE:
        case X86_INS_JA:
        case X86_INS_JS:
        case X86_INS_JNS:
        case X86_INS_JP:
        case X86_INS_JNP:
        case X86_INS_JL:
        case X86_INS_JGE:
        case X86_INS_JLE:
        case X86_INS_LJMP:
        case X86_INS_JMP:
        case X86_INS_CALL:
        case X86_INS_LCALL:
            return true;
        default:
            return false;
    }
}

void Conflict::Print() {
    printf("%s%64s%s\n", COLOR_RED, "=== CONFLICT ===", COLOR_RESET);
    for (u64 i = 0; i < std::max(ours_size, theirs_size); i++) {
        printf("%s 0x%llx%s %s%-10s %-40s\t%s0x%llx%s %s%-10s %-40s\n",
               COLOR_GRAY, (i > ours_size) ? 0x0 : ours[i].address, COLOR_RESET,
               (i < ours_size && bad_instructions.contains(ours[i].address))
                   ? COLOR_RED
                   : COLOR_RESET,
               (i >= ours_size) ? "..." : ours[i].mnemonic,
               (i >= ours_size) ? "..." : ours[i].op_str, COLOR_GRAY,
               (i >= theirs_size) ? 0x0 : theirs[i].address, COLOR_RESET,
               (i < theirs_size && bad_instructions.contains(theirs[i].address))
                   ? COLOR_RED
                   : COLOR_RESET,
               (i >= theirs_size) ? "..." : theirs[i].mnemonic,
               (i >= theirs_size) ? "..." : theirs[i].op_str);
    }
    printf("%s\n", COLOR_RESET);
}

void Conflict::GuessResolution(BinInfo *bin) {
    u64 our_problems{};
    u64 their_problems{};

    FindSuspiciousInstructions(ours, ours_size, bin);
    our_problems = bad_instructions.size();
    FindSuspiciousInstructions(theirs, theirs_size, bin);
    their_problems = bad_instructions.size() - our_problems;

    if (our_problems > their_problems) {
        accept = Accept::Theirs;
    } else if (their_problems > our_problems) {
        accept = Accept::Ours;
    } else {
        accept = Accept::Theirs;
        return;
        this->Print();
        logger::Warn("Can't automatically resolve this conflict :(");
        u32 input{};
        while (input < 1 || input > 2) {
            std::cout << input << "\n";
            std::cout
                << "Please choose left or right option by entering 1 or 2: ";
            std::cin >> input;
        }
        accept = static_cast<Accept>(input);
    }
}

bool IsSuspicious(cs_insn *instr, BinInfo *bin) {
    switch (static_cast<x86_insn>(instr->id)) {
        // Legacy BCD
        case X86_INS_SBB:
        case X86_INS_AAA:
        case X86_INS_AAD:
        case X86_INS_AAM:
        case X86_INS_AAS:
        case X86_INS_DAA:
        case X86_INS_DAS:
        // Floating point instructions replaced with stdlib calls
        case X86_INS_F2XM1:
        case X86_INS_FPTAN:
        case X86_INS_FPATAN:
        case X86_INS_FSIN:
        case X86_INS_FCOS:
        case X86_INS_FSINCOS:
        case X86_INS_FPREM:
        case X86_INS_FPREM1:
        case X86_INS_FYL2X:
        case X86_INS_FYL2XP1:
        // Unused array bounds checking instruction
        case X86_INS_BOUND:
        // 16-bit mode specific
        case X86_INS_ENTER:
        case X86_INS_LOOP:
        case X86_INS_LOOPE:
        case X86_INS_LOOPNE:
        // Legacy
        case X86_INS_XLATB:
        case X86_INS_WAIT:
        case X86_INS_PUSHAL:
        case X86_INS_PUSHAW:
        case X86_INS_POPAW:
        case X86_INS_POPAL:
        // System instructions
        case X86_INS_SGDT:
        case X86_INS_SIDT:
        case X86_INS_SLDT:
        case X86_INS_SMSW:
        case X86_INS_LMSW:
        case X86_INS_IN:
        case X86_INS_OUT:
        case X86_INS_WBINVD:
        case X86_INS_INVD:
        case X86_INS_SYSENTER:
        case X86_INS_SYSCALL:
        case X86_INS_SYSRET:
        case X86_INS_VMXON:
        case X86_INS_VMXOFF:
            return true;
        default:
            break;
    }
    if (CreatesBranch(static_cast<x86_insn>(instr->id))) {
        u64 addr = GetTargetAddress(instr, bin);
        if (addr != 0 && !bin->IsValidPtr(addr)) {
            logger::Warn("0x%llx is invalid ptr", addr);
            return true;
        }
    }

    return false;
}

void Conflict::FindSuspiciousInstructions(cs_insn *insn, usize size,
                                          BinInfo *bin) {
    for (u64 i = 0; i < size; i++) {
        if (IsSuspicious(&insn[i], bin)) {
            bad_instructions[insn[i].address] = true;
        }
    }
}

Err Disassembly::deep_disassemble(const byte *ptr, usize size, BinInfo *bin) {
    Err err{};

    logger::Info("Doing deep disassembly");

    u64 entrypoint = bin->EntryPoint();
    if (entrypoint == 0) {
        logger::Error(
            "Deep disassembly failed. You can disable it with "
            "'--no-disasm-fix' flag");
        return Err::InvalidEntrypoint;
    }

    const u64 text_base = 0x1000;
    u64 cur_offset = entrypoint;
    std::queue<u64> queue{};
    std::set<u64> visited{};
    queue.push(cur_offset);
    cs_insn *insns{};
    u64 instr_count{};
    bool can_free = false;
    u64 disasm_count = 0;
    std::set<u64> resolved{};

    while (!queue.empty()) {
        cur_offset = queue.front();
        queue.pop();
        if (cur_offset >= text_base + size) {
            continue;
        }
        if (visited.contains(cur_offset)) {
            continue;
        }
        visited.insert(cur_offset);
        if (can_free && insns) {
            // cs_free(insns, instr_count);
            insns = nullptr;
        }
        can_free = true;

        if (instr_map.contains(cur_offset)) {
            auto it = instr_map.lower_bound(cur_offset);
            while (it != instr_map.end()) {
                auto [addr, cur_insn] = *it;
                if (CreatesBranch(static_cast<x86_insn>(cur_insn->id))) {
                    u64 target_addr = GetTargetAddress(cur_insn, bin);
                    if (target_addr) {
                        queue.push(target_addr);
                    }
                }
                it++;
            }
        } else {
            logger::Info("Trying to disassemble code starting from 0x%llx",
                         cur_offset);
            logger::Debug("Offset is 0x%llx", cur_offset - text_base);
            logger::Debug("Base addr is 0x%llx", cur_offset);
            instr_count = cs_disasm(handle, ptr + cur_offset - text_base,
                                    size - (cur_offset - text_base), cur_offset,
                                    0, &insns);
            disasm_count++;
            if (instr_count == 0) {
                logger::Error(
                    "Deep disassembly failed. You can disable it with "
                    "'--no-disasm-fix' flag");
                return Err::DisassemblerError;
            }

            Conflict conflict{};

            for (u64 i = 0; i < instr_count; i++) {
                cs_insn cur_insn = insns[i];
                if (!IsCovered(cur_insn.address)) {
                    can_free = false;
                    logger::Warn(
                        "Instruction at 0x%llx is not covered by existing "
                        "disassembly",
                        cur_insn.address);
                    u64 new_range_start = cur_insn.address;
                    u64 new_range_end = cur_insn.address + cur_insn.size;
                    u64 restore_i = i - 1;
                    while (i < instr_count && !IsCovered(cur_insn.address)) {
                        cur_insn = insns[i];
                        new_range_end = cur_insn.address + cur_insn.size;
                        instr_map[cur_insn.address] = &insns[i];
                        i++;
                    }
                    covered_bytes[new_range_start] = new_range_end;
                    logger::Debug(
                        "Inserted new coverage range 0x%llx -> 0x%llx",
                        new_range_start, new_range_end);
                    i = restore_i;
                    logger::Debug("Processing the discovered disassembly");
                    continue;
                }
                if (!resolved.contains(cur_insn.address) &&
                    !instr_map.contains(cur_insn.address)) {
                    can_free = false;
                    if (conflict.addr == 0) {
                        logger::Debug("New conflict");
                        conflict.addr = cur_insn.address;
                        conflict.theirs = &insns[i];
                        while (!instr_map.contains(conflict.addr)) {
                            conflict.addr--;
                        }
                        conflict.ours =
                            instr_map.lower_bound(conflict.addr)->second;
                        logger::Debug("Ours: %s %s", conflict.ours->mnemonic,
                                      conflict.ours->op_str);
                    }
                    logger::Debug(
                        "0x%llx ~~> 0x%llx (cur = 0x%llx)",
                        conflict.theirs[conflict.theirs_size].address,
                        conflict.theirs[conflict.theirs_size].address +
                            conflict.theirs[conflict.theirs_size].size,
                        cur_insn.address);
                    while (
                        conflict.ours[conflict.ours_size].address >=
                            text_base &&
                        ((conflict.ours[conflict.ours_size].address >
                              conflict.theirs[conflict.theirs_size].address &&
                          conflict.ours[conflict.ours_size].address <
                              conflict.theirs[conflict.theirs_size].address +
                                  conflict.theirs[conflict.theirs_size].size) ||
                         ((conflict.ours[conflict.ours_size].address <
                               conflict.theirs[conflict.theirs_size].address &&
                           conflict.ours[conflict.ours_size].address +
                                   conflict.ours[conflict.ours_size].size <=
                               conflict.theirs[conflict.theirs_size].address +
                                   conflict.theirs[conflict.theirs_size]
                                       .size)))) {
                        logger::Debug(
                            "0x%llx %s %s conflicts with 0x%llx",
                            conflict.ours[conflict.ours_size].address,
                            conflict.ours[conflict.ours_size].mnemonic,
                            conflict.ours[conflict.ours_size].op_str,
                            conflict.theirs[conflict.theirs_size].address);
                        conflict.ours_size++;
                    }
                    conflict.theirs_size++;
                    can_free = false;
                    logger::Warn(
                        "Anomaly found: disassembly mismatch at 0x%llx (this "
                        "address does not appear in original disassembly)",
                        cur_insn.address);
                    logger::Warn("%s %s", cur_insn.mnemonic, cur_insn.op_str);
                } else if (conflict.addr != 0) {
                    logger::Okay("Conflict is over at 0x%llx %s %s",
                                 cur_insn.address, cur_insn.mnemonic,
                                 cur_insn.op_str);
                    can_free = false;
                    conflict.GuessResolution(bin);
                    ApplyConflictResolution(conflict);
                    resolved.insert(conflict.addr);
                    conflict.Print();
                    conflict = {};
                }
                if (CreatesBranch(static_cast<x86_insn>(cur_insn.id))) {
                    u64 target_addr = GetTargetAddress(&cur_insn, bin);
                    if (target_addr) {
                        queue.push(target_addr);
                    }
                }
            }
            if (conflict.addr != 0) {
                can_free = false;
                conflict.GuessResolution(bin);
                ApplyConflictResolution(conflict);
                resolved.insert(conflict.addr);
                conflict.Print();
            }
        }
    }

    logger::Warn("Program was disassembled %d times", disasm_count);

    return err;
}

void Disassembly::ApplyConflictResolution(const Conflict &conflict) {
    if (conflict.accept == Conflict::Accept::Unknown) {
        logger::Error("Attempted to apply unresolved conflict");
    } else {
        logger::Debug(
            "Conflict at 0x%llx resolved in favor of %s", conflict.addr,
            (conflict.accept == Conflict::Accept::Ours) ? "ours" : "theirs");
    }
    if (conflict.accept != Conflict::Accept::Theirs) return;
    for (u64 i = 0; i < conflict.ours_size; i++) {
        logger::Debug("Removing 0x%llx", conflict.ours[i].address);
        instr_map.erase(conflict.ours[i].address);
        count--;
    }
    for (u64 i = 0; i < conflict.theirs_size; i++) {
        logger::Debug("inserting %s %s at 0x%llx", conflict.theirs[i].mnemonic,
                      conflict.theirs[i].op_str, conflict.theirs[i].address);
        instr_map[conflict.theirs[i].address] = &conflict.theirs[i];
        count++;
    }
}

Err Disassembly::Disassemble(const byte *ptr, usize size, BinInfo *bin) {
    Err err{};
    ResetCache();

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    u64 offset = 0x1000;
    count = cs_disasm(handle, ptr, size, offset, 0, &instructions);
    if (count == 0) {
        return Err::DisassemblerError;
    }
    logger::Okay("Disassembly finished. %d instructions found", count);
    for (u64 i = 0; i < count; i++) {
        instr_map[instructions[i].address] = &instructions[i];
    }
    cs_insn last_instr = instructions[count - 1];
    covered_bytes[offset] = last_instr.address + last_instr.size;
    logger::Debug("Initially covered bytes:");
    for (const auto &[start, end] : covered_bytes) {
        logger::Debug("0x%llx -> 0x%llx", start, end);
    }

    if (!config::Get().do_disasm_fixes) {
        return err;
    }

    err = deep_disassemble(ptr, size, bin);
    if (err != Err::Ok) return err;

    logger::Debug("Covered bytes:");
    for (const auto &[start, end] : covered_bytes) {
        logger::Debug("0x%llx -> 0x%llx", start, end);
    }
    logger::Debug("Expected last byte: 0x%llx", offset + size);

    return err;
}

bool Disassembly::IsCovered(u64 addr) {
    auto it = covered_bytes.upper_bound(addr);
    it--;
    return it->second >= addr;
}

Disassembly::Disassembly() {
    if (cs_open(CS_ARCH_X86, ACTIVE_CS_MODE, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize capstone");
    }
}

void Disassembly::RegAccess(const cs_insn *instr, cs_regs reg_write,
                            u8 *reg_write_count, cs_regs reg_read,
                            u8 *reg_read_count) {
    if (reg_write == nullptr) {
        cs_regs dummy{};
        u8 dummy_count{};
        cs_regs_access(handle, instr, reg_read, reg_read_count, dummy,
                       &dummy_count);
    } else if (reg_read == nullptr) {
        cs_regs dummy{};
        u8 dummy_count{};
        cs_regs_access(handle, instr, dummy, &dummy_count, reg_write,
                       reg_write_count);
    } else {
        cs_regs_access(handle, instr, reg_read, reg_read_count, reg_write,
                       reg_write_count);
    }
}

void Disassembly::RegAccess(u64 instr_addr, cs_regs reg_write,
                            u8 *reg_write_count, cs_regs reg_read,
                            u8 *reg_read_count) {
    assert(reg_write != nullptr || reg_read != nullptr && "WTF are you doing");
    RegAccess(instr_map.at(instr_addr), reg_write, reg_write_count, reg_read,
              reg_read_count);
}

void PrintUnsafe(const cs_insn *instr, u64 count) {
    while (count--) {
        logger::Printf("0x%" PRIx64 ":\t%s\t\t%s", instr->address,
                       instr->mnemonic, instr->op_str);
        instr++;
    }
}

void Disassembly::Print(u64 addr, u64 count) {
    auto it = instr_map.lower_bound(addr);
    while (count-- && it != instr_map.end()) {
        const auto &[_, instr] = *it;
        logger::Printf("0x%" PRIx64 ":\t%s\t\t%s", instr->address,
                       instr->mnemonic, instr->op_str);
        it++;
    }
}

i64 ParseOffsetPtr(const char *opstr) {
    try {
        std::string input(opstr);
        std::regex re(R"(\[\s*[^\[\]]*\s*([\+\-])\s*0x([0-9a-fA-F]+)\s*\])");
        std::smatch match;

        if (std::regex_search(input, match, re) && match.size() > 2) {
            char sign = match[1].str()[0];
            std::stringstream ss;
            ss << std::hex << match[2].str();
            i64 offset;
            ss >> offset;

            return (sign == '-') ? -offset : offset;
        }
    } catch (const std::exception &exception) {
        logger::Error("%s", exception.what());
    }

    return 0;
}

u64 FindRegValue(x86_reg reg, const cs_insn *instr) {
    for (u64 i = 0; i < MaxRegSearchOffset; i++, instr--) {
        if (!strstr(instr->mnemonic, "mov") &&
            !strstr(instr->mnemonic, "lea")) {
            continue;
        }
        auto x86 = instr->detail->x86;
        if (x86.operands[0].type != X86_OP_REG) continue;
        if (x86.operands[1].type != X86_OP_IMM &&
            x86.operands[1].type != X86_OP_REG) {
            continue;
        }
        if (x86.operands[0].reg != reg) continue;
        if (x86.operands[1].type == X86_OP_IMM) {
            return x86.operands[1].imm;
        }
        return FindRegValue(x86.operands[1].reg, instr - 1);
    }

    return 0;
}

u64 SolveMemAddress(const cs_insn *instr) {
    cs_x86_op op{};
    for (u8 i = 0; i < instr->detail->x86.op_count; i++) {
        op = instr->detail->x86.operands[i];
        if (op.type == X86_OP_MEM) break;
    }
    auto reg = op.mem.base;
    auto disp = op.mem.disp;
    auto index = op.mem.index;
    auto scale = op.mem.scale;

    u64 reg_val{};
    u64 index_val{};

    if (reg == X86_REG_INVALID) {
        reg_val = 0;
    } else if (reg == X86_REG_RIP) {
        reg_val = instr->address + instr->size;
    } else {
        reg_val = FindRegValue(reg, instr);
        if (!reg_val) return 0;
    }

    if (index == X86_REG_INVALID) {
        index_val = 0;
    } else if (index == X86_REG_RIP) {
        index_val = instr->address + instr->size;
    } else {
        index_val = FindRegValue(index, instr);
        if (!index_val) return 0;
    }

    u64 res = reg_val + index_val * scale + disp;
    return res;
}

u64 SolveMemValue(const cs_insn *instr, BinInfo *bin) {
    u64 mem_addr = SolveMemAddress(instr);
    if (!mem_addr) return 0;

    const u8 *mem = bin->Data(mem_addr, 8);
    if (!mem) {
        logger::Warn("Failed to read memory at 0x%llx", mem_addr);
        return 0;
    }
    return *reinterpret_cast<const u64 *>(mem);
}

static std::map<u64, u64> target_address_cache{};
u64 GetTargetAddress(const cs_insn *instr, BinInfo *bin) {
    if (target_address_cache.contains(instr->address)) {
        return target_address_cache.at(instr->address);
    }

    auto op = instr->detail->x86.operands[0];
    u64 result{};
    bool relative = false;

    switch (static_cast<x86_insn>(instr->id)) {
        case X86_INS_JO:
        case X86_INS_JNO:
        case X86_INS_JB:
        case X86_INS_JAE:
        case X86_INS_JE:
        case X86_INS_JNE:
        case X86_INS_JBE:
        case X86_INS_JA:
        case X86_INS_JS:
        case X86_INS_JNS:
        case X86_INS_JP:
        case X86_INS_JNP:
        case X86_INS_JL:
        case X86_INS_JGE:
        case X86_INS_JLE:
        case X86_INS_LJMP:
        case X86_INS_JMP:
            relative = true;
        default:
            relative = false;
    }

    switch (op.type) {
        case X86_OP_INVALID:
            logger::Warn("Invalid operand in %s %s", instr->mnemonic,
                         instr->op_str);
            result = 0;
            break;
        case X86_OP_REG: {
            auto reg = op.reg;
            result = FindRegValue(reg, instr);
            break;
        }
        case X86_OP_IMM:
            result = op.imm;
            break;
        case X86_OP_MEM:
            result = SolveMemValue(instr, bin);
            break;
        default:
            result = 0;
            break;
    }

    if (result && relative) result += instr->address + instr->size;

    target_address_cache[instr->address] = result;
    return result;
}

// TODO: move cache into the Disassembly class
void ResetCache() { target_address_cache.clear(); }

void Disassembly::PrintCoverage(size_t expected_size) {
    printf("%s%76s%s\n", COLOR_GREEN,
           "=== DISASSEMBLY COVERAGE ===", COLOR_RESET);
    static const size_t BAR_WIDTH = 120;

    std::cout << "[";
    for (size_t i = 0; i < BAR_WIDTH; i++) {
        uint64_t offset =
            static_cast<uint64_t>((double)i / BAR_WIDTH * expected_size);
        if (IsCovered(offset)) {
            std::cout << COLOR_GREEN << "=" << COLOR_RESET;
        } else {
            std::cout << COLOR_RED << "=" << COLOR_RESET;
        }
    }
    std::cout << "]\n";

    std::string carets(BAR_WIDTH + 2, ' ');
    carets.front() = '[';
    carets.back() = ']';

    std::string addresses(BAR_WIDTH + 2, ' ');
    addresses.front() = '[';
    addresses.back() = ']';

    std::vector<std::pair<size_t, uint64_t>> markers;
    markers.reserve(covered_bytes.size() * 2);

    for (auto &kv : covered_bytes) {
        uint64_t start = kv.first;
        uint64_t end = kv.second;

        size_t startPos =
            static_cast<size_t>((double)start / expected_size * BAR_WIDTH);
        size_t endPos =
            static_cast<size_t>((double)end / expected_size * BAR_WIDTH);

        if (startPos >= BAR_WIDTH) startPos = BAR_WIDTH - 1;
        if (endPos >= BAR_WIDTH) endPos = BAR_WIDTH - 1;

        markers.emplace_back(startPos, start);
        markers.emplace_back(endPos, end);
    }

    std::sort(markers.begin(), markers.end(),
              [](auto &a, auto &b) { return a.first < b.first; });

    auto placeStringWithShift = [&](std::string &str, size_t pos,
                                    const std::string &txt) {
        size_t i = pos;
        while (true) {
            if (i + txt.size() >= str.size()) {
                return;
            }
            bool canPlace = true;
            for (size_t j = 0; j < txt.size(); j++) {
                if (str[i + j] != ' ') {
                    canPlace = false;
                    break;
                }
            }
            if (canPlace) {
                for (size_t j = 0; j < txt.size(); j++) {
                    str[i + j] = txt[j];
                }
                return;
            }
            i++;
        }
    };

    for (auto &[pos, addr] : markers) {
        size_t index = pos + 1;
        std::stringstream ss;
        ss << std::hex << "0x" << addr;

        placeStringWithShift(carets, index, "^");
        placeStringWithShift(addresses, index, ss.str());
    }

    std::cout << carets << "\n";
    std::cout << addresses << "\n";
}
}  // namespace core::static_analysis::disassembler
