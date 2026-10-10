#include "HookRelocator32.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace HookAsm {
    namespace {

        ZydisDecoder& GetDecoder()
        {
            static ZydisDecoder decoder;
            static bool inited = false;
            if (!inited) {
                ZydisDecoderInit(&decoder,
                    ZYDIS_MACHINE_MODE_LEGACY_32,
                    ZYDIS_STACK_WIDTH_32);
                inited = true;
            }
            return decoder;
        }

        int JccCondCode(ZydisMnemonic m)
        {
            switch (m) {
            case ZYDIS_MNEMONIC_JO:   return 0x0;
            case ZYDIS_MNEMONIC_JNO:  return 0x1;
            case ZYDIS_MNEMONIC_JB:   return 0x2;
            case ZYDIS_MNEMONIC_JNB:  return 0x3;
            case ZYDIS_MNEMONIC_JZ:   return 0x4;
            case ZYDIS_MNEMONIC_JNZ:  return 0x5;
            case ZYDIS_MNEMONIC_JBE:  return 0x6;
            case ZYDIS_MNEMONIC_JNBE: return 0x7;
            case ZYDIS_MNEMONIC_JS:   return 0x8;
            case ZYDIS_MNEMONIC_JNS:  return 0x9;
            case ZYDIS_MNEMONIC_JP:   return 0xA;
            case ZYDIS_MNEMONIC_JNP:  return 0xB;
            case ZYDIS_MNEMONIC_JL:   return 0xC;
            case ZYDIS_MNEMONIC_JNL:  return 0xD;
            case ZYDIS_MNEMONIC_JLE:  return 0xE;
            case ZYDIS_MNEMONIC_JNLE: return 0xF;
            default:                  return -1;
            }
        }

        bool IsLoopFamily(ZydisMnemonic m)
        {
            switch (m) {
            case ZYDIS_MNEMONIC_LOOP:
            case ZYDIS_MNEMONIC_LOOPE:
            case ZYDIS_MNEMONIC_LOOPNE:
            case ZYDIS_MNEMONIC_JCXZ:
            case ZYDIS_MNEMONIC_JECXZ:
                return true;
            default:
                return false;
            }
        }

        inline bool Uses16BitCounter(const Instruction& info)
        {
            return info.insn.address_width == 16;
        }

        size_t LoopExpandedLength(const Instruction& info)
        {
            const bool c16 = Uses16BitCounter(info);
            switch (info.insn.mnemonic) {
            case ZYDIS_MNEMONIC_LOOP:   return c16 ? 13 : 12;
            case ZYDIS_MNEMONIC_LOOPE:  return c16 ? 19 : 18;
            case ZYDIS_MNEMONIC_LOOPNE: return c16 ? 19 : 18;
            default:                    return 0;
            }
        }

        size_t JcxzExpandedLength(const Instruction& info)
        {
            switch (info.insn.mnemonic) {
            case ZYDIS_MNEMONIC_JCXZ:  return 13;
            case ZYDIS_MNEMONIC_JECXZ: return 12;
            default:                   return 0;
            }
        }

        bool ExtractRelativeImm(const Instruction& info, int64_t& rel)
        {
            for (ZyanU8 i = 0; i < info.insn.operand_count; ++i) {
                if (info.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    rel = info.operands[i].imm.is_signed
                        ? info.operands[i].imm.value.s
                        : static_cast<int64_t>(info.operands[i].imm.value.u);
                    return true;
                }
            }
            return false;
        }

        size_t ComputeNewLength(const Instruction& info)
        {
            if (info.isLoopFamily) {
                switch (info.insn.mnemonic) {
                case ZYDIS_MNEMONIC_LOOP:
                case ZYDIS_MNEMONIC_LOOPE:
                case ZYDIS_MNEMONIC_LOOPNE:
                    return LoopExpandedLength(info);
                case ZYDIS_MNEMONIC_JCXZ:
                case ZYDIS_MNEMONIC_JECXZ:
                    return JcxzExpandedLength(info);
                default:
                    return info.length;
                }
            }
            if (info.isXbegin) return 6;
            if (info.isRelative) {
                if (info.insn.mnemonic == ZYDIS_MNEMONIC_JMP)  return 5;
                if (info.insn.mnemonic == ZYDIS_MNEMONIC_CALL) return 5;
                if (JccCondCode(info.insn.mnemonic) >= 0)      return 6;
            }
            return info.length;
        }

        bool EncodeRelativeBranch(
            const Instruction& info, uint64_t newAddr, std::vector<uint8_t>& out)
        {
            uint8_t buf[6];
            size_t  len;
            int64_t rel;

            if (info.insn.mnemonic == ZYDIS_MNEMONIC_JMP) {
                buf[0] = 0xE9; len = 5;
                rel = (int64_t)info.target - (int64_t)(newAddr + 5);
            }
            else if (info.insn.mnemonic == ZYDIS_MNEMONIC_CALL) {
                buf[0] = 0xE8; len = 5;
                rel = (int64_t)info.target - (int64_t)(newAddr + 5);
            }
            else {
                int cc = JccCondCode(info.insn.mnemonic);
                if (cc < 0) return false;
                buf[0] = 0x0F;
                buf[1] = (uint8_t)(0x80 | cc);
                len = 6;
                rel = (int64_t)info.target - (int64_t)(newAddr + 6);
            }

            if (rel < INT32_MIN || rel > INT32_MAX) return false;
            int32_t r32 = (int32_t)rel;
            std::memcpy(buf + (len - 4), &r32, 4);
            out.insert(out.end(), buf, buf + len);
            return true;
        }

        bool EncodeXbegin(
            const Instruction& info, uint64_t newAddr, std::vector<uint8_t>& out)
        {
            int64_t rel = (int64_t)info.target - (int64_t)(newAddr + 6);
            if (rel < INT32_MIN || rel > INT32_MAX) return false;

            uint8_t buf[6] = { 0xC7, 0xF8, 0, 0, 0, 0 };
            int32_t r32 = (int32_t)rel;
            std::memcpy(buf + 2, &r32, 4);
            out.insert(out.end(), buf, buf + 6);
            return true;
        }

        bool EncodeLoop32(const Instruction& info, uint64_t newAddr,
            std::vector<uint8_t>& out)
        {
            const uint64_t target = info.target;
            const bool c16 = Uses16BitCounter(info);

            if (info.insn.mnemonic == ZYDIS_MNEMONIC_LOOP) {
                if (!c16) {
                    uint8_t code[12] = {
                        0x9C, 0xFF, 0xC9, 0x74, 0x06, 0x9D,
                        0xE9, 0, 0, 0, 0, 0x9D
                    };
                    int64_t rel = (int64_t)target - (int64_t)(newAddr + 11);
                    if (rel < INT32_MIN || rel > INT32_MAX) return false;
                    int32_t r32 = (int32_t)rel;
                    std::memcpy(code + 7, &r32, 4);
                    out.insert(out.end(), code, code + 12);
                }
                else {
                    uint8_t code[13] = {
                        0x9C, 0x66, 0xFF, 0xC9, 0x74, 0x06, 0x9D,
                        0xE9, 0, 0, 0, 0, 0x9D
                    };
                    int64_t rel = (int64_t)target - (int64_t)(newAddr + 12);
                    if (rel < INT32_MIN || rel > INT32_MAX) return false;
                    int32_t r32 = (int32_t)rel;
                    std::memcpy(code + 8, &r32, 4);
                    out.insert(out.end(), code, code + 13);
                }
                return true;
            }

            const bool isE = (info.insn.mnemonic == ZYDIS_MNEMONIC_LOOPE);
            const uint8_t jccOp = isE ? 0x84 : 0x85;

            if (!c16) {
                uint8_t code[18] = {
                    0x9C, 0xFF, 0xC9, 0x74, 0x0C, 0x9D,
                    0x0F, jccOp, 0, 0, 0, 0,
                    0xE9, 0x01, 0x00, 0x00, 0x00, 0x9D
                };
                int64_t rel = (int64_t)target - (int64_t)(newAddr + 12);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                int32_t r32 = (int32_t)rel;
                std::memcpy(code + 7, &r32, 4);
                out.insert(out.end(), code, code + 18);
            }
            else {
                uint8_t code[19] = {
                    0x9C, 0x66, 0xFF, 0xC9, 0x74, 0x0C, 0x9D,
                    0x0F, jccOp, 0, 0, 0, 0,
                    0xE9, 0x01, 0x00, 0x00, 0x00, 0x9D
                };
                int64_t rel = (int64_t)target - (int64_t)(newAddr + 13);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                int32_t r32 = (int32_t)rel;
                std::memcpy(code + 8, &r32, 4);
                out.insert(out.end(), code, code + 19);
            }
            return true;
        }

        bool EncodeJcxz32(const Instruction& info, uint64_t newAddr,
            std::vector<uint8_t>& out)
        {
            const uint64_t target = info.target;

            if (info.insn.mnemonic == ZYDIS_MNEMONIC_JCXZ) {
                uint8_t code[13] = {
                    0x9C, 0x66, 0x85, 0xC9, 0x75, 0x06, 0x9D,
                    0xE9, 0, 0, 0, 0, 0x9D
                };
                int64_t rel = (int64_t)target - (int64_t)(newAddr + 12);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                int32_t r32 = (int32_t)rel;
                std::memcpy(code + 8, &r32, 4);
                out.insert(out.end(), code, code + 13);
            }
            else {
                uint8_t code[12] = {
                    0x9C, 0x85, 0xC9, 0x75, 0x06, 0x9D,
                    0xE9, 0, 0, 0, 0, 0x9D
                };
                int64_t rel = (int64_t)target - (int64_t)(newAddr + 11);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                int32_t r32 = (int32_t)rel;
                std::memcpy(code + 7, &r32, 4);
                out.insert(out.end(), code, code + 12);
            }
            return true;
        }

        bool EncodeLoopFamily(const Instruction& info, uint64_t newAddr,
            std::vector<uint8_t>& out)
        {
            switch (info.insn.mnemonic) {
            case ZYDIS_MNEMONIC_LOOP:
            case ZYDIS_MNEMONIC_LOOPE:
            case ZYDIS_MNEMONIC_LOOPNE:
                return EncodeLoop32(info, newAddr, out);
            case ZYDIS_MNEMONIC_JCXZ:
            case ZYDIS_MNEMONIC_JECXZ:
                return EncodeJcxz32(info, newAddr, out);
            default:
                return false;
            }
        }

        bool EncodeInstruction(
            const Instruction& info, uint64_t newAddr, std::vector<uint8_t>& out)
        {
            if (info.isLoopFamily) return EncodeLoopFamily(info, newAddr, out);
            if (info.isXbegin)     return EncodeXbegin(info, newAddr, out);
            if (info.isRelative)   return EncodeRelativeBranch(info, newAddr, out);

            out.insert(out.end(),
                reinterpret_cast<const uint8_t*>(info.address),
                reinterpret_cast<const uint8_t*>(info.address) + info.length);
            return true;
        }

    } // anonymous namespace

    // ============================================================
    // 接口 1：反汇编
    // ============================================================
    std::optional<DisasmResult> HookRelocator32::Disassemble(
        uint64_t sourceAddr, size_t minBytes)
    {
        auto& decoder = GetDecoder();
        DisasmResult result;

        size_t   totalBytes = 0;
        size_t   totalNewLength = 0;
        uint64_t cursor = sourceAddr;

        while (totalBytes < minBytes) {
            Instruction info;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder,
                reinterpret_cast<const uint8_t*>(cursor),
                ZYDIS_MAX_INSTRUCTION_LENGTH,
                &info.insn, info.operands)))
            {
                return std::nullopt;
            }

            info.address = cursor;
            info.length = (uint8_t)info.insn.length;

            if (info.insn.mnemonic == ZYDIS_MNEMONIC_XBEGIN) {
                int64_t rel = 0;
                if (!ExtractRelativeImm(info, rel)) return std::nullopt;
                info.target = info.address + info.length + rel;
                info.isXbegin = true;
            }
            else {
                bool isBranch =
                    (info.insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
                    || (info.insn.meta.category == ZYDIS_CATEGORY_COND_BR)
                    || (info.insn.meta.category == ZYDIS_CATEGORY_CALL);
                if (isBranch) {
                    int64_t rel = 0;
                    if (ExtractRelativeImm(info, rel)) {
                        info.target = info.address + info.length + rel;
                        info.isRelative = true;
                    }
                }
            }

            info.isLoopFamily = IsLoopFamily(info.insn.mnemonic);
            info.newLength = (uint8_t)ComputeNewLength(info);

            result.instructions.push_back(info);
            totalBytes += info.length;
            totalNewLength += info.newLength;
            cursor += info.length;
        }

        result.totalBytes = totalBytes;
        result.totalNewLength = totalNewLength;
        return result;
    }

    // ============================================================
    // 接口 2：重定位汇编
    // ============================================================
    std::optional<RelocResult> HookRelocator32::RelocateTo(
        const std::vector<Instruction>& instructions, uint64_t targetAddr)
    {
        if (instructions.empty())
            return std::nullopt;

        std::vector<Instruction> insns = instructions;

        uint64_t cursor = targetAddr;
        for (auto& insn : insns) {
            insn.newAddress = cursor;
            cursor += insn.newLength;
        }

        auto findNewAddr = [&](uint64_t addr) -> uint64_t {
            auto it = std::lower_bound(
                insns.begin(), insns.end(), addr,
                [](const Instruction& insn, uint64_t a) {
                    return insn.address < a;
                });
            if (it != insns.end() && it->address == addr)
                return it->newAddress;
            return addr;
            };

        for (auto& insn : insns) {
            if (!insn.isRelative && !insn.isXbegin && !insn.isLoopFamily)
                continue;
            insn.target = findNewAddr(insn.target);
        }

        std::vector<uint8_t> trampoline;
        trampoline.reserve((size_t)(cursor - targetAddr));

        for (auto& insn : insns) {
            size_t before = trampoline.size();
            if (!EncodeInstruction(insn, insn.newAddress, trampoline))
                return std::nullopt;
            if (trampoline.size() - before != insn.newLength)
                return std::nullopt;
        }

        RelocResult result;
        result.bytes = std::move(trampoline);
        result.totalNewLength = result.bytes.size();
        result.stolenBytes = (size_t)(
            instructions.back().address
            - instructions.front().address
            + instructions.back().length);
        return result;
    }

} // namespace hook32