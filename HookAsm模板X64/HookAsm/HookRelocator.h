#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <Zydis/Zydis.h>

namespace HookAsm {

    struct Instruction
    {
        uint64_t address = 0;
        uint8_t  length = 0;
        uint64_t target = 0;
        uint8_t  newLength = 0;
        uint64_t newAddress = 0;

        bool isRelative = false;
        bool isRipMem = false;
        bool isLoopFamily = false;
        bool isXbegin = false;

        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};
    };

    // 反汇编结果
    struct DisasmResult
    {
        std::vector<Instruction> instructions;    // 按执行顺序排列
        size_t                   totalBytes = 0; // 原始代码被覆盖的总字节数
        size_t                   totalNewLength = 0; // 重定位后 trampoline 的总字节数
    };

    // 重定位结果
    struct RelocResult
    {
        std::vector<uint8_t> bytes;             // trampoline 字节流
        size_t               stolenBytes = 0;  // 原始代码被消耗的字节数
        size_t               totalNewLength = 0; // = bytes.size()
    };

    class HookRelocator
    {
    public:
        std::optional<DisasmResult> Disassemble(
            uint64_t sourceAddr, size_t minBytes);

        std::optional<RelocResult> RelocateTo(
            const std::vector<Instruction>& instructions, uint64_t targetAddr);
    };

} // namespace hook