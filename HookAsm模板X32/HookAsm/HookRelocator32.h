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
        bool isLoopFamily = false;
        bool isXbegin = false;

        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};
    };

    struct DisasmResult
    {
        std::vector<Instruction> instructions;
        size_t                   totalBytes = 0;
        size_t                   totalNewLength = 0;
    };

    struct RelocResult
    {
        std::vector<uint8_t> bytes;
        size_t               stolenBytes = 0;
        size_t               totalNewLength = 0;
    };

    class HookRelocator32
    {
    public:
        std::optional<DisasmResult> Disassemble(
            uint64_t sourceAddr, size_t minBytes);

        std::optional<RelocResult> RelocateTo(
            const std::vector<Instruction>& instructions, uint64_t targetAddr);
    };

} // namespace hook32