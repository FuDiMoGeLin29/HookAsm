#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>
#include <stdint.h>
//#pragma comment(lib, "XEDParse/XEDParse_x64.lib")

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

enum HookError : int
{
	ErrorOk,
	ErrorDisAsmFailed,
	ErrorAsmFailed,
	ErrorMemoryAllocFailed,
	ErrorHasHooked,
	ErrorHasHookedNear,
	ErrorBadParameter,
};

enum OriginalCodeLocation : int
{
	OriginalCodeLocation_Behind,
	OriginalCodeLocation_Front,
	OriginalCodeLocation_Without,
};

typedef DWORD64 Eflags;

struct Register
{
	union
	{
		int64_t r15;
		int32_t r15d;
		int16_t r15w;
		int8_t r15b;
	};
	union
	{
		int64_t r14;
		int32_t r14d;
		int16_t r14w;
		int8_t r14b;
	};
	union
	{
		int64_t r13;
		int32_t r13d;
		int16_t r13w;
		int8_t r13b;
	};
	union
	{
		int64_t r12;
		int32_t r12d;
		int16_t r12w;
		int8_t r12b;
	};
	union
	{
		int64_t r11;
		int32_t r11d;
		int16_t r11w;
		int8_t r11b;
	};
	union
	{
		int64_t r10;
		int32_t r10d;
		int16_t r10w;
		int8_t r10b;
	};
	union
	{
		int64_t r9;
		int32_t r9d;
		int16_t r9w;
		int8_t r9b;
	};
	union
	{
		int64_t r8;
		int32_t r8d;
		int16_t r8w;
		int8_t r8b;
	};
	union
	{
		int64_t rdi;
		int32_t edi;
		int16_t di;
	};
	union
	{
		int64_t rsi;
		int32_t esi;
		int16_t si;
	};
	union
	{
		int64_t rbp;
		int32_t ebp;
		int16_t bp;
	};
	union
	{
		int64_t rsp;
		int32_t esp;
		int16_t sp;
	};
	union
	{
		int64_t rbx;
		int32_t ebx;
		int16_t bx;
		struct
		{
			int8_t bl;
			int8_t bh;
		};
	};
	union
	{
		int64_t rdx;
		int32_t edx;
		int16_t dx;
		struct
		{
			int8_t dl;
			int8_t dh;
		};
	};
	union
	{
		int64_t rcx;
		int32_t ecx;
		int16_t cx;
		struct
		{
			int8_t cl;
			int8_t ch;
		};
	};
	union
	{
		int64_t rax;
		int32_t eax;
		int16_t ax;
		struct
		{
			int8_t al;
			int8_t ah;
		};
	};
	Eflags eflags;
	union
	{
		//该寄存器修改不能和rsp/esp/sp寄存器修改共存，修改它会导致rsp/esp/sp寄存器修改失效
		int64_t rip;
		//该寄存器修改不能和rsp/esp/sp寄存器修改共存，修改它会导致rsp/esp/sp寄存器修改失效
		int32_t eip;
		//该寄存器修改不能和rsp/esp/sp寄存器修改共存，修改它会导致rsp/esp/sp寄存器修改失效
		int16_t ip;
	};
	const int64_t fromAddress;
};

// 必须 16 字节对齐（AVX 需要 64 字节对齐）
#pragma pack(push, 1)
struct alignas(64) FXSAVE64_Area {  // 使用 64 对齐以兼容 AVX（可选）
	// --- 基本部分 (512 bytes) ---
	// FPU/MMX 控制部分 (0x00-0x1F)
	uint16_t fpu_control_word;     // 0x00
	uint16_t fpu_status_word;      // 0x02
	uint16_t fpu_tag_word;         // 0x04
	uint16_t fpu_opcode;           // 0x06
	uint32_t fpu_eip;              // 0x08
	uint16_t fpu_cs;               // 0x0C
	uint16_t fpu_reserved1;        // 0x0E
	uint32_t fpu_data_offset;      // 0x10
	uint16_t fpu_data_selector;    // 0x14
	uint16_t fpu_reserved2;        // 0x16
	uint32_t mxcsr;                // 0x18: SSE 控制寄存器
	uint32_t mxcsr_mask;           // 0x1C: MXCSR 掩码

	// FPU 寄存器栈 (0x20-0x9F)
	struct {
		uint8_t data[10];          // 80-bit 扩展精度
		uint8_t reserved[6];        // 填充到 16 字节
	} st_regs[8];                   // ST0-ST7

	// XMM0-XMM15 寄存器 (0xA0-0x1FF)
	struct alignas(16) {
		uint8_t xmm[16];           // 128-bit XMM
	} xmm_regs[16];                // 64 位下 XMM0-XMM15

	// 保留区域 (0x200-0x3FF)
	uint8_t reserved[384];         // 可能包含扩展状态（如 AVX）

	// --- 扩展部分（AVX 需额外 64 字节）---
	// YMM0-YMM15 高 128 位 (仅当支持 AVX 时存在)
	// uint8_t ymm_hi[16*16];       // 0x300-0x3FF (可选)
};
#pragma pack(pop)

typedef void(_stdcall* HookCallBack)(Register& reg);

class DisAsmStr
{
public:
	std::string asmStr;
	size_t asmByteSize;
	DisAsmStr() : asmStr(std::string()), asmByteSize(0) {}
};

//typedef std::vector<DisAsmStr> DisAsmStrList;

long long htoi64(const char* _String);

DisAsmStr HookDisAsm(LPVOID address);

#define DISASM_SIZE 60

#ifndef __ASMCODE_H
#define __ASMCODE_H

extern "C"
{
	//使用汇编cmp指令取得标志位
	Eflags _stdcall Asm_Cmp(long long num1, long long num2);
	//使用汇编test指令取得标志位
	Eflags _stdcall Asm_Test(long long num1, long long num2);
}

#endif

/// <summary>
/// 生成ret XXXX指令的RIP地址
/// </summary>
/// <param name="theRspAdd">RSP增加的值(填写0则会内部调用不含参数的Asm_Ret重载函数)</param>
/// <returns>RIP地址(0则失败)</returns>
int64_t Asm_Ret(int16_t theRspAdd);
/// <summary>
/// 生成Ret指令的RIP地址
/// </summary>
/// <returns>RIP地址(0则失败)</returns>
int64_t Asm_Ret();
/// <summary>
/// 释放生成的ret/ret XXXX指令的RIP地址
/// </summary>
/// <param name="theRspAdd">RSP增加的值</param>
void Asm_Ret_Free(int16_t theRspAdd);
/// <summary>
/// 生成修改Rsp并Jmp到指定地址的RIP地址
/// </summary>
/// <param name="theRsp">修改的RSP</param>
/// <param name="theJmpAddress">Jmp到地址</param>
/// <returns>RIP地址(0则失败)</returns>
int64_t Asm_Mov_Rsp_And_Jmp(int64_t theRsp, int64_t theJmpAddress);
/// <summary>
/// 释放生成的修改Rsp并Jmp到指定地址的RIP地址
/// </summary>
/// <param name="theRsp">修改的RSP</param>
/// <param name="theJmpAddress">Jmp到地址</param>
void Asm_Mov_Rsp_And_Jmp_Free(int64_t theRsp, int64_t theJmpAddress);

//保存全部浮点数寄存器
FXSAVE64_Area Asm_Fxsave();
//恢复全部浮点数寄存器
void Asm_Fxrstor(const FXSAVE64_Area& theFxsaveArea);

// 验证基础大小
static_assert(sizeof(FXSAVE64_Area) >= 512, "FXSAVE64_Area size error");

/// <summary>
/// 开始Hook(Hook Asm版本)
/// </summary>
/// <param name="hookAddress">要Hook的地址</param>
/// <param name="callBack">Hook回调函数</param>
/// <param name="isRSPAlign16Bytes">Hook的位置RSP是否16字节对齐</param>
/// <param name="originalCodeLocation">被Hook的原代码位置</param>
/// <param name="jmpBackAddress">Hook回跳地址</param>
/// <returns>Hook结果</returns>
HookError HookBegin(LPVOID hookAddress, HookCallBack callBack, bool isRSPAlign16Bytes = true, OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind, LPCVOID jmpBackAddress = (LPCVOID)-1);

/// <summary>
/// 停止Hook(Asm版本)
/// </summary>
/// <param name="hookAddress">被Hook的地址</param>
/// <returns>是否成功</returns>
bool HookStop(LPVOID hookAddress);

/// <summary>
/// 开始Hook(Hook函数版本)
/// </summary>
/// <param name="newFunc">新函数</param>
/// <param name="oldFunc">[in,out]存储要Hook的旧函数，并返回调用后不会产生递归的函数指针</param>
/// <returns>Hook结果</returns>
HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc);

/// <summary>
/// 停止Hook(Hook函数版本)
/// </summary>
/// <param name="oldFunc">[in,out]存储调用后不会产生递归的被Hook的函数指针，并返回原函数指针</param>
/// <returns>是否成功</returns>
bool HookFunctionStop(LPVOID* oldFunc);