#pragma once
//#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <vector>
#include <stdint.h>
//#include "XEDParse/XEDParse.h"
//#pragma comment(lib, "asmtk/asmtk.lib")
//#pragma comment(lib, "XEDParse/XEDParse_x86.lib")

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

typedef DWORD Eflags;

struct Register
{
	Eflags eflags;
	union
	{
		int32_t edi;
		int16_t di;
	};
	union
	{
		int32_t esi;
		int16_t si;
	};
	union
	{
		int32_t ebp;
		int16_t bp;
	};
	union
	{
		int32_t esp;
		int16_t sp;
	};
	union
	{
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
		int32_t eax;
		int16_t ax;
		struct
		{
			int8_t al;
			int8_t ah;
		};
	};
	union
	{
		//该寄存器修改不能和esp/sp寄存器修改共存，修改它会导致esp/sp寄存器修改失效
		int32_t eip;
		//该寄存器修改不能和esp/sp寄存器修改共存，修改它会导致esp/sp寄存器修改失效
		int16_t ip;
	};
	const int32_t fromAddress;
};

// 必须强制 16 字节对齐
#pragma pack(push, 1)        // 取消结构体对齐填充
struct alignas(16) FXSAVE_Area {
	// FPU/MMX 控制部分 (0x00-0x1F)
	uint16_t fpu_control_word;  // 0x00
	uint16_t fpu_status_word;   // 0x02
	uint16_t fpu_tag_word;      // 0x04
	uint16_t fpu_opcode;        // 0x06
	uint32_t fpu_eip;           // 0x08 (指令指针)
	uint32_t fpu_cs;            // 0x0C (代码段)
	uint32_t fpu_data_offset;   // 0x10 (数据指针)
	uint32_t fpu_data_selector; // 0x14 (数据段)
	uint32_t fpu_mxcsr;         // 0x18 MXCSR 寄存器
	uint32_t fpu_mxcsr_mask;    // 0x1C MXCSR_MASK (不同 CPU 可能不同)

	// ST0-ST7 寄存器 (0x20-0x9F)
	struct {
		uint8_t data[10];      // 80-bit 扩展精度
		uint8_t reserved[6];    // 填充到 16 字节
	} st_regs[8];              // 每个 ST 寄存器占 16 字节

	// XMM0-XMM7 寄存器 (0xA0-0x1FF)
	struct alignas(16) {
		uint8_t xmm[16];       // 128-bit XMM 寄存器
	} xmm_regs[8];

	// 保留区域 (不同处理器可能有扩展)
	uint8_t reserved[224];     // 0x180-0x1FF
};
#pragma pack(pop)              // 恢复默认对齐

// 验证基础大小
static_assert(sizeof(FXSAVE_Area) >= 512, "FXSAVE_Area size error");

typedef void(_stdcall* HookCallBack)(Register& reg);

class DisAsmStr
{
public:
	std::string asmStr;
	size_t asmByteSize;
	DisAsmStr() : asmStr(std::string()), asmByteSize(0) {}
};

//typedef std::vector<DisAsmStr> DisAsmStrList;

int htoi(const char* _String);

DisAsmStr HookDisAsm(LPVOID address);

#define DISASM_SIZE 30

//使用汇编cmp指令取得标志位
Eflags Asm_Cmp(int num1, int num2);
//使用汇编test指令取得标志位
Eflags Asm_Test(int num1, int num2);
//保存全部浮点数寄存器
FXSAVE_Area Asm_Fxsave();
//恢复全部浮点数寄存器
void Asm_Fxrstor(const FXSAVE_Area& theFxsaveArea);
/// <summary>
/// 生成ret XXXX指令的EIP地址
/// </summary>
/// <param name="theEspAdd">ESP增加的值(填写0则会内部调用不含参数的Asm_Ret重载函数)</param>
/// <returns>EIP地址(0则失败)</returns>
int32_t Asm_Ret(int16_t theEspAdd);
/// <summary>
/// 生成Ret指令的EIP地址
/// </summary>
/// <returns>EIP地址(0则失败)</returns>
int32_t Asm_Ret();
/// <summary>
/// 释放生成的ret/ret XXXX指令的EIP地址
/// </summary>
/// <param name="theEspAdd">ESP增加的值</param>
void Asm_Ret_Free(int16_t theEspAdd);

/// <summary>
/// 开始Hook(Hook Asm版本)
/// </summary>
/// <param name="hookAddress">要Hook的地址</param>
/// <param name="callBack">Hook回调函数</param>
/// <param name="originalCodeLocation">被Hook的原代码位置</param>
/// <param name="jmpBackAddress">Hook回跳地址</param>
/// <returns>Hook结果</returns>
HookError HookBegin(LPVOID hookAddress, HookCallBack callBack, OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind, LPCVOID jmpBackAddress = (LPCVOID)-1);

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