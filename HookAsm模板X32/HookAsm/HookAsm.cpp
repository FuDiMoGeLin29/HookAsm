#include <map>
#include "capstone/capstone.h"
#define ASMTK_STATIC
#define ASMJIT_EMBED
#define ASMJIT_STATIC
#define ASMJIT_BUILD_RELEASE
#include "asmtk/asmjit/asmjit.h"
#include "asmtk/asmtk.h"
//#pragma comment(lib, "capstone/capstone.lib")
#include "HookAsm.h"

constexpr size_t HOOK_CALL_OFFSET = 23;

std::map<LPVOID, const BYTE*> hookOriginalCode;
std::map<LPVOID, size_t> hookOriginalCodeSize;
std::map<LPVOID, LPVOID> hookAllocAddress;

std::map<LPVOID, const BYTE*> hookFuncOriginalCode;
std::map<LPVOID, size_t> hookFuncOriginalCodeSize;
std::map<LPVOID, LPVOID> hookFuncAddress;
std::map<LPVOID, LPVOID> hookFuncAllocAddress;

std::map<int16_t, LPVOID> RetAddress;

constexpr BYTE HookCallByteArr[] = { 0x68,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x60,0x9C,0x83,0x44,0x24,0x10,0x08,0x83,0x44,0x24,0x24,0x17,0x54,0xE8,0x00,0x00,0x00,0x00,0x9D,0x61,0xC2,0x04,0x00,0x8B,0x64,0x24,0xE4 };
constexpr BYTE HookJmp[] = { 0xE9,0,0,0,0 };
constexpr BYTE NOP[9][9] =
{
	{0x90,0,0,0,0,0,0,0,0},
	{0x66,0x90,0,0,0,0,0,0,0},
	{0x0F,0x1F,0,0,0,0,0,0,0},
	{0x0F,0x1F,0x40,0,0,0,0,0,0},
	{0x0F,0x1F,0x44,0,0,0,0,0,0},
	{0x66,0x0F,0x1F,0x44,0,0,0,0,0},
	{0x0F,0x1F,0x80,0,0,0,0,0,0},
	{0x0F,0x1F,0x84,0,0,0,0,0,0},
	{0x66,0x0F,0x1F,0x84,0,0,0,0,0}
};

constexpr BYTE RetEspAddByteArr[] = { 0xC2,0,0 };
constexpr BYTE RetByteArr[] = { 0xC3 };

HANDLE heapHandle = 0;
HANDLE funcHeapHandle = 0;
HANDLE eipFuncHeapHandle = 0;

int htoi(const char* _String)
{
	size_t len = strlen(_String);
	char* _Str = new char[len + 1];
	ZeroMemory(_Str, len + 1);
	strcpy_s(_Str, len + 1, _String);
	if (len > 2)
	{
		if (_String[0] == '0' && _String[1] == 'x')
		{
			strcpy_s(_Str, len - 1, _String + 2);
			len -= 2;
		}
	}
	for (size_t i = 0; i < len; i++)
	{
		if (_Str[i] >= 'A' && _Str[i] <= 'F')
		{
			_Str[i] = char(_Str[i] - 'A' + 'a');
		}
	}
	int result = 0;
	for (int i = 0; i < len; i++)
	{
		if (_Str[len - i - 1] >= 'a' && _Str[len - i - 1] <= 'f')
		{
			result += (10 + _Str[len - i - 1] - 'a') * (1 << (4 * i));
		}
		else if (_Str[len - i - 1] >= '0' && _Str[len - i - 1] <= '9')
		{
			result += (_Str[len - i - 1] - '0') * (1 << (4 * i));
		}
		else
		{
			delete[] _Str;
			return 0;
		}
	}
	delete[] _Str;
	return result;
}

DisAsmStr HookDisAsm(LPVOID address)
{
	csh csHandle;
	cs_insn* insn;
	size_t count = 0;
	DisAsmStr resultStr;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) != CS_ERR_OK)
	{
		return DisAsmStr();
	}

	cs_option(csHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	uint8_t byteArr[DISASM_SIZE];
	ReadProcessMemory(GetCurrentProcess(), address, byteArr, sizeof(byteArr), 0);
	count = cs_disasm(csHandle, byteArr, DISASM_SIZE, (uint64_t)address, 0, &insn);
	if (count > 0)
	{
		for (int i = 0; i < count; i++)
		{
			std::string asmMnemonic = insn[i].mnemonic;
			std::string asmOp_Str = insn[i].op_str;
			if (asmMnemonic[0] == 'f')
			{
				while (true)
				{
					size_t leftBracket = asmOp_Str.find("(");
					if (leftBracket != std::string::npos)
					{
						asmOp_Str.erase(leftBracket, 1);
					}
					size_t rightBracket = asmOp_Str.find(")");
					if (rightBracket != std::string::npos)
					{
						asmOp_Str.erase(rightBracket, 1);
					}
					if (leftBracket == std::string::npos && rightBracket == std::string::npos)
					{
						break;
					}
				}
			}
			resultStr.asmStr += asmMnemonic + " " + asmOp_Str + "\n";
			resultStr.asmByteSize += insn[i].size;
			if (resultStr.asmByteSize >= 5)
			{
				break;
			}
		}
		cs_free(insn, count);
		cs_close(&csHandle);
		return resultStr;

	}
	cs_close(&csHandle);
	return DisAsmStr();
}

void FillNop(BYTE* resultData, size_t nopSize)
{
	int Nop9Count = nopSize / 9;
	for (int i = 0; i < Nop9Count; i++)
	{
		memcpy(resultData + i * 9, NOP[8], 9);
	}
	int NopCount = nopSize - Nop9Count * 9;
	if (NopCount > 0)
	{
		memcpy(resultData + Nop9Count * 9, NOP[NopCount - 1], NopCount);
	}
}

HookError HookBegin(LPVOID hookAddress, HookCallBack callBack, OriginalCodeLocation originalCodeLocation, LPCVOID jmpBackAddress)
{
	/*if (hookAllocAddress.count(hookAddress) > 0)
	{
		return false;
	}*/
	DisAsmStr disAsmStr = HookDisAsm(hookAddress);
	if (disAsmStr.asmByteSize == 0)
	{
		return HookError::ErrorDisAsmFailed;
	}
	for (size_t i = 1; i < DISASM_SIZE; i++)
	{
		LPVOID findAddress = (LPVOID)((int)hookAddress - i);
		if (hookAllocAddress.count(findAddress) > 0)
		{
			if (hookOriginalCodeSize[findAddress] > i)
			{
				return HookError::ErrorHasHookedNear;
			}
		}
	}
	for (size_t i = 0; i < disAsmStr.asmByteSize; i++)
	{
		LPVOID findAddress = (LPVOID)((int)hookAddress + i);
		if (hookAllocAddress.count(findAddress) > 0)
		{
			return i == 0 ? HookError::ErrorHasHooked : HookError::ErrorHasHookedNear;
		}
	}
	BYTE* defaultByteArr = new BYTE[disAsmStr.asmByteSize];
	BYTE* hookByteArr = new BYTE[disAsmStr.asmByteSize];
	if (heapHandle == NULL)
	{
		heapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
		if (heapHandle == NULL)
		{
			return HookError::ErrorMemoryAllocFailed;
		}
	}
	//LPVOID allocAddress = VirtualAlloc(0, sizeof(HookCallByteArr) + DISASM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	LPVOID allocAddress = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sizeof(HookCallByteArr) + DISASM_SIZE);
	if (allocAddress == NULL)
	{
		return HookError::ErrorMemoryAllocFailed;
	}
	//XEDPARSE asmByte;
	//asmByte.x64 = false;
	int asmLen = 0;
	BYTE asmByteArr[DISASM_SIZE + sizeof(HookCallByteArr) + sizeof(HookJmp)];
	int hookCall = 0;
	switch (originalCodeLocation)
	{
	case OriginalCodeLocation_Behind:
	{
		hookCall = (int)callBack - (int)allocAddress - HOOK_CALL_OFFSET - 5;
		memcpy(asmByteArr, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + (HOOK_CALL_OFFSET + 1), &hookCall, sizeof(hookCall));
		memcpy(asmByteArr + 1, &hookAddress, sizeof(hookAddress));

		//asmjit::CodeBuffer codeBuffer = HookAssemble(disAsmStrList[i].asmStr.c_str(), ((int)allocAddress + sizeof(HookCallByteArr) + asmLen));
		asmjit::Environment env(asmjit::Arch::kX86);
		asmjit::CodeHolder code;
		code.init(env, (uint64_t)((int)allocAddress + sizeof(HookCallByteArr)));

		// Attach x86::Assembler to `code`.
		asmjit::x86::Assembler a(&code);

		// Create AsmParser that will emit to x86::Assembler.
		asmtk::AsmParser p(&a);

		//asmjit::CodeHolder

		// Parse some assembly.
		asmjit::Error err = p.parse(disAsmStr.asmStr.c_str());

		// Error handling (use asmjit::ErrorHandler for more robust error handling).
		if (err) {
			//VirtualFree(allocAddress, 0, MEM_RELEASE);
			ZeroMemory(allocAddress, sizeof(HookCallByteArr) + DISASM_SIZE);
			HeapFree(heapHandle, 0, allocAddress);
			if (hookAllocAddress.size() == 0)
			{
				HeapDestroy(heapHandle);
				heapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			return HookError::ErrorAsmFailed;
		}

		// Now you can print the code, which is stored in the first section (.text).
		asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();
		//if (codeBuffer.size() == 0)
		//{
		//	VirtualFree(allocAddress, 0, MEM_RELEASE);
		//	delete[] defaultByteArr;
		//	delete[] hookByteArr;
		//	return false;
		//}
		//asmByte.cip = ((int)allocAddress + sizeof(HookCallByteArr) + asmLen);
		//strcpy_s(asmByte.instr, disAsmStrList[i].asmStr.c_str());
		//XEDParseAssemble(&asmByte);
		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((int)allocAddress + sizeof(HookCallByteArr) + asmLen), asmByte.dest, asmByte.dest_size, 0);
		memcpy(asmByteArr + sizeof(HookCallByteArr), codeBuffer.data(), codeBuffer.size());
		asmLen += codeBuffer.size();

		break;
	}
	case OriginalCodeLocation_Front:
	{
		/*asmjit::CodeBuffer codeBuffer = HookAssemble(disAsmStrList[i].asmStr.c_str(), ((int)allocAddress + asmLen));
			if (codeBuffer.size() == 0)
			{
				VirtualFree(allocAddress, 0, MEM_RELEASE);
				delete[] defaultByteArr;
				delete[] hookByteArr;
				return false;
			}*/

		asmjit::Environment env(asmjit::Arch::kX86);
		asmjit::CodeHolder code;
		code.init(env, (uint64_t)((int)allocAddress));

		// Attach x86::Assembler to `code`.
		asmjit::x86::Assembler a(&code);

		// Create AsmParser that will emit to x86::Assembler.
		asmtk::AsmParser p(&a);

		//asmjit::CodeHolder

		// Parse some assembly.
		asmjit::Error err = p.parse(disAsmStr.asmStr.c_str());

		// Error handling (use asmjit::ErrorHandler for more robust error handling).
		if (err) {
			//VirtualFree(allocAddress, 0, MEM_RELEASE);
			ZeroMemory(allocAddress, sizeof(HookCallByteArr) + DISASM_SIZE);
			HeapFree(heapHandle, 0, allocAddress);
			if (hookAllocAddress.size() == 0)
			{
				HeapDestroy(heapHandle);
				heapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			return HookError::ErrorAsmFailed;
		}

		// Now you can print the code, which is stored in the first section (.text).
		asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();

		//asmByte.cip = ((int)allocAddress + asmLen);
		//strcpy_s(asmByte.instr, disAsmStrList[i].asmStr.c_str());
		//XEDParseAssemble(&asmByte);
		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((int)allocAddress + sizeof(HookCallByteArr) + asmLen), asmByte.dest, asmByte.dest_size, 0);
		memcpy(asmByteArr, codeBuffer.data(), codeBuffer.size());
		asmLen += codeBuffer.size();

		hookCall = (int)callBack - (int)allocAddress - asmLen - HOOK_CALL_OFFSET - 5;
		memcpy(asmByteArr + asmLen, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + asmLen + (HOOK_CALL_OFFSET + 1), &hookCall, sizeof(hookCall));
		memcpy(asmByteArr + asmLen + 1, &hookAddress, sizeof(hookAddress));
		break;
	}
	case OriginalCodeLocation_Without:
		hookCall = (int)callBack - (int)allocAddress - HOOK_CALL_OFFSET - 5;
		memcpy(asmByteArr, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + (HOOK_CALL_OFFSET + 1), &hookCall, sizeof(hookCall));
		memcpy(asmByteArr + 1, &hookAddress, sizeof(hookAddress));
		break;
	default:
		//VirtualFree(allocAddress, 0, MEM_RELEASE);
		ZeroMemory(allocAddress, sizeof(HookCallByteArr) + DISASM_SIZE);
		HeapFree(heapHandle, 0, allocAddress);
		if (hookAllocAddress.size() == 0)
		{
			HeapDestroy(heapHandle);
			heapHandle = NULL;
		}
		delete[] defaultByteArr;
		delete[] hookByteArr;
		return HookError::ErrorBadParameter;
	}
	int hookJmpBack;
	if (jmpBackAddress != (LPCVOID)-1)
	{
		hookJmpBack = ((int)jmpBackAddress) - (int)allocAddress - sizeof(HookCallByteArr) - asmLen - 5;
	}
	else
	{
		hookJmpBack = ((int)hookAddress + disAsmStr.asmByteSize) - (int)allocAddress - sizeof(HookCallByteArr) - asmLen - 5;
	}
	memcpy(asmByteArr + sizeof(HookCallByteArr) + asmLen, HookJmp, sizeof(HookJmp));
	memcpy(asmByteArr + sizeof(HookCallByteArr) + asmLen + 1, &hookJmpBack, sizeof(hookJmpBack));
	WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, asmLen + sizeof(HookCallByteArr) + sizeof(HookJmp), 0);
	memcpy(defaultByteArr, hookAddress, disAsmStr.asmByteSize);
	hookOriginalCode[hookAddress] = defaultByteArr;
	hookOriginalCodeSize[hookAddress] = disAsmStr.asmByteSize;
	hookAllocAddress[hookAddress] = allocAddress;
	int hookJmpTo = (int)allocAddress - (int)hookAddress - 5;
	memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
	memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

	FillNop(hookByteArr + sizeof(HookJmp), disAsmStr.asmByteSize - sizeof(HookJmp));

	/*int Nop9Count = (disAsmStr.asmByteSize - sizeof(HookJmp)) / 9;
	for (int i = 0; i < Nop9Count; i++)
	{
		memcpy(hookByteArr + sizeof(HookJmp) + i * 9, NOP[8], 9);
	}
	int NopCount = disAsmStr.asmByteSize - sizeof(HookJmp) - Nop9Count * 9;
	if (NopCount > 0)
	{
		memcpy(hookByteArr + sizeof(HookJmp) + Nop9Count * 9, NOP[NopCount - 1], NopCount);
	}*/

	WriteProcessMemory(GetCurrentProcess(), hookAddress, hookByteArr, disAsmStr.asmByteSize, 0);
	delete[] hookByteArr;
	return HookError::ErrorOk;
}

bool HookStop(LPVOID hookAddress)
{
	if (hookAllocAddress.count(hookAddress) == 0)
	{
		return false;
	}
	size_t oldCodeSize = hookOriginalCodeSize[hookAddress];
	const BYTE* oldCode = hookOriginalCode[hookAddress];
	LPVOID allocAddress = hookAllocAddress[hookAddress];
	WriteProcessMemory(GetCurrentProcess(), hookAddress, oldCode, oldCodeSize, 0);
	//VirtualFree(allocAddress, 0, MEM_RELEASE);
	ZeroMemory(allocAddress, sizeof(HookCallByteArr) + DISASM_SIZE);
	HeapFree(heapHandle, 0, allocAddress);
	hookOriginalCodeSize.erase(hookAddress);
	hookOriginalCode.erase(hookAddress);
	hookAllocAddress.erase(hookAddress);
	if (hookAllocAddress.size() == 0)
	{
		HeapDestroy(heapHandle);
		heapHandle = NULL;
	}
	delete[] oldCode;
	return true;
}

HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc)
{
	for (std::map<LPVOID, LPVOID>::reverse_iterator iter = hookFuncAddress.rbegin(); iter != hookFuncAddress.rend(); iter++)
	{
		if (iter->second == *oldFunc)
		{
			return HookError::ErrorHasHooked;
		}
	}
	if (hookFuncAddress.count(*oldFunc) > 0)
	{
		return HookError::ErrorHasHooked;
	}
	LPVOID oldFuncAddress = *oldFunc;
	DisAsmStr disAsmStr = HookDisAsm(*oldFunc);
	if (disAsmStr.asmByteSize == 0)
	{
		return HookError::ErrorDisAsmFailed;
	}
	BYTE* defaultByteArr = new BYTE[disAsmStr.asmByteSize];
	memcpy(defaultByteArr, *oldFunc, disAsmStr.asmByteSize);
	BYTE hookByteArr[DISASM_SIZE];
	BYTE asmByteArr[DISASM_SIZE];
	if (funcHeapHandle == NULL)
	{
		funcHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
		if (funcHeapHandle == NULL)
		{
			return HookError::ErrorMemoryAllocFailed;
		}
	}
	LPVOID allocAddress = HeapAlloc(funcHeapHandle, HEAP_ZERO_MEMORY, sizeof(HookJmp) + DISASM_SIZE);
	if (allocAddress == NULL)
	{
		return HookError::ErrorMemoryAllocFailed;
	}
	asmjit::Environment env(asmjit::Arch::kX86);
	asmjit::CodeHolder code;
	code.init(env, (uint64_t)((int)allocAddress));

	// Attach x86::Assembler to `code`.
	asmjit::x86::Assembler a(&code);

	// Create AsmParser that will emit to x86::Assembler.
	asmtk::AsmParser p(&a);

	//asmjit::CodeHolder

	// Parse some assembly.
	asmjit::Error err = p.parse(disAsmStr.asmStr.c_str());

	// Error handling (use asmjit::ErrorHandler for more robust error handling).
	if (err) {
		//VirtualFree(allocAddress, 0, MEM_RELEASE);
		ZeroMemory(allocAddress, sizeof(HookCallByteArr) + DISASM_SIZE);
		HeapFree(funcHeapHandle, 0, allocAddress);
		if (hookFuncAllocAddress.size() == 0)
		{
			HeapDestroy(funcHeapHandle);
			funcHeapHandle = NULL;
		}
		delete[] defaultByteArr;
		return HookError::ErrorAsmFailed;
	}

	// Now you can print the code, which is stored in the first section (.text).

	asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();
	uintptr_t hookJmpBack = ((int)(*oldFunc) + disAsmStr.asmByteSize) - ((int)allocAddress + codeBuffer.size()) - 5;
	memcpy(asmByteArr, codeBuffer.data(), codeBuffer.size());
	memcpy(asmByteArr + codeBuffer.size(), HookJmp, sizeof(HookJmp));
	memcpy(asmByteArr + codeBuffer.size() + 1, &hookJmpBack, sizeof(hookJmpBack));

	WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, sizeof(asmByteArr), 0);;
	*oldFunc = allocAddress;

	int hookJmpTo = (int)newFunc - (int)oldFuncAddress - 5;
	memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
	memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

	FillNop(hookByteArr + sizeof(HookJmp), disAsmStr.asmByteSize - sizeof(HookJmp));
	WriteProcessMemory(GetCurrentProcess(), oldFuncAddress, hookByteArr, disAsmStr.asmByteSize, 0);

	hookFuncOriginalCode[*oldFunc] = defaultByteArr;
	hookFuncOriginalCodeSize[*oldFunc] = disAsmStr.asmByteSize;
	hookFuncAddress[*oldFunc] = oldFuncAddress;
	hookFuncAllocAddress[*oldFunc] = allocAddress;
	return HookError::ErrorOk;
}

bool HookFunctionStop(LPVOID* oldFunc)
{
	LPVOID oldFunction = *oldFunc;
	if (hookFuncAddress.count(oldFunction) == 0)
	{
		return false;
	}
	WriteProcessMemory(GetCurrentProcess(), hookFuncAddress[oldFunction], hookFuncOriginalCode[oldFunction], hookFuncOriginalCodeSize[oldFunction], 0);
	ZeroMemory(hookFuncAllocAddress[oldFunction], sizeof(HookJmp) + DISASM_SIZE);
	HeapFree(funcHeapHandle, 0, hookAllocAddress[oldFunction]);
	delete hookFuncOriginalCode[oldFunction];
	hookFuncOriginalCode.erase(oldFunction);
	hookFuncOriginalCodeSize.erase(oldFunction);
	*oldFunc = hookFuncAddress[oldFunction];
	hookFuncAddress.erase(oldFunction);
	hookFuncAllocAddress.erase(oldFunction);
	if (hookFuncAddress.size() == 0)
	{
		HeapDestroy(funcHeapHandle);
		funcHeapHandle = NULL;
	}
	return true;
}

Eflags Asm_Cmp(int num1, int num2)
{
	Eflags result;
	_asm
	{
		mov eax, num2;
		cmp num1, eax;
		pushfd;
		pop result;
	}
	return result;
}

Eflags Asm_Test(int num1, int num2)
{
	Eflags result;
	_asm
	{
		mov eax, num2;
		test num1, eax;
		pushfd;
		pop result;
	}
	return result;
}

int32_t Asm_Ret()
{
	if (eipFuncHeapHandle == NULL)
	{
		eipFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
		if (eipFuncHeapHandle == NULL)
		{
			return 0;
		}
	}
	if (RetAddress.count(0) == 0)
	{
		LPVOID allocAddress = HeapAlloc(eipFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(RetByteArr));
		memcpy(allocAddress, RetByteArr, sizeof(RetByteArr));
		RetAddress[0] = allocAddress;
		return (int32_t)allocAddress;
	}
	else
	{
		return (int32_t)RetAddress[0];
	}
}

int32_t Asm_Ret(int16_t theEspAdd)
{
	if (theEspAdd == 0)
	{
		return Asm_Ret();
	}
	if (eipFuncHeapHandle == NULL)
	{
		eipFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
		if (eipFuncHeapHandle == NULL)
		{
			return 0;
		}
	}
	if (RetAddress.count(theEspAdd) == 0)
	{
		LPVOID allocAddress = HeapAlloc(eipFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(RetEspAddByteArr));
		memcpy(allocAddress, RetEspAddByteArr, sizeof(RetEspAddByteArr));
		memcpy((LPVOID)((int32_t)allocAddress + 1), &theEspAdd, sizeof(theEspAdd));
		RetAddress[theEspAdd] = allocAddress;
		return (int32_t)allocAddress;
	}
	else
	{
		return (int32_t)RetAddress[theEspAdd];
	}
}

void Asm_Ret_Free(int16_t theEspAdd)
{
	if (theEspAdd == 0)
	{
		ZeroMemory(RetAddress[0], sizeof(RetByteArr));
	}
	else
	{
		ZeroMemory(RetAddress[theEspAdd], sizeof(RetEspAddByteArr));
	}
	HeapFree(eipFuncHeapHandle, 0, RetAddress[theEspAdd]);
	RetAddress.erase(theEspAdd);
	if (RetAddress.size() == 0)
	{
		HeapDestroy(eipFuncHeapHandle);
		eipFuncHeapHandle = NULL;
	}
}

#pragma pack(push, 1)        // 取消结构体对齐填充
alignas(16) volatile FXSAVE_Area gFxsave_area;
#pragma pack(pop)              // 恢复默认对齐

FXSAVE_Area Asm_Fxsave()
{
	FXSAVE_Area result;
	_fxsave((void*)&gFxsave_area);
	memcpy(&result, (void*)&gFxsave_area, sizeof(FXSAVE_Area));
	return result;
}

void Asm_Fxrstor(const FXSAVE_Area& theFxsaveArea)
{
	memcpy((void*)&gFxsave_area, &theFxsaveArea, sizeof(FXSAVE_Area));
	_fxrstor((void*)&gFxsave_area);
}