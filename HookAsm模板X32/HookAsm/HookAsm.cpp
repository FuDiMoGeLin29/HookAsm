#include <map>
#include <stack>
#include <tuple>
#include <Zydis/Zydis.h>
#include <asmjit/x86.h>
#include <asmjit/core.h>
#include <intrin.h>
#include "HookRelocator32.h"
//#pragma comment(lib, "capstone/capstone.lib")
#include "HookAsm.h"

using namespace asmjit;

namespace HookAsm
{

	struct EspAndJmpAddress
	{
		int32_t mEsp;
		int32_t mJmpAddress;

		bool operator<(const EspAndJmpAddress& other) const {
			return std::tie(mEsp, mJmpAddress) < std::tie(other.mEsp, other.mJmpAddress);
		}
	};

	constexpr size_t HOOK_CALL_OFFSET = 23;

	std::map<LPVOID, std::stack<const BYTE*>> hookOriginalCodes;
	std::map<LPVOID, std::stack<size_t>> hookOriginalCodeSizes;
	std::map<LPVOID, std::stack<LPVOID>> hookAllocAddresses;

	std::map<LPVOID, std::stack<const BYTE*>> hookFuncOriginalCodes;
	std::map<LPVOID, std::stack<size_t>> hookFuncOriginalCodeSizes;
	std::map<LPVOID, std::stack<LPVOID>> hookFuncAddresses;
	std::map<LPVOID, std::stack<LPVOID>> hookFuncAllocAddresses;

	std::map<int16_t, LPVOID> RetAddress;
	std::map<EspAndJmpAddress, LPVOID> MovEspAndJmpAddressAddress;

	//constexpr BYTE HookCallByteArr[] = { 0x68,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x60,0x9C,0x83,0x44,0x24,0x10,0x08,0x83,0x44,0x24,0x24,0x17,0x54,0xE8,0x00,0x00,0x00,0x00,0x9D,0x61,0xC2,0x04,0x00,0x8B,0x64,0x24,0xE4 };
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

	constexpr BYTE MovEspByteArr[] = { 0xBC,0x00,0x00,0x00,0x00 };

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

	std::vector<uint8_t> CreateHookCallByteArr(uint32_t hookCallbackAsmAddress, uint32_t fromAddress, uint32_t hookCallBackAddress)
	{
		Environment env(asmjit::Arch::kX86);
		CodeHolder code;                        // 创建 CodeHolder
		code.init(env, hookCallbackAsmAddress);               // 初始化 CodeHolder 以匹配运行时环境

		x86::Assembler a(&code);
		a.push(fromAddress);
		//call eip+5
		Label next = a.new_label();
		a.call(next);
		a.bind(next);
		a.pushad();
		a.pushfd();
		//add dword ptr [esp+0x10], 0x08  (修正esp)
		a.add(x86::dword_ptr(x86::esp, 0x10), 0x8);
		//add dword ptr [esp+0x24], 0x17 (修正ret返回地址)
		a.add(x86::dword_ptr(x86::esp, 0x24), 0x17);
		a.push(x86::esp);
		a.call(hookCallBackAddress);
		a.popfd();
		a.popad();
		a.ret(4);
		//mov esp, [esp-0x1C]
		a.mov(x86::esp, x86::ptr(x86::esp, -0x1C));

		const Section* text = code.text_section();
		if (!text) return {};
		const uint8_t* data = text->buffer().data();
		size_t size = text->buffer_size();
		return std::vector<uint8_t>(data, data + size);
	}

	HookError HookBegin(LPVOID hookAddress, HookCallBack callBack, OriginalCodeLocation originalCodeLocation, size_t minDisAsmSize, LPCVOID jmpBackAddress)
	{
		/*if (hookAllocAddress.count(hookAddress) > 0)
		{
			return false;
		}*/
		HookAsm::HookRelocator32 reloc;
		auto disAsmRes = reloc.Disassemble((uint64_t)hookAddress, (minDisAsmSize >= 0 && minDisAsmSize <= sizeof(HookJmp)) ? sizeof(HookJmp) : minDisAsmSize);
		//DisAsmStr disAsmStr = HookDisAsm(hookAddress);
		if (!disAsmRes)
		{
			return HookError::ErrorDisAsmFailed;
		}
		
		BYTE* defaultByteArr = new BYTE[disAsmRes->totalBytes];
		BYTE* hookByteArr = new BYTE[disAsmRes->totalBytes];
		if (heapHandle == NULL)
		{
			heapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (heapHandle == NULL)
			{
				return HookError::ErrorMemoryAllocFailed;
			}
		}
		//LPVOID allocAddress = VirtualAlloc(0, sizeof(HookCallByteArr) + DISASM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		// 
		// 用 dummy 地址生成一次，只为拿大小
		auto probe = CreateHookCallByteArr(
			/*hookCallbackAsmAddress=*/0x1000,
			/*fromAddress=*/0x2000,
			/*hookCallBackAddress=*/0x3000);
		size_t stubSize = probe.size();

		LPVOID allocAddress = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, stubSize + disAsmRes->totalNewLength + sizeof(HookJmp));
		if (allocAddress == NULL)
		{
			return HookError::ErrorMemoryAllocFailed;
		}
		//XEDPARSE asmByte;
		//asmByte.x64 = false;
		size_t asmLen = 0;
		BYTE* asmByteArr = new BYTE[disAsmRes->totalNewLength + stubSize + sizeof(HookJmp)];
		std::vector<uint8_t> hookCallByteArr;
		switch (originalCodeLocation)
		{
		case OriginalCodeLocation_Behind:
		{
			hookCallByteArr = CreateHookCallByteArr((uint32_t)allocAddress, (uint32_t)hookAddress, (uint32_t)callBack);
			memcpy(asmByteArr, hookCallByteArr.data(), hookCallByteArr.size());

			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress + hookCallByteArr.size()));
			if (!relocToRes)
			{
				HeapFree(heapHandle, 0, allocAddress);
				if (hookAllocAddresses.size() == 0)
				{
					HeapDestroy(heapHandle);
					heapHandle = NULL;
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}

			memcpy(asmByteArr + hookCallByteArr.size(), relocToRes->bytes.data(), relocToRes->bytes.size());
			asmLen += relocToRes->bytes.size();

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

			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress));
			if (!relocToRes)
			{
				HeapFree(heapHandle, 0, allocAddress);
				if (hookAllocAddresses.size() == 0)
				{
					HeapDestroy(heapHandle);
					heapHandle = NULL;
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}

			memcpy(asmByteArr, relocToRes->bytes.data(), relocToRes->bytes.size());
			asmLen += relocToRes->bytes.size();

			hookCallByteArr = CreateHookCallByteArr((uint32_t)allocAddress + asmLen, (uint32_t)hookAddress, (uint32_t)callBack);
			memcpy(asmByteArr + asmLen, hookCallByteArr.data(), hookCallByteArr.size());
			break;
		}
		case OriginalCodeLocation_Without:
			hookCallByteArr = CreateHookCallByteArr((uint32_t)allocAddress, (uint32_t)hookAddress, (uint32_t)callBack);
			memcpy(asmByteArr, hookCallByteArr.data(), hookCallByteArr.size());
			break;
		default:
			//VirtualFree(allocAddress, 0, MEM_RELEASE);
			HeapFree(heapHandle, 0, allocAddress);
			if (hookAllocAddresses.size() == 0)
			{
				HeapDestroy(heapHandle);
				heapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorBadParameter;
		}
		int hookJmpBack;
		if (jmpBackAddress != (LPCVOID)-1)
		{
			hookJmpBack = ((int)jmpBackAddress) - (int)allocAddress - hookCallByteArr.size() - asmLen - 5;
		}
		else
		{
			hookJmpBack = ((int)hookAddress + disAsmRes->totalBytes) - (int)allocAddress - hookCallByteArr.size() - asmLen - 5;
		}
		memcpy(asmByteArr + hookCallByteArr.size() + asmLen, HookJmp, sizeof(HookJmp));
		memcpy(asmByteArr + hookCallByteArr.size() + asmLen + 1, &hookJmpBack, sizeof(hookJmpBack));
		if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, asmLen + hookCallByteArr.size() + sizeof(HookJmp), 0))
		{
			HeapFree(heapHandle, 0, allocAddress);
			if (hookAllocAddresses.size() == 0)
			{
				HeapDestroy(heapHandle);
				heapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorWriteMemoryFailed;
		}
		memcpy(defaultByteArr, hookAddress, disAsmRes->totalBytes);
		int hookJmpTo = (int)allocAddress - (int)hookAddress - 5;
		memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
		memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

		FillNop(hookByteArr + sizeof(HookJmp), disAsmRes->totalBytes - sizeof(HookJmp));

		if (!WriteProcessMemory(GetCurrentProcess(), hookAddress, hookByteArr, disAsmRes->totalBytes, 0))
		{
			HeapFree(heapHandle, 0, allocAddress);
			if (hookAllocAddresses.size() == 0)
			{
				HeapDestroy(heapHandle);
				heapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorWriteMemoryFailed;
		}

		hookOriginalCodes[hookAddress].push(defaultByteArr);
		hookOriginalCodeSizes[hookAddress].push(disAsmRes->totalBytes);
		hookAllocAddresses[hookAddress].push(allocAddress);
		delete[] hookByteArr;
		delete[] asmByteArr;
		return HookError::ErrorOk;
	}

	bool HookStop(LPVOID hookAddress)
	{
		if (hookAllocAddresses.count(hookAddress) == 0)
		{
			return false;
		}
		size_t oldCodeSize = hookOriginalCodeSizes[hookAddress].top();
		const BYTE* oldCode = hookOriginalCodes[hookAddress].top();
		LPVOID allocAddress = hookAllocAddresses[hookAddress].top();
		WriteProcessMemory(GetCurrentProcess(), hookAddress, oldCode, oldCodeSize, 0);
		//VirtualFree(allocAddress, 0, MEM_RELEASE);
		HeapFree(heapHandle, 0, allocAddress);
		hookOriginalCodeSizes[hookAddress].pop();
		if (hookOriginalCodeSizes[hookAddress].empty())
		{
			hookOriginalCodeSizes.erase(hookAddress);
		}
		hookOriginalCodes[hookAddress].pop();
		if (hookOriginalCodes[hookAddress].empty())
		{
			hookOriginalCodes.erase(hookAddress);
		}
		hookAllocAddresses[hookAddress].pop();
		if (hookAllocAddresses[hookAddress].empty())
		{
			hookAllocAddresses.erase(hookAddress);
		}
		if (hookAllocAddresses.size() == 0)
		{
			HeapDestroy(heapHandle);
			heapHandle = NULL;
		}
		delete[] oldCode;
		return true;
	}

	HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc)
	{
		LPVOID oldFuncAddress = *oldFunc;
		HookAsm::HookRelocator32 reloc;
		auto disAsmRes = reloc.Disassemble((uint64_t)oldFuncAddress, sizeof(HookJmp));
		if (!disAsmRes)
		{
			return HookError::ErrorDisAsmFailed;
		}
		
		BYTE* defaultByteArr = new BYTE[disAsmRes->totalBytes];
		memcpy(defaultByteArr, *oldFunc, disAsmRes->totalBytes);
		BYTE* hookByteArr = new BYTE[disAsmRes->totalBytes];
		BYTE* asmByteArr = new BYTE[disAsmRes->totalNewLength + sizeof(HookJmp)];
		if (funcHeapHandle == NULL)
		{
			funcHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (funcHeapHandle == NULL)
			{
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorMemoryAllocFailed;
			}
		}
		LPVOID allocAddress = HeapAlloc(funcHeapHandle, HEAP_ZERO_MEMORY, sizeof(HookJmp) + disAsmRes->totalNewLength);
		if (allocAddress == NULL)
		{
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorMemoryAllocFailed;
		}

		auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress));
		if (!relocToRes)
		{
			HeapFree(funcHeapHandle, 0, allocAddress);
			if (hookFuncAllocAddresses.size() == 0)
			{
				HeapDestroy(funcHeapHandle);
				funcHeapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorAsmFailed;
		}

		uintptr_t hookJmpBack = ((int)(*oldFunc) + disAsmRes->totalBytes) - ((int)allocAddress + relocToRes->bytes.size()) - 5;
		memcpy(asmByteArr, relocToRes->bytes.data(), relocToRes->bytes.size());
		memcpy(asmByteArr + relocToRes->bytes.size(), HookJmp, sizeof(HookJmp));
		memcpy(asmByteArr + relocToRes->bytes.size() + 1, &hookJmpBack, sizeof(hookJmpBack));

		if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, relocToRes->bytes.size() + sizeof(HookJmp), 0))
		{
			HeapFree(funcHeapHandle, 0, allocAddress);
			if (hookFuncAllocAddresses.size() == 0)
			{
				HeapDestroy(funcHeapHandle);
				funcHeapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorWriteMemoryFailed;
		}
		*oldFunc = allocAddress;

		int hookJmpTo = (int)newFunc - (int)oldFuncAddress - 5;
		memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
		memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

		FillNop(hookByteArr + sizeof(HookJmp), disAsmRes->totalBytes - sizeof(HookJmp));
		if (!WriteProcessMemory(GetCurrentProcess(), oldFuncAddress, hookByteArr, disAsmRes->totalBytes, 0))
		{
			HeapFree(funcHeapHandle, 0, allocAddress);
			if (hookFuncAllocAddresses.size() == 0)
			{
				HeapDestroy(funcHeapHandle);
				funcHeapHandle = NULL;
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorWriteMemoryFailed;
		}

		hookFuncOriginalCodes[*oldFunc].push(defaultByteArr);
		hookFuncOriginalCodeSizes[*oldFunc].push(disAsmRes->totalBytes);
		hookFuncAddresses[*oldFunc].push(oldFuncAddress);
		hookFuncAllocAddresses[*oldFunc].push(allocAddress);
		delete[] hookByteArr;
		delete[] asmByteArr;
		return HookError::ErrorOk;
	}

	bool HookFunctionStop(LPVOID* oldFunc)
	{
		LPVOID oldFunction = *oldFunc;
		if (hookFuncAddresses.count(oldFunction) == 0)
		{
			return false;
		}
		WriteProcessMemory(GetCurrentProcess(), hookFuncAddresses[oldFunction].top(), hookFuncOriginalCodes[oldFunction].top(), hookFuncOriginalCodeSizes[oldFunction].top(), 0);
		HeapFree(funcHeapHandle, 0, hookFuncAllocAddresses[oldFunction].top());
		delete[] hookFuncOriginalCodes[oldFunction].top();
		hookFuncOriginalCodes[oldFunction].pop();
		if (hookFuncOriginalCodes[oldFunction].empty())
		{
			hookFuncOriginalCodes.erase(oldFunction);
		}
		hookFuncOriginalCodeSizes[oldFunction].pop();
		if (hookFuncOriginalCodeSizes[oldFunction].empty())
		{
			hookFuncOriginalCodeSizes.erase(oldFunction);
		}
		*oldFunc = hookFuncAddresses[oldFunction].top();
		hookFuncAddresses[oldFunction].pop();
		if (hookFuncAddresses[oldFunction].empty())
		{
			hookFuncAddresses.erase(oldFunction);
		}
		hookFuncAllocAddresses[oldFunction].pop();
		if (hookFuncAllocAddresses[oldFunction].empty())
		{
			hookFuncAllocAddresses.erase(oldFunction);
		}
		if (hookFuncAddresses.size() == 0)
		{
			HeapDestroy(funcHeapHandle);
			funcHeapHandle = NULL;
		}
		return true;
	}

	Eflags Asm_Cmp(int32_t num1, int32_t num2)
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

	Eflags Asm_Test(int32_t num1, int32_t num2)
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
		if (RetAddress.count(theEspAdd) > 0)
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
			if (RetAddress.size() == 0 && MovEspAndJmpAddressAddress.size() == 0)
			{
				HeapDestroy(eipFuncHeapHandle);
				eipFuncHeapHandle = NULL;
			}
		}
	}

	int32_t Asm_Mov_Esp_And_Jmp(int32_t theEsp, int32_t theJmpAddress)
	{
		if (eipFuncHeapHandle == NULL)
		{
			eipFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (eipFuncHeapHandle == NULL)
			{
				return 0;
			}
		}
		if (MovEspAndJmpAddressAddress.count({ theEsp, theJmpAddress }) == 0)
		{
			LPVOID allocAddress = HeapAlloc(eipFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(MovEspByteArr) + sizeof(HookJmp));
			memcpy(allocAddress, MovEspByteArr, sizeof(MovEspByteArr));
			memcpy((LPVOID)((int32_t)allocAddress + 1), &theEsp, sizeof(theEsp));
			memcpy((LPVOID)((int32_t)allocAddress + sizeof(MovEspByteArr)), HookJmp, sizeof(HookJmp));
			int32_t aJmpTo = theJmpAddress - ((int32_t)allocAddress + sizeof(MovEspByteArr)) - 5;
			memcpy((LPVOID)((int32_t)allocAddress + sizeof(MovEspByteArr) + 1), &aJmpTo, sizeof(aJmpTo));
			MovEspAndJmpAddressAddress[{theEsp, theJmpAddress}] = allocAddress;
			return (int32_t)allocAddress;
		}
		else
		{
			return (int32_t)MovEspAndJmpAddressAddress[{theEsp, theJmpAddress}];
		}
	}

	void Asm_Mov_Esp_And_Jmp_Free(int32_t theEsp, int32_t theJmpAddress)
	{
		if (MovEspAndJmpAddressAddress.count({ theEsp, theJmpAddress }) > 0)
		{
			ZeroMemory((MovEspAndJmpAddressAddress[{theEsp, theJmpAddress}]), sizeof(MovEspByteArr) + sizeof(HookJmp));
			HeapFree(eipFuncHeapHandle, 0, MovEspAndJmpAddressAddress[{theEsp, theJmpAddress}]);
			MovEspAndJmpAddressAddress.erase({ theEsp, theJmpAddress });
			if (RetAddress.size() == 0 && MovEspAndJmpAddressAddress.size() == 0)
			{
				HeapDestroy(eipFuncHeapHandle);
				eipFuncHeapHandle = NULL;
			}
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
}