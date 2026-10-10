#include <map>
#include <stack>
#include <cmath>
#include <exception>
#include <tuple>
#include <Zydis/Zydis.h>
#include <asmjit/x86.h>
#include <asmjit/core.h>
//#pragma comment(lib, "capstone/capstone.lib")
#include "HookAsmCodeHeap.h"
#include "HookAsm.h"
#include "HookRelocator.h"
#include <string>
#include <string.h>
#include <intrin.h>

using namespace asmjit;

namespace HookAsm
{

	struct RspAndJmpAddress
	{
		int64_t mRsp;
		int64_t mJmpAddress;

		bool operator<(const RspAndJmpAddress& other) const {
			return std::tie(mRsp, mJmpAddress) < std::tie(other.mRsp, other.mJmpAddress);
		}
	};

	std::map<LPVOID, std::stack<const BYTE*>> hookOriginalCodes;
	std::map<LPVOID, std::stack<size_t>> hookOriginalCodeSizes;
	std::map<LPVOID, std::stack<LPVOID>> hookAllocAddresses;

	//CodeHeap* codeHeap = nullptr;
	std::vector<CodeHeap*> codeHeaps;

	std::map<LPVOID, std::stack<const BYTE*>> hookFuncOriginalCodes;
	std::map<LPVOID, std::stack<size_t>> hookFuncOriginalCodeSizes;
	std::map<LPVOID, std::stack<LPVOID>> hookFuncAddresses;
	std::map<LPVOID, std::stack<LPVOID>> hookFuncAllocAddresses;

	std::map<int16_t, LPVOID> RetAddress;
	std::map<RspAndJmpAddress, LPVOID> MovRspAndJmpAddressAddress;

	//constexpr BYTE HookCallByteArr[] = { 0x48,0x8D,0x64,0x24,0xF8,0xC7,0x04,0x24,0x00,0x00,0x00,0x00,0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x9C,0x50,0x51,0x52,0x53,0x48,0x8D,0x44,0x24,0x38,0x50,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x83,0x84,0x24,0x88,0x00,0x00,0x00,0x5E,0x48,0x83,0xEC,0x08,0x48,0x8D,0x4C,0x24,0x08,0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xD0,0x48,0x83,0xC4,0x08,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x48,0x83,0xC4,0x08,0x5B,0x5A,0x59,0x58,0x9D,0xC2,0x08,0x00,0x48,0x8B,0x64,0x24,0xC0 };
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
	constexpr BYTE HookJmpLong[] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	constexpr BYTE RetRspAddByteArr[] = { 0xC2,0,0 };
	constexpr BYTE RetByteArr[] = { 0xC3 };

	constexpr BYTE MovRspByteArr[] = { 0x48,0xBC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	HANDLE ripFuncHeapHandle = 0;

	long long htoi64(const char* _String)
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
		long long result = 0;
		for (int i = 0; i < len; i++)
		{
			if (_Str[len - i - 1] >= 'a' && _Str[len - i - 1] <= 'f')
			{
				result += ((long long)(10 + _Str[len - i - 1] - 'a')) * ((long long)1 << (4 * i));
			}
			else if (_Str[len - i - 1] >= '0' && _Str[len - i - 1] <= '9')
			{
				result += ((long long)(_Str[len - i - 1] - '0')) * ((long long)1 << (4 * i));
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

	std::vector<uint8_t> CreateHookCallByteArr(uint64_t hookCallbackAsmAddress,uint64_t fromAddress, bool isRSPAlign16Bytes, uint64_t hookCallBackAddress)
	{
		Environment env(asmjit::Arch::kX64);
		CodeHolder code;                        // 创建 CodeHolder
		code.init(env, hookCallbackAsmAddress);               // 初始化 CodeHolder 以匹配运行时环境

		x86::Assembler a(&code);
		//lea rsp,[rsp - 8]
		a.lea(x86::rsp, x86::ptr(x86::rsp, -8));
		//mov dword ptr [rsp],fromAddress(low32bit)
		uint32_t fromAddr32_l = (uint32_t)fromAddress;
		a.mov(x86::dword_ptr(x86::rsp), fromAddr32_l);
		//mov dword ptr [rsp+4],fromAddress(high32bit)
		uint32_t fromAddr32_h = ((uint64_t)fromAddress) >> 32;
		a.mov(x86::dword_ptr(x86::rsp, 4), fromAddr32_h);
		//call rip+5
		Label next = a.new_label();
		a.call(next);
		a.bind(next);

		a.pushfq();
		a.push(x86::rax);
		a.push(x86::rcx);
		a.push(x86::rdx);
		a.push(x86::rbx);
		//lea rax,[rsp+0x38]
		a.lea(x86::rax, x86::ptr(x86::rsp, 0x38));
		a.push(x86::rax);
		a.push(x86::rbp);
		a.push(x86::rsi);
		a.push(x86::rdi);
		a.push(x86::r8);
		a.push(x86::r9);
		a.push(x86::r10);
		a.push(x86::r11);
		a.push(x86::r12);
		a.push(x86::r13);
		a.push(x86::r14);
		a.push(x86::r15);
		//add dwprd ptr [rso+0x88],0x5E   (修正ret返回地址)
		a.add(x86::dword_ptr(x86::rsp, 0x88), 0x5E);
		uint8_t subRSPValue = isRSPAlign16Bytes ? 0x8 : 0x10;
		a.sub(x86::rsp, subRSPValue);
		//lea rcx,[rsp+0x8]/lea rcx,[rsp+0x10]
		a.lea(x86::rcx, x86::ptr(x86::rsp, subRSPValue));
		a.movabs(x86::rax, hookCallBackAddress);
		a.call(x86::rax);
		a.add(x86::rsp, subRSPValue);
		a.pop(x86::r15);
		a.pop(x86::r14);
		a.pop(x86::r13);
		a.pop(x86::r12);
		a.pop(x86::r11);
		a.pop(x86::r10);
		a.pop(x86::r9);
		a.pop(x86::r8);
		a.pop(x86::rdi);
		a.pop(x86::rsi);
		a.pop(x86::rbp);
		a.add(x86::rsp, 8);
		a.pop(x86::rbx);
		a.pop(x86::rdx);
		a.pop(x86::rcx);
		a.pop(x86::rax);
		a.popfq();
		a.ret(8);
		//mov rsp,[rsp-0x40]
		a.mov(x86::rsp, x86::ptr(x86::rsp, -0x40));

		const Section* text = code.text_section();
		if (!text) return {};
		const uint8_t* data = text->buffer().data();
		size_t size = text->buffer_size();
		return std::vector<uint8_t>(data, data + size);
	}

	HookError HookBegin(LPVOID hookAddress, HookCallBack callBack, bool isRSPAlign16Bytes, OriginalCodeLocation originalCodeLocation, bool isUseLongJump, size_t minDisAsmSize, LPCVOID jmpBackAddress)
	{
		HookAsm::HookRelocator reloc;
		size_t aTrueMinDisAsmSize = (minDisAsmSize >= 0 && minDisAsmSize <= (isUseLongJump ? sizeof(HookJmpLong) : sizeof(HookJmp))) ? (isUseLongJump ? sizeof(HookJmpLong) : sizeof(HookJmp)) : minDisAsmSize;
		auto disAsmRes = reloc.Disassemble((uint64_t)hookAddress, aTrueMinDisAsmSize);
		
		if (!disAsmRes)
		{
			return HookError::ErrorDisAsmFailed;
		}
		
		BYTE* defaultByteArr = new BYTE[disAsmRes->totalBytes];
		BYTE* hookByteArr = new BYTE[disAsmRes->totalBytes];
		LPVOID allocAddress = 0;
		CodeHeap* codeHeap = nullptr;
		size_t codeHeapPos = 0;
		// 用 dummy 地址生成一次，只为拿大小
		auto probe = CreateHookCallByteArr(
			/*hookCallbackAsmAddress=*/0x1000,
			/*fromAddress=*/0x2000,
			/*isRSPAlign16Bytes=*/false,
			/*hookCallBackAddress=*/0x3000);
		size_t stubSize = probe.size();
		for (size_t i = 0; i < codeHeaps.size() + 1; i++)
		{
			codeHeapPos = i;
			codeHeap = nullptr;
			auto CodeHeapAllocAddress = [&]() mutable -> bool {
				if (codeHeap == nullptr)
				{
					codeHeap = new CodeHeap(hookAddress);
				}
				try
				{
					allocAddress = codeHeap->Alloc(stubSize + disAsmRes->totalNewLength + sizeof(HookJmp));
				}
				catch (const CodeHeapException& e)
				{
					MessageBoxA(NULL, e.what(), "Error!", MB_OK | MB_ICONERROR);
					delete[] defaultByteArr;
					delete[] hookByteArr;
					return false;
				}
				return true;
				};
			if (i == codeHeaps.size())
			{
				bool isSuccess = CodeHeapAllocAddress();
				if (!isSuccess)
				{
					return HookError::ErrorMemoryAllocFailed;
				}
				codeHeaps.push_back(codeHeap);
				break;
			}
			else
			{
				codeHeap = codeHeaps[i];
				bool isSuccess = CodeHeapAllocAddress();
				if (!isSuccess)
				{
					return HookError::ErrorMemoryAllocFailed;
				}
				int64_t distance = (((int64_t)hookAddress) - ((int64_t)allocAddress + stubSize + disAsmRes->totalNewLength));
				if (distance > INT_MAX || distance < INT_MIN)
				{
					codeHeap->Free(allocAddress);
				}
				else
				{
					break;
				}
			}
		}

		//XEDPARSE asmByte;
		//asmByte.x64 = true;
		size_t asmLen = 0;
		/*BYTE asmByteArr[DISASM_SIZE + sizeof(HookCallByteArr) + sizeof(HookJmpLong)];*/
		BYTE* asmByteArr = new BYTE[disAsmRes->totalNewLength + stubSize + sizeof(HookJmpLong)];
		//int hookCall = 0;
		BYTE subRSPValue = isRSPAlign16Bytes ? 0x8 : 0x10;
		std::vector<uint8_t> hookCallByteArr;
		switch (originalCodeLocation)
		{
		case OriginalCodeLocation_Behind:
		{
			//hookCall = (long long)callBack - (long long)allocAddress - 0x20 - 5;
			hookCallByteArr = CreateHookCallByteArr((uint64_t)allocAddress, (uint64_t)hookAddress, isRSPAlign16Bytes, (uint64_t)callBack);
			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress + hookCallByteArr.size()));
			if (!relocToRes)
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}

			memcpy(asmByteArr, hookCallByteArr.data(), hookCallByteArr.size());

			memcpy(asmByteArr + hookCallByteArr.size(), relocToRes->bytes.data(), relocToRes->bytes.size());
			asmLen += relocToRes->bytes.size();

			//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((long long)allocAddress), asmByteArr, asmLen, 0);
			break;
		}
		case OriginalCodeLocation_Front:
		{
			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress));
			if (!relocToRes)
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}

			memcpy(asmByteArr, relocToRes->bytes.data(), relocToRes->bytes.size());
			asmLen += relocToRes->bytes.size();

			hookCallByteArr = CreateHookCallByteArr((uint64_t)allocAddress + asmLen, (uint64_t)hookAddress, isRSPAlign16Bytes, (uint64_t)callBack);

			memcpy(asmByteArr + asmLen, hookCallByteArr.data(), hookCallByteArr.size());
			break;
		}
		case OriginalCodeLocation_Without:
		{
			hookCallByteArr = CreateHookCallByteArr((uint64_t)allocAddress, (uint64_t)hookAddress, isRSPAlign16Bytes, (uint64_t)callBack);
			memcpy(asmByteArr, hookCallByteArr.data(), hookCallByteArr.size());
			break;
		}
		default:
			//VirtualFree(allocAddress, 0, MEM_RELEASE);
			codeHeap->Free(allocAddress);
			if (codeHeap->getMaxSize() == 0)
			{
				delete codeHeap;
				codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			delete[] asmByteArr;
			return HookError::ErrorBadParameter;
		}
		if (!isUseLongJump)
		{
			int hookJmpBack;
			if (jmpBackAddress != (LPCVOID)-1)
			{
				hookJmpBack = ((long long)jmpBackAddress) - (long long)allocAddress - hookCallByteArr.size() - asmLen - 5;
			}
			else
			{
				hookJmpBack = ((long long)hookAddress + disAsmRes->totalBytes) - (long long)allocAddress - hookCallByteArr.size() - asmLen - 5;
			}
			memcpy(asmByteArr + hookCallByteArr.size() + asmLen, HookJmp, sizeof(HookJmp));
			memcpy(asmByteArr + hookCallByteArr.size() + asmLen + 1, &hookJmpBack, sizeof(hookJmpBack));
			if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, hookCallByteArr.size() + sizeof(HookJmp) + asmLen, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
			memcpy(defaultByteArr, hookAddress, disAsmRes->totalBytes);
			int32_t hookJmpTo = (int32_t)((uint64_t)allocAddress - (uint64_t)hookAddress - 5);
			memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
			memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

			FillNop(hookByteArr + sizeof(HookJmp), disAsmRes->totalBytes - sizeof(HookJmp));

			if (!WriteProcessMemory(GetCurrentProcess(), hookAddress, hookByteArr, disAsmRes->totalBytes, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
		}
		else
		{
			uint64_t hookJmpBack;
			if (jmpBackAddress != (LPVOID)-1)
			{
				hookJmpBack = (uint64_t)jmpBackAddress;
			}
			else
			{
				hookJmpBack = ((uint64_t)hookAddress + disAsmRes->totalBytes);
			}
			memcpy(asmByteArr + hookCallByteArr.size() + asmLen, HookJmpLong, sizeof(HookJmpLong));
			memcpy(asmByteArr + hookCallByteArr.size() + asmLen + 6, &hookJmpBack, sizeof(hookJmpBack));
			if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, hookCallByteArr.size() + sizeof(HookJmpLong) + asmLen, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
			memcpy(defaultByteArr, hookAddress, disAsmRes->totalBytes);
			uint64_t hookJmpTo = (uint64_t)allocAddress;
			memcpy(hookByteArr, HookJmpLong, sizeof(HookJmpLong));
			memcpy(hookByteArr + 6, &hookJmpTo, sizeof(hookJmpTo));

			FillNop(hookByteArr + sizeof(HookJmpLong), disAsmRes->totalBytes - sizeof(HookJmpLong));
			if (!WriteProcessMemory(GetCurrentProcess(), hookAddress, hookByteArr, disAsmRes->totalBytes, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
		}
		hookOriginalCodes[hookAddress].push(defaultByteArr);
		hookOriginalCodeSizes[hookAddress].push(disAsmRes->totalBytes);
		hookAllocAddresses[hookAddress].push(allocAddress);
		delete[] asmByteArr;
		delete[] hookByteArr;
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
		for (size_t i = 0; i < codeHeaps.size(); i++)
		{
			if (codeHeaps[i]->Free(allocAddress))
			{
				if (codeHeaps[i]->getMaxSize() == 0)
				{
					delete codeHeaps[i];
					codeHeaps.erase(codeHeaps.begin() + i);
				}
				break;
			}
		}
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
		delete[] oldCode;
		return true;
	}

	HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc, bool isUseLongJump)
	{
		LPVOID oldFuncAddress = *oldFunc;

		HookAsm::HookRelocator reloc;
		size_t aTrueMinDisAsmSize = isUseLongJump ? sizeof(HookJmpLong) : sizeof(HookJmp);
		auto disAsmRes = reloc.Disassemble((uint64_t)oldFuncAddress, aTrueMinDisAsmSize);
		if (!disAsmRes)
		{
			return HookError::ErrorDisAsmFailed;
		}
		
		BYTE* defaultByteArr = new BYTE[disAsmRes->totalBytes];
		memcpy(defaultByteArr, *oldFunc, disAsmRes->totalBytes);
		//BYTE hookByteArr[DISASM_SIZE];
		BYTE* hookByteArr = new BYTE[disAsmRes->totalBytes];
		BYTE* asmByteArr = new BYTE[disAsmRes->totalNewLength + sizeof(HookJmpLong) + sizeof(HookJmp)];
		LPVOID allocAddress = 0;

		CodeHeap* codeHeap = nullptr;
		size_t codeHeapPos = 0;
		for (size_t i = 0; i < codeHeaps.size() + 1; i++)
		{
			codeHeapPos = i;
			codeHeap = nullptr;
			auto CodeHeapAllocAddress = [&]() mutable -> bool {
				if (codeHeap == nullptr)
				{
					codeHeap = new CodeHeap(oldFuncAddress);
				}
				try
				{
					allocAddress = codeHeap->Alloc(sizeof(HookJmpLong) + disAsmRes->totalNewLength + sizeof(HookJmpLong));
				}
				catch (const CodeHeapException& e)
				{
					MessageBoxA(NULL, e.what(), "Error!", MB_OK | MB_ICONERROR);
					delete[] defaultByteArr;
					return false;
				}
				return true;
				};
			if (i == codeHeaps.size())
			{
				bool isSuccess = CodeHeapAllocAddress();
				if (!isSuccess)
				{
					return HookError::ErrorMemoryAllocFailed;
				}
				codeHeaps.push_back(codeHeap);
				break;
			}
			else
			{
				codeHeap = codeHeaps[i];
				bool isSuccess = CodeHeapAllocAddress();
				if (!isSuccess)
				{
					return HookError::ErrorMemoryAllocFailed;
				}
				int64_t distance = (((int64_t)oldFuncAddress) - ((int64_t)allocAddress + sizeof(HookJmpLong) + disAsmRes->totalNewLength + sizeof(HookJmpLong)));
				if (distance > INT_MAX || distance < INT_MIN)
				{
					codeHeap->Free(allocAddress);
				}
				else
				{
					break;
				}
			}
		}
		if (!isUseLongJump)
		{
			memcpy(asmByteArr, HookJmpLong, sizeof(HookJmpLong));
			memcpy(asmByteArr + 6, &newFunc, sizeof(newFunc));
		}

		if (!isUseLongJump)
		{
			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress + sizeof(HookJmpLong)));
			if (!relocToRes)
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}
			int32_t hookJmpBack = ((int64_t)(*oldFunc) + disAsmRes->totalBytes) - ((int64_t)allocAddress + relocToRes->bytes.size() + sizeof(HookJmpLong)) - 5;
			memcpy(asmByteArr + sizeof(HookJmpLong), relocToRes->bytes.data(), relocToRes->bytes.size());
			memcpy(asmByteArr + sizeof(HookJmpLong) + relocToRes->bytes.size(), HookJmp, sizeof(HookJmp));
			memcpy(asmByteArr + sizeof(HookJmpLong) + relocToRes->bytes.size() + 1, &hookJmpBack, sizeof(hookJmpBack));
			if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, sizeof(HookJmpLong) + relocToRes->bytes.size() + sizeof(HookJmp), 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
			*oldFunc = (LPVOID)((uintptr_t)allocAddress + sizeof(HookJmpLong));

			int32_t hookJmpTo = (int32_t)((uintptr_t)allocAddress - (uintptr_t)oldFuncAddress - 5);
			memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
			memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

			FillNop(hookByteArr + sizeof(HookJmp), disAsmRes->totalBytes - sizeof(HookJmp));
			if(!WriteProcessMemory(GetCurrentProcess(), oldFuncAddress, hookByteArr, disAsmRes->totalBytes, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
		}
		else
		{
			auto relocToRes = reloc.RelocateTo(disAsmRes->instructions, ((uint64_t)allocAddress));
			if (!relocToRes)
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorAsmFailed;
			}
			uint64_t hookJmpBack = ((uint64_t)(*oldFunc) + disAsmRes->totalBytes);
			memcpy(asmByteArr, relocToRes->bytes.data(), relocToRes->bytes.size());
			memcpy(asmByteArr + relocToRes->bytes.size(), HookJmpLong, sizeof(HookJmpLong));
			memcpy(asmByteArr + relocToRes->bytes.size() + 6, &hookJmpBack, sizeof(hookJmpBack));
			if (!WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, relocToRes->bytes.size() + sizeof(HookJmpLong), 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
			*oldFunc = (LPVOID)((uintptr_t)allocAddress);

			uint64_t hookJmpTo = (uint64_t)newFunc;
			memcpy(hookByteArr, HookJmpLong, sizeof(HookJmpLong));
			memcpy(hookByteArr + 6, &hookJmpTo, sizeof(hookJmpTo));

			FillNop(hookByteArr + sizeof(HookJmpLong), disAsmRes->totalBytes - sizeof(HookJmpLong));
			if (!WriteProcessMemory(GetCurrentProcess(), oldFuncAddress, hookByteArr, disAsmRes->totalBytes, 0))
			{
				codeHeap->Free(allocAddress);
				if (codeHeap->getMaxSize() == 0)
				{
					delete codeHeap;
					codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
				}
				delete[] defaultByteArr;
				delete[] hookByteArr;
				delete[] asmByteArr;
				return HookError::ErrorWriteMemoryFailed;
			}
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
		//ZeroMemory(hookFuncAllocAddress[oldFunction], sizeof(HookJmp) + DISASM_SIZE);
		LPVOID allocAddress = hookFuncAllocAddresses[oldFunction].top();
		for (size_t i = 0; i < codeHeaps.size(); i++)
		{
			if (codeHeaps[i]->Free(allocAddress))
			{
				if (codeHeaps[i]->getMaxSize() == 0)
				{
					delete codeHeaps[i];
					codeHeaps.erase(codeHeaps.begin() + i);
				}
				break;
			}
		}
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
		return true;
	}


	int64_t Asm_Ret()
	{
		if (ripFuncHeapHandle == NULL)
		{
			ripFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (ripFuncHeapHandle == NULL)
			{
				return 0;
			}
		}
		if (RetAddress.count(0) == 0)
		{
			LPVOID allocAddress = HeapAlloc(ripFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(RetByteArr));
			memcpy(allocAddress, RetByteArr, sizeof(RetByteArr));
			RetAddress[0] = allocAddress;
			return (int64_t)allocAddress;
		}
		else
		{
			return (int64_t)RetAddress[0];
		}
	}

	int64_t Asm_Ret(int16_t theRspAdd)
	{
		if (theRspAdd == 0)
		{
			return Asm_Ret();
		}
		if (ripFuncHeapHandle == NULL)
		{
			ripFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (ripFuncHeapHandle == NULL)
			{
				return 0;
			}
		}
		if (RetAddress.count(theRspAdd) == 0)
		{
			LPVOID allocAddress = HeapAlloc(ripFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(RetRspAddByteArr));
			memcpy(allocAddress, RetRspAddByteArr, sizeof(RetRspAddByteArr));
			memcpy((LPVOID)((int64_t)allocAddress + 1), &theRspAdd, sizeof(theRspAdd));
			RetAddress[theRspAdd] = allocAddress;
			return (int64_t)allocAddress;
		}
		else
		{
			return (int64_t)RetAddress[theRspAdd];
		}
	}

	void Asm_Ret_Free(int16_t theRspAdd)
	{
		if (RetAddress.count(theRspAdd) > 0)
		{
			if (theRspAdd == 0)
			{
				ZeroMemory(RetAddress[0], sizeof(RetByteArr));
			}
			else
			{
				ZeroMemory(RetAddress[theRspAdd], sizeof(RetRspAddByteArr));
			}
			HeapFree(ripFuncHeapHandle, 0, RetAddress[theRspAdd]);
			RetAddress.erase(theRspAdd);
			if (RetAddress.size() == 0 && MovRspAndJmpAddressAddress.size() == 0)
			{
				HeapDestroy(ripFuncHeapHandle);
				ripFuncHeapHandle = NULL;
			}
		}
	}

	int64_t Asm_Mov_Rsp_And_Jmp(int64_t theRsp, int64_t theJmpAddress)
	{
		if (ripFuncHeapHandle == NULL)
		{
			ripFuncHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
			if (ripFuncHeapHandle == NULL)
			{
				return 0;
			}
		}
		if (MovRspAndJmpAddressAddress.count({ theRsp, theJmpAddress }) == 0)
		{
			LPVOID allocAddress = HeapAlloc(ripFuncHeapHandle, HEAP_ZERO_MEMORY, sizeof(MovRspByteArr) + sizeof(HookJmpLong));
			memcpy(allocAddress, MovRspByteArr, sizeof(MovRspByteArr));
			memcpy((LPVOID)((int64_t)allocAddress + 2), &theRsp, sizeof(theRsp));
			memcpy((LPVOID)((int64_t)allocAddress + sizeof(MovRspByteArr)), HookJmpLong, sizeof(HookJmpLong));
			memcpy((LPVOID)((int64_t)allocAddress + sizeof(MovRspByteArr) + 6), &theJmpAddress, sizeof(theJmpAddress));
			MovRspAndJmpAddressAddress[{theRsp, theJmpAddress}] = allocAddress;
			return (int64_t)allocAddress;
		}
		else
		{
			return (int64_t)MovRspAndJmpAddressAddress[{theRsp, theJmpAddress}];
		}
	}

	void Asm_Mov_Rsp_And_Jmp_Free(int64_t theRsp, int64_t theJmpAddress)
	{
		if (MovRspAndJmpAddressAddress.count({ theRsp, theJmpAddress }) > 0)
		{
			ZeroMemory((MovRspAndJmpAddressAddress[{theRsp, theJmpAddress}]), sizeof(MovRspByteArr) + sizeof(HookJmpLong));
			HeapFree(ripFuncHeapHandle, 0, MovRspAndJmpAddressAddress[{theRsp, theJmpAddress}]);
			MovRspAndJmpAddressAddress.erase({ theRsp, theJmpAddress });
			if (RetAddress.size() == 0 && MovRspAndJmpAddressAddress.size() == 0)
			{
				HeapDestroy(ripFuncHeapHandle);
				ripFuncHeapHandle = NULL;
			}
		}
	}

#pragma pack(push, 1)        // 取消结构体对齐填充
	alignas(64) volatile FXSAVE64_Area gFxsave_area;
#pragma pack(pop)              // 恢复默认对齐

	FXSAVE64_Area Asm_Fxsave()
	{
		FXSAVE64_Area result;
		_fxsave((void*)&gFxsave_area);
		memcpy(&result, (void*)&gFxsave_area, sizeof(FXSAVE64_Area));
		return result;
	}

	void Asm_Fxrstor(const FXSAVE64_Area& theFxsaveArea)
	{
		memcpy((void*)&gFxsave_area, &theFxsaveArea, sizeof(FXSAVE64_Area));
		_fxrstor((void*)&gFxsave_area);
	}

}