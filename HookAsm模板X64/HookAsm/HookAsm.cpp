#include <map>
#include <cmath>
#include <exception>
#include "capstone/capstone.h"
#define ASMTK_STATIC
#define ASMJIT_EMBED
#define ASMJIT_STATIC
#define ASMJIT_BUILD_RELEASE
#include "asmtk/asmjit/asmjit.h"
#include "asmtk/asmtk.h"
//#pragma comment(lib, "capstone/capstone.lib")
#include "HookAsmCodeHeap.h"
#include "HookAsm.h"
#include <string>
#include <string.h>

std::map<LPVOID, const BYTE*> hookOriginalCode;
std::map<LPVOID, size_t> hookOriginalCodeSize;
std::map<LPVOID, LPVOID> hookAllocAddress;

//CodeHeap* codeHeap = nullptr;
std::vector<CodeHeap*> codeHeaps;

std::map<LPVOID, const BYTE*> hookFuncOriginalCode;
std::map<LPVOID, size_t> hookFuncOriginalCodeSize;
std::map<LPVOID, LPVOID> hookFuncAddress;
std::map<LPVOID, LPVOID> hookFuncAllocAddress;

constexpr BYTE HookCallByteArr[] = { 0x48,0x8D,0x64,0x24,0xF8,0xC7,0x04,0x24,0x00,0x00,0x00,0x00,0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x9C,0x50,0x51,0x52,0x53,0x48,0x8D,0x44,0x24,0x38,0x50,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x83,0x84,0x24,0x88,0x00,0x00,0x00,0x5E,0x48,0x83,0xEC,0x08,0x48,0x8D,0x4C,0x24,0x08,0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xD0,0x48,0x83,0xC4,0x08,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x48,0x83,0xC4,0x08,0x5B,0x5A,0x59,0x58,0x9D,0xC2,0x08,0x00,0x48,0x8B,0x64,0x24,0xC0 };
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
	DisAsmStr resultStrList;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle) != CS_ERR_OK)
	{
		return DisAsmStr();
	}

	cs_option(csHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	uint8_t byteArr[DISASM_SIZE];
	ReadProcessMemory(GetCurrentProcess(), address, byteArr, DISASM_SIZE, 0);
	count = cs_disasm(csHandle, byteArr, DISASM_SIZE, (uint64_t)address, 0, &insn);
	if (count > 0)
	{
		for (int i = 0; i < count; i++)
		{
			/*char* str = new char[192];
			strcpy_s(str, 192, insn[i].mnemonic);
			strcat_s(str, 192, " ");
			strcat_s(str, 192, insn[i].op_str);*/
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

			std::string str = asmMnemonic + std::string(" ") + asmOp_Str;

			/*DisAsmStr disAsmStr;
			disAsmStr.asmStr = str;*/
			/*char numStr[30];
			char hexStr[30];*/
			if (str.find("[") != std::string::npos)
			{
				std::string addressStr = str.substr(str.find("[") + 1, str.find("]") - str.find("[") - 1);
				size_t position = addressStr.find(' ');
				while (position != std::string::npos)
				{
					addressStr.erase(position, 1);
					position = addressStr.find(' ', position);
				}
				size_t ripPos = addressStr.find("rip");
				if (ripPos != std::string::npos)
				{
					size_t operatorPos = ripPos + strlen("rip");
					if (operatorPos != addressStr.size())
					{
						long long deviationAddr = htoi64(addressStr.substr(operatorPos + 1).c_str());
						char numStr[30];
						//char hexStr[30];
						std::string hexStr = std::string();
						if (addressStr[operatorPos] == '+')
						{
							_i64toa_s((long long)address + insn[i].size + resultStrList.asmByteSize + deviationAddr, numStr, sizeof(numStr), 16);
						}
						if (addressStr[operatorPos] == '-')
						{
							_i64toa_s((long long)address + insn[i].size + resultStrList.asmByteSize - deviationAddr, numStr, sizeof(numStr), 16);
						}
						hexStr = "0x" + std::string(numStr);
						str.replace(str.find("[") + 1, str.find("]") - str.find("[") - 1, hexStr);
					}
				}
			}
			/*_i64toa_s((long long)address + insn[i].size + len, numStr, sizeof(numStr), 16);
			sprintf_s(hexStr, "0x%s", numStr);
			size_t ripPos = disAsmStr.asmStr.find("rip");
			if (ripPos != -1)
			{
				disAsmStr.asmStr.replace(ripPos, strlen("rip"), hexStr);
			}*/
			resultStrList.asmStr += (str + "\n");
			resultStrList.asmByteSize += insn[i].size;
			if (resultStrList.asmByteSize >= 5)
			{
				break;
			}
		}
		cs_free(insn, count);
		cs_close(&csHandle);
		return resultStrList;
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

bool HookBegin(LPVOID hookAddress, HookCallBack callBack, OriginalCodeLocation originalCodeLocation, LPCVOID jmpBackAddress)
{
	//if (hookAllocAddress.count(hookAddress) > 0)
	//{
	//	return false;
	//}
	DisAsmStr disAsmStr = HookDisAsm(hookAddress);
	if (disAsmStr.asmByteSize == 0)
	{
		return false;
	}
	for (size_t i = 1; i < DISASM_SIZE; i++)
	{
		LPVOID findAddress = (LPVOID)((long long)hookAddress - i);
		if (hookAllocAddress.count(findAddress) > 0)
		{
			if (hookOriginalCodeSize[findAddress] > i)
			{
				return false;
			}
		}
	}
	for (size_t i = 0; i < disAsmStr.asmByteSize; i++)
	{
		LPVOID findAddress = (LPVOID)((long long)hookAddress + i);
		if (hookAllocAddress.count(findAddress) > 0)
		{
			return false;
		}
	}
	BYTE* defaultByteArr = new BYTE[disAsmStr.asmByteSize];
	BYTE* hookByteArr = new BYTE[disAsmStr.asmByteSize];
	LPVOID allocAddress = 0;
	/*long long distance = 0;
	bool before = false;
	while (allocAddress == 0)
	{
		if (before)
		{
			distance -= 4096;
			if (distance < INT_MIN)
			{
				delete[] defaultByteArr;
				delete[] hookByteArr;
				return false;
			}
		}
		else
		{
			distance += 4096;
			if (distance > INT_MAX)
			{
				distance = 0;
				before = true;
				continue;
			}
		}
		allocAddress = VirtualAlloc((LPVOID)((long long)hookAddress + distance), sizeof(HookCallByteArr) + DISASM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	}*/
	CodeHeap* codeHeap = nullptr;
	size_t codeHeapPos = 0;
	for (size_t i = 0; i < codeHeaps.size() + 1; i++)
	{
		codeHeapPos = i;
		codeHeap = nullptr;
		auto CodeHeapAllocAddress = [&]() mutable {
			if (codeHeap == nullptr)
			{
				codeHeap = new CodeHeap(hookAddress);
			}
			try
			{
				allocAddress = codeHeap->Alloc(sizeof(HookCallByteArr) + DISASM_SIZE);
			}
			catch (const CodeHeapException& e)
			{
				MessageBoxA(NULL, e.what(), "Error!", MB_OK | MB_ICONERROR);
				delete[] defaultByteArr;
				delete[] hookByteArr;
				return false;
			}
			};
		if (i == codeHeaps.size())
		{
			CodeHeapAllocAddress();
			codeHeaps.push_back(codeHeap);
			break;
		}
		else
		{
			codeHeap = codeHeaps[i];
			CodeHeapAllocAddress();
			int64_t distance = (((uint64_t)hookAddress) - ((uint64_t)allocAddress + sizeof(HookCallByteArr) + DISASM_SIZE));
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
	int asmLen = 0;
	BYTE asmByteArr[DISASM_SIZE + sizeof(HookCallByteArr) + sizeof(HookJmp)];
	//int hookCall = 0;
	switch (originalCodeLocation)
	{
	case OriginalCodeLocation_Behind:
	{
		//hookCall = (long long)callBack - (long long)allocAddress - 0x20 - 5;
		memcpy(asmByteArr, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + 0x4A, &callBack, sizeof(callBack));
		uint32_t fromAddr = (uint32_t)hookAddress;
		memcpy(asmByteArr + 8, &fromAddr, sizeof(fromAddr));
		fromAddr = ((uint64_t)hookAddress) >> 32;
		memcpy(asmByteArr + 16, &fromAddr, sizeof(fromAddr));

		asmjit::Environment env(asmjit::Arch::kX64);
		asmjit::CodeHolder code;
		code.init(env, ((long long)allocAddress + sizeof(HookCallByteArr)));

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
			codeHeap->Free(allocAddress);
			if (codeHeap->getMaxSize() == 0)
			{
				delete codeHeap;
				codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			return false;
		}

		// Now you can print the code, which is stored in the first section (.text).
		asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();
		//asmByte.cip = ((long long)allocAddress + sizeof(HookCallByteArr) + asmLen);
		//MessageBoxA(0, disAsmStrList[i].asmStr.c_str(), 0, MB_OK);
		//strcpy_s(asmByte.instr, disAsmStrList[i].asmStr.c_str());
		//XEDParseAssemble(&asmByte);
		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((int)allocAddress + sizeof(HookCallByteArr) + asmLen), asmByte.dest, asmByte.dest_size, 0);
		memcpy(asmByteArr + sizeof(HookCallByteArr), codeBuffer.data(), codeBuffer.size());
		asmLen += codeBuffer.size();

		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((long long)allocAddress), asmByteArr, asmLen, 0);
		break;
	}
	case OriginalCodeLocation_Front:
	{
		asmjit::Environment env(asmjit::Arch::kX64);
		asmjit::CodeHolder code;
		code.init(env, ((long long)allocAddress));

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
			codeHeap->Free(allocAddress);
			if (codeHeap->getMaxSize() == 0)
			{
				delete codeHeap;
				codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
			}
			delete[] defaultByteArr;
			delete[] hookByteArr;
			return false;
		}

		// Now you can print the code, which is stored in the first section (.text).
		asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();
		//asmByte.cip = ((long long)allocAddress + asmLen);
		//MessageBoxA(0, disAsmStrList[i].asmStr.c_str(), 0, MB_OK);
		//strcpy_s(asmByte.instr, disAsmStrList[i].asmStr.c_str());
		//XEDParseAssemble(&asmByte);
		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)((int)allocAddress + sizeof(HookCallByteArr) + asmLen), asmByte.dest, asmByte.dest_size, 0);
		memcpy(asmByteArr, codeBuffer.data(), codeBuffer.size());
		asmLen += codeBuffer.size();

		memcpy(asmByteArr + asmLen, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + asmLen + 0x4A, &callBack, sizeof(callBack));
		uint32_t fromAddr = (uint32_t)hookAddress;
		memcpy(asmByteArr + asmLen + 8, &fromAddr, sizeof(fromAddr));
		fromAddr = ((uint64_t)hookAddress) >> 32;
		memcpy(asmByteArr + asmLen + 16, &fromAddr, sizeof(fromAddr));
		break;
	}
	case OriginalCodeLocation_Without:
	{
		memcpy(asmByteArr, HookCallByteArr, sizeof(HookCallByteArr));
		memcpy(asmByteArr + 0x4A, &callBack, sizeof(callBack));
		uint32_t fromAddr = (uint32_t)hookAddress;
		memcpy(asmByteArr + 8, &fromAddr, sizeof(fromAddr));
		fromAddr = ((uint64_t)hookAddress) >> 32;
		memcpy(asmByteArr + 16, &fromAddr, sizeof(fromAddr));
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
		return false;
	}
	int hookJmpBack;
	if (jmpBackAddress != (LPCVOID)-1)
	{
		hookJmpBack = ((long long)jmpBackAddress) - (long long)allocAddress - sizeof(HookCallByteArr) - asmLen - 5;
	}
	else
	{
		hookJmpBack = ((long long)hookAddress + disAsmStr.asmByteSize) - (long long)allocAddress - sizeof(HookCallByteArr) - asmLen - 5;
	}
	memcpy(asmByteArr + sizeof(HookCallByteArr) + asmLen, HookJmp, sizeof(HookJmp));
	memcpy(asmByteArr + sizeof(HookCallByteArr) + asmLen + 1, &hookJmpBack, sizeof(hookJmpBack));
	WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, sizeof(HookCallByteArr) + sizeof(HookJmp) + asmLen, 0);
	memcpy(defaultByteArr, hookAddress, disAsmStr.asmByteSize);
	hookOriginalCode[hookAddress] = defaultByteArr;
	hookOriginalCodeSize[hookAddress] = disAsmStr.asmByteSize;
	hookAllocAddress[hookAddress] = allocAddress;
	int hookJmpTo = (long long)allocAddress - (long long)hookAddress - 5;
	memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
	memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

	FillNop(hookByteArr + sizeof(HookJmp), disAsmStr.asmByteSize - sizeof(HookJmp));

	WriteProcessMemory(GetCurrentProcess(), hookAddress, hookByteArr, disAsmStr.asmByteSize, 0);
	delete[] hookByteArr;
	return true;
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
	hookOriginalCodeSize.erase(hookAddress);
	hookOriginalCode.erase(hookAddress);
	hookAllocAddress.erase(hookAddress);
	delete[] oldCode;
	return true;
}

bool HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc)
{
	for (std::map<LPVOID, LPVOID>::reverse_iterator iter = hookFuncAddress.rbegin(); iter != hookFuncAddress.rend(); iter++)
	{
		if (iter->second == *oldFunc)
		{
			return false;
		}
	}
	if (hookFuncAddress.count(*oldFunc) > 0)
	{
		return false;
	}
	LPVOID oldFuncAddress = *oldFunc;
	DisAsmStr disAsmStr = HookDisAsm(*oldFunc);
	BYTE* defaultByteArr = new BYTE[disAsmStr.asmByteSize];
	memcpy(defaultByteArr, *oldFunc, disAsmStr.asmByteSize);
	BYTE hookByteArr[DISASM_SIZE];
	BYTE asmByteArr[DISASM_SIZE + sizeof(HookJmpLong)];
	LPVOID allocAddress = 0;

	CodeHeap* codeHeap = nullptr;
	size_t codeHeapPos = 0;
	for (size_t i = 0; i < codeHeaps.size() + 1; i++)
	{
		codeHeapPos = i;
		codeHeap = nullptr;
		auto CodeHeapAllocAddress = [&]() mutable {
			if (codeHeap == nullptr)
			{
				codeHeap = new CodeHeap(oldFuncAddress);
			}
			try
			{
				allocAddress = codeHeap->Alloc(sizeof(HookJmpLong) + DISASM_SIZE);
			}
			catch (const CodeHeapException& e)
			{
				MessageBoxA(NULL, e.what(), "Error!", MB_OK | MB_ICONERROR);
				delete[] defaultByteArr;
				return false;
			}
			};
		if (i == codeHeaps.size())
		{
			CodeHeapAllocAddress();
			codeHeaps.push_back(codeHeap);
			break;
		}
		else
		{
			codeHeap = codeHeaps[i];
			CodeHeapAllocAddress();
			int64_t distance = (((uint64_t)oldFuncAddress) - ((uint64_t)allocAddress + sizeof(HookJmpLong) + DISASM_SIZE));
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

	memcpy(asmByteArr, HookJmpLong, sizeof(HookJmpLong));
	memcpy(asmByteArr + 6, &newFunc, sizeof(newFunc));

	asmjit::Environment env(asmjit::Arch::kX64);
	asmjit::CodeHolder code;
	code.init(env, (uint64_t)((long long)allocAddress + sizeof(HookJmpLong)));

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
		codeHeap->Free(allocAddress);
		if (codeHeap->getMaxSize() == 0)
		{
			delete codeHeap;
			codeHeaps.erase(codeHeaps.begin() + codeHeapPos);
		}
		delete[] defaultByteArr;
		return false;
	}

	// Now you can print the code, which is stored in the first section (.text).

	asmjit::CodeBuffer& codeBuffer = code.sectionById(0)->buffer();
	uintptr_t hookJmpBack = ((uintptr_t)(*oldFunc) + disAsmStr.asmByteSize) - ((uintptr_t)allocAddress + codeBuffer.size() + sizeof(HookJmpLong)) - 5;
	memcpy(asmByteArr + sizeof(HookJmpLong), codeBuffer.data(), codeBuffer.size());
	memcpy(asmByteArr + sizeof(HookJmpLong) + codeBuffer.size(), HookJmp, sizeof(HookJmp));
	memcpy(asmByteArr + sizeof(HookJmpLong) + codeBuffer.size() + 1, &hookJmpBack, sizeof(hookJmpBack));
	WriteProcessMemory(GetCurrentProcess(), allocAddress, asmByteArr, sizeof(HookJmpLong) + codeBuffer.size() + sizeof(HookJmp), 0);
	*oldFunc = (LPVOID)((uintptr_t)allocAddress + sizeof(HookJmpLong));

	int hookJmpTo = (uintptr_t)allocAddress - (int)oldFuncAddress - 5;
	memcpy(hookByteArr, HookJmp, sizeof(HookJmp));
	memcpy(hookByteArr + 1, &hookJmpTo, sizeof(hookJmpTo));

	FillNop(hookByteArr + sizeof(HookJmp), disAsmStr.asmByteSize - sizeof(HookJmp));
	WriteProcessMemory(GetCurrentProcess(), oldFuncAddress, hookByteArr, disAsmStr.asmByteSize, 0);

	hookFuncOriginalCode[*oldFunc] = defaultByteArr;
	hookFuncOriginalCodeSize[*oldFunc] = disAsmStr.asmByteSize;
	hookFuncAddress[*oldFunc] = oldFuncAddress;
	hookFuncAllocAddress[*oldFunc] = allocAddress;
	return true;
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
	LPVOID allocAddress = hookFuncAllocAddress[oldFunction];
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
	delete hookFuncOriginalCode[oldFunction];
	hookFuncOriginalCode.erase(oldFunction);
	hookFuncOriginalCodeSize.erase(oldFunction);
	*oldFunc = hookFuncAddress[oldFunction];
	hookFuncAddress.erase(oldFunction);
	hookFuncAllocAddress.erase(oldFunction);
	return true;
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
