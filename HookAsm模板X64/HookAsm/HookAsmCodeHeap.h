#pragma once
#include "HookAsm.h"

struct CodeHeapData
{
	CodeHeapData(LPVOID address, size_t size, size_t baseAddressId) :address(address), size(size), isFree(false), baseAddressId(baseAddressId) {}
	CodeHeapData() :address(0), size(0), isFree(false), baseAddressId(0) {}
	LPVOID address;
	size_t size;
	bool isFree;
	size_t baseAddressId;
};

struct BaseAddress
{
	BaseAddress(LPVOID address) :baseAddress(address), allocCount(0) {}
	BaseAddress() : baseAddress(0), allocCount(0) {}
	LPVOID baseAddress;
	size_t allocCount;
};

class CodeHeapException : public std::exception
{
private:
	std::string message;

public:
	CodeHeapException(std::string message) : message(message) {}

	virtual const char* what() const throw()
	{
		return message.c_str();
	}
};

class CodeHeap
{
private:
	LPVOID allocAddress;
	std::vector<BaseAddress> baseAddress;
	std::vector<CodeHeapData> allocArr;
	//std::vector<CodeHeapData> middleFreeArr;
	size_t maxSize;

	bool DestroyHeap(LPVOID address);
	LPVOID CreateHeap(LPVOID address);
public:
	CodeHeap(LPVOID address);
	~CodeHeap();
	LPVOID Alloc(size_t allocSize);
	bool Free(LPVOID address);
	size_t getMaxSize()
	{
		return maxSize;
	}
};