#include "HookAsmCodeHeap.h"

constexpr size_t HEAP_SIZE = USN_PAGE_SIZE;

CodeHeap::CodeHeap(LPVOID address)
{
	maxSize = 0;
	/*LPVOID allocAddress = CreateHeap(address);
	if (allocAddress == 0)
	{
		throw CodeHeapException("Code heap allocation failed!");
	}*/
	allocAddress = address;
	//baseAddress.push_back(allocAddress);
	//maxSize += HEAP_SIZE;
}

CodeHeap::~CodeHeap()
{
	for (int i = 0; i < baseAddress.size(); i++)
	{
		DestroyHeap(baseAddress[i].baseAddress);
	}
}

LPVOID CodeHeap::Alloc(size_t allocSize)
{
	size_t currentSize = 0;
	if (allocArr.size() > 0)
	{
		for (size_t i = 0; i < allocArr.size(); i++)
		{
			currentSize += allocArr[i].size;
			if (allocArr[i].isFree && allocArr[i].size >= allocSize)
			{
				baseAddress[allocArr[i].baseAddressId].allocCount++;
				allocArr[i].isFree = false;
				return allocArr[i].address;
			}
		}
	}
	if ((currentSize + allocSize) > maxSize)
	{
		LPVOID allocAddress = CreateHeap(this->allocAddress);
		if (allocAddress == 0)
		{
			throw CodeHeapException("Code heap allocation failed!");
		}
		baseAddress.push_back(allocAddress);
		baseAddress[baseAddress.size() - 1].allocCount++;
		maxSize += HEAP_SIZE;
		allocArr.push_back(CodeHeapData(allocAddress, allocSize, baseAddress.size() - 1));
		return allocAddress;
	}
	else
	{
		size_t arrLen = allocArr.size();
		LPVOID allocAddress = 0;
		/*if (arrLen == 0)
		{
			allocAddress = baseAddress[0].baseAddress;
			allocArr.push_back(CodeHeapData(allocAddress, allocSize, 0));
		}
		else
		{
			allocAddress = (LPVOID)((long long)allocArr[arrLen - 1].address + allocArr[arrLen - 1].size);
			allocArr.push_back(CodeHeapData(allocAddress, allocSize, allocArr[arrLen - 1].baseAddressId));
		}*/
		allocAddress = (LPVOID)((long long)allocArr[arrLen - 1].address + allocArr[arrLen - 1].size);
		allocArr.push_back(CodeHeapData(allocAddress, allocSize, allocArr[arrLen - 1].baseAddressId));
		baseAddress[allocArr[arrLen - 1].baseAddressId].allocCount++;
		return allocAddress;
	}
}

bool CodeHeap::Free(LPVOID address)
{
	if (allocArr.size() > 0)
	{
		for (size_t i = 0; i < allocArr.size(); i++)
		{
			if (address == allocArr[i].address)
			{
				ZeroMemory(allocArr[i].address, allocArr[i].size);
				size_t baseAddressId = allocArr[i].baseAddressId;
				bool isRemoveResidues = false;
				//if (baseAddress[baseAddressId].allocCount == 1 && baseAddressId == (baseAddress.size() - 1))
				if (baseAddress[baseAddressId].allocCount == 1)
				{
					bool result = DestroyHeap(baseAddress[baseAddressId].baseAddress);
					if (result == false)
					{
						return false;
					}
					baseAddress.erase(baseAddress.begin() + baseAddressId);
					maxSize -= HEAP_SIZE;
					isRemoveResidues = true;
				}
				if ((allocArr.size() - 1) == i)
				{
					allocArr.pop_back();
				}
				else
				{
					allocArr[i].isFree = true;
				}
				if (isRemoveResidues)
				{
					size_t tempTarget = -1;
					size_t targetCount = 0;
					for (size_t j = 0; j < allocArr.size(); j++)
					{
						size_t tempId = allocArr[j].baseAddressId;
						if (tempId == baseAddressId)
						{
							if (tempTarget == -1)
							{
								tempTarget = j;
							}
							targetCount++;
						}
					}
					for (size_t j = 0; j < targetCount; j++)
					{
						allocArr.erase(allocArr.begin() + tempTarget);
					}
				}
				else
				{
					baseAddress[baseAddressId].allocCount--;
				}
				return true;
			}
		}
	}
	return false;
}

LPVOID CodeHeap::CreateHeap(LPVOID address)
{
	LPVOID allocAddress = 0;
	long long distance = 0;
	bool before = false;
	while (allocAddress == 0)
	{
		allocAddress = VirtualAlloc((LPVOID)((long long)address + distance), HEAP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (before)
		{
			distance -= USN_PAGE_SIZE;
			if (distance < INT_MIN)
			{
				return 0;
			}
		}
		else
		{
			distance += USN_PAGE_SIZE;
			if (distance > INT_MAX)
			{
				distance = 0;
				before = true;
				continue;
			}
		}
	}
	return allocAddress;
}

bool CodeHeap::DestroyHeap(LPVOID address)
{
	return VirtualFree(address, 0, MEM_RELEASE);
}