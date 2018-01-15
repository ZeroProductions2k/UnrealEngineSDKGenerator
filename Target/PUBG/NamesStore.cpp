#include <windows.h>

#include "PatternFinder.hpp"
#include "NamesStore.hpp"
#include "EngineClasses.hpp"

class FNameEntry
{
public:
	__int32 Index;
	char pad_0x0004[0x4];
	FNameEntry* HashNext;
	union
	{
		char AnsiName[1024];
		wchar_t WideName[1024];
	};

	const char* GetName() const
	{
		return AnsiName;
	}
};

template<typename ElementType, int32_t MaxTotalElements, int32_t ElementsPerChunk>
class TStaticIndirectArrayThreadSafeRead
{
public:
	int32_t Num() const
	{
		return NumElements;
	}

	bool IsValidIndex(int32_t index) const
	{
		return index >= 0 && index < Num() && GetById(index) != nullptr;
	}

	ElementType const* const& GetById(int32_t index) const
	{
		return *GetItemPtr(index);
	}

private:
	ElementType const* const* GetItemPtr(int32_t Index) const
	{
		int32_t ChunkIndex = Index / ElementsPerChunk;
		int32_t WithinChunkIndex = Index % ElementsPerChunk;
		ElementType** Chunk = Chunks[ChunkIndex];
		return Chunk + WithinChunkIndex;
	}

	enum
	{
		ChunkTableSize = (MaxTotalElements + ElementsPerChunk - 1) / ElementsPerChunk
	};

	ElementType** Chunks[ChunkTableSize];
	__int32 NumElements;
	__int32 NumChunks;
};

using TNameEntryArray = TStaticIndirectArrayThreadSafeRead<FNameEntry, 2 * 1024 * 1024, 16384>;

TNameEntryArray* GlobalNames = nullptr;

bool NamesStore::Initialize()
{
	// PUBG Pointer decryption
	// thx to Jeffeeee @ unknowncheats.me

	auto address = FindPattern(GetModuleHandleW(nullptr), reinterpret_cast<const unsigned char*>("\xE8\x00\x00\x00\x00\x0F\xB7\xC0\x48\x8B\xCF\x48\x8B\x1C\xC7\xE8\x00\x00\x00\x00\x48\x33\xC3\x48\x8B\xC8"), "x????xxxxxxxxxxx????xxxxxx");
	if (address == -1)
	{
		return false;
	}

	auto offset = *reinterpret_cast<int32_t*>(address + 0x01);
	auto Decrypt1 = reinterpret_cast<uintptr_t(*)(void*)>(address + 0x05 + offset);

	offset = *reinterpret_cast<int32_t*>(address + 0x10);
	auto Decrypt2 = reinterpret_cast<uintptr_t(*)(void*)>(address + 0x14 + offset);

	address = FindPattern(GetModuleHandleW(nullptr), reinterpret_cast<const unsigned char*>("\x49\x8D\x1C\xC4\xE8\x00\x00\x00\x00\x48\x33\x03\x75\x5E"), "xxxxx????xxxxx");
	if (address == -1)
	{
		return false;
	}

	offset = *reinterpret_cast<int32_t*>(address - 0x30);

	uintptr_t* pEncryptedPtr = reinterpret_cast<uintptr_t*>(address - 0x2C + offset);

	uintptr_t Xor1 = pEncryptedPtr[Decrypt1(pEncryptedPtr)];
	uintptr_t Xor2 = Decrypt2(pEncryptedPtr);

	GlobalNames = reinterpret_cast<decltype(GlobalNames)>(Xor1 ^ Xor2);

	return true;
}

void* NamesStore::GetAddress()
{
	return GlobalNames;
}

size_t NamesStore::GetNamesNum() const
{
	return GlobalNames->Num();
}

bool NamesStore::IsValid(size_t id) const
{
	return GlobalNames->IsValidIndex(static_cast<int32_t>(id));
}

std::string NamesStore::GetById(size_t id) const
{
	return GlobalNames->GetById(static_cast<int32_t>(id))->GetName();
}
