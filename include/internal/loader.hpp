#pragma once

#include "binarywriter.hpp"
#include "pe.hpp"
#include "peerror.hpp"

#include <Windows.h>
#include <optional>
#include <vector>
#include <winternl.h>

namespace Torpedo
{

class Module
{
public:
    Module(PVOID base, std::size_t imageSize) noexcept : _base{base}, _imageSize{imageSize} { Parse(); }
    ~Module() noexcept
    {
        for (auto module : _importModules)
        {
            FreeLibrary(module);
        }

        if (_base)
        {
            VirtualFree(_base, _imageSize, MEM_FREE);
        }
    }

    [[nodiscard]] constexpr bool Ok() const noexcept { return _ok; }

    [[nodiscard]] constexpr const auto DosHeader() const noexcept { return _dosHeader; }
    [[nodiscard]] constexpr const auto NtHeader() const noexcept { return _ntHeader; }
    [[nodiscard]] constexpr const auto& SectionHeaders() const noexcept { return _sectionHeaders; }
    [[nodiscard]] constexpr auto ImageBase() const noexcept { return _base; }

    [[nodiscard]] auto ImportDirectory() const noexcept
    {
        return FetchDataDirectory<IMAGE_IMPORT_DESCRIPTOR>(IMAGE_DIRECTORY_ENTRY_IMPORT);
    }

    [[nodiscard]] auto ExportDirectory() const noexcept
    {
        return FetchDataDirectory<IMAGE_EXPORT_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_EXPORT);
    }

    [[nodiscard]] auto RelocationDirectory() const noexcept
    {
        return FetchDataDirectory<IMAGE_BASE_RELOCATION>(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    }

    [[nodiscard]] auto TLSDirectory() const noexcept
    {
        return FetchDataDirectory<IMAGE_TLS_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_TLS);
    }

    [[nodiscard]] constexpr std::span<std::uint8_t> Data() noexcept
    {
        return {static_cast<std::uint8_t*>(_base), _imageSize};
    }

    constexpr void AddImportModule(HMODULE module) { _importModules.push_back(module); }

private:
    PVOID _base{};
    std::size_t _imageSize;
    IMAGE_DOS_HEADER* _dosHeader{};
    IMAGE_NT_HEADERS* _ntHeader{};
    std::vector<IMAGE_SECTION_HEADER*> _sectionHeaders{};
    std::vector<HMODULE> _importModules{};
    PEError _error{PEError::Success};
    bool _ok{false};

    void Parse()
    {
        _dosHeader = static_cast<IMAGE_DOS_HEADER*>(_base);
        if (_dosHeader->e_magic != IMAGE_DOS_SIGNATURE || _dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER))
        {
            SetError(PEError::InvalidPeFormat);
            return;
        }

        _ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(static_cast<std::byte*>(_base) + _dosHeader->e_lfanew);

        if (_ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            SetError(PEError::InvalidPeFormat);
            return;
        }

        if (_ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            SetError(PEError::NotSupportedMachine);
            return;
        }

        _sectionHeaders.reserve(_ntHeader->FileHeader.NumberOfSections);
        auto pSectionHeader = IMAGE_FIRST_SECTION(_ntHeader);
        for (int i = 0; i < _ntHeader->FileHeader.NumberOfSections; ++i)
        {
            _sectionHeaders.push_back(pSectionHeader++);
        }

        _ntHeader->OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(_base);

        _ok = true;
    }

    constexpr void SetError(PEError error) noexcept { _error = error; }

    template<typename T> [[nodiscard]] const T* FetchDataDirectory(int index) const noexcept
    {
        auto dataDirectory = _ntHeader->OptionalHeader.DataDirectory[index];
        if (dataDirectory.Size == 0)
        {
            return nullptr;
        }

        return reinterpret_cast<const T*>(static_cast<std::byte*>(_base) + dataDirectory.VirtualAddress);
    }
};

class ModuleLoader
{
public:
    ModuleLoader() = default;

    std::optional<Module> Load(const PE& pe)
    {
        if (not pe.Ok())
        {
            return {};
        }

        // alloc memory
        auto memory = VirtualAlloc(nullptr, pe.ImageSize(), MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
        if (memory == nullptr)
        {
            return {};
        }

        // copy image headers
        BinaryWriter bw{memory, pe.ImageSize()};
        const auto rawData = pe.Data();
        const auto& sectionHeaders = pe.SectionHeaders();
        const auto size =
            reinterpret_cast<std::size_t>(sectionHeaders[0]) - reinterpret_cast<std::size_t>(rawData.data());

        bw << std::span{rawData.begin(), size};

        for (const auto& sectionHeader : sectionHeaders)
        {
            bw << sectionHeader;
        }

        bw.Seek(sectionHeaders[0]->VirtualAddress);

        std::size_t pos{};

        for (const auto sectionHeader : sectionHeaders)
        {
            LoadSection(bw, rawData.subspan(sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData),
                        sectionHeader);
        }

        Module mod{memory, pe.ImageSize()};
        if (not mod.Ok() || BuildIAT(mod) == false)
        {
            return {};
        }

        auto delta = mod.NtHeader()->OptionalHeader.ImageBase - pe.NtHeader()->OptionalHeader.ImageBase;
        if (delta != 0)
        {
            RelocateBase(mod, delta);
        }

        if (FinalizeSection(mod) == false)
        {
            return {};
        }

        RunTLSCallbacks(mod);

        return mod;
    }

private:
    bool LoadSection(BinaryWriter& bw, std::span<const std::uint8_t> data, const IMAGE_SECTION_HEADER* sectionHeader)
    {
        bw.Seek(sectionHeader->VirtualAddress);
        bw << data;

        return true;
    }

    bool BuildIAT(Module& mod)
    {
        auto importDirectory = mod.ImportDirectory();
        if (importDirectory == nullptr)
        {
            return true;
        }

        auto rawData = mod.Data();
        while (importDirectory->Characteristics)
        {
            const char* dll = reinterpret_cast<const char*>(&rawData[importDirectory->Name]);

            auto module = LoadLibraryA(dll);
            if (module == nullptr)
            {
                return false;
            }

            auto OFT = reinterpret_cast<std::size_t*>(&rawData[importDirectory->OriginalFirstThunk]);
            if (importDirectory->OriginalFirstThunk == 0)
            {
                OFT = reinterpret_cast<std::size_t*>(&rawData[importDirectory->FirstThunk]);
            }

            auto IAT = reinterpret_cast<std::uintptr_t*>(&rawData[importDirectory->FirstThunk]);

            while (*OFT != 0)
            {
                std::uintptr_t function{};
                if (IMAGE_SNAP_BY_ORDINAL(*OFT))
                {
                    function = reinterpret_cast<std::uintptr_t>(
                        GetProcAddress(module, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(*OFT))));
                }
                else
                {
                    auto iin = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(&rawData[*OFT]);
                    function = reinterpret_cast<std::uintptr_t>(GetProcAddress(module, iin->Name));
                }

                if (function == 0)
                {
                    return false;
                }

                *IAT++ = function;
                ++OFT;
            }

            mod.AddImportModule(module);
            ++importDirectory;
        }

        return true;
    }

    void RelocateBase(Module& mod, std::uint64_t delta)
    {
        auto relocTable = mod.RelocationDirectory();
        if (relocTable == nullptr)
        {
            return;
        }

        auto base = mod.Data();
        while (relocTable->VirtualAddress)
        {
            auto reloc = reinterpret_cast<const WORD*>(relocTable + 1);
            while (*reloc)
            {
                auto dest = &base[relocTable->VirtualAddress + (*reloc & 0xfff)];
                switch (auto type = *reloc >> 12; type)
                {
                case IMAGE_REL_BASED_DIR64:
                    *reinterpret_cast<std::uint64_t*>(dest) += delta;
                    break;
                }

                ++reloc;
            }

            relocTable = reinterpret_cast<decltype(relocTable)>(reinterpret_cast<std::uintptr_t>(relocTable) +
                                                                relocTable->SizeOfBlock);
        }
    }

    bool FinalizeSection(Module& mod)
    {
        auto isBitSet = [&](auto flags, auto flag) { return (flags & flag) == flag; };
        auto imageBase = static_cast<std::uint8_t*>(mod.ImageBase());

        for (auto sectionHeader : mod.SectionHeaders())
        {
            auto isWritable = isBitSet(sectionHeader->Characteristics, IMAGE_SCN_MEM_WRITE);
            auto isExecutable = isBitSet(sectionHeader->Characteristics, IMAGE_SCN_MEM_EXECUTE);

            DWORD newProtect{};

            if (isWritable)
            {
                newProtect = isExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            }
            else
            {
                newProtect = isExecutable ? PAGE_EXECUTE_READ : PAGE_READONLY;
            }

            DWORD oldProtect{};
            auto result = VirtualProtect(imageBase + sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize,
                                         newProtect, &oldProtect);

            if (result == FALSE)
            {
                return false;
            }
        }

        return true;
    }

    void RunTLSCallbacks(Module& mod)
    {
        auto tlsDirectory = mod.TLSDirectory();
        if (tlsDirectory == nullptr)
        {
            return;
        }

        auto imageBase = mod.ImageBase();
        auto tlsCallbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);
        while (*tlsCallbacks)
        {
            (*tlsCallbacks)(imageBase, DLL_PROCESS_ATTACH, nullptr);
            ++tlsCallbacks;
        }
    }
};

} // namespace Torpedo
