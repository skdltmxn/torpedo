#pragma once

#include "peerror.hpp"
#include "streamreader.hpp"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <vector>

namespace Torpedo
{

namespace detail
{

constexpr bool inBetween(auto x, auto lb, auto ub)
{
    return (lb <= x) && (x < ub);
}

constexpr bool rvaInSection(std::uint32_t rva, const IMAGE_SECTION_HEADER* header)
{
    return inBetween(rva, header->VirtualAddress, header->VirtualAddress + header->Misc.VirtualSize);
}

} // namespace detail

class PE
{
public:
    PE(const std::filesystem::path& path) noexcept
    {
        std::ifstream ifs{path, std::ios_base::in | std::ios_base::binary};
        if (not ifs.is_open())
        {
            return;
        }

        Parse(ifs);
    }

    constexpr ~PE() noexcept { _ok = false; }

    [[nodiscard]] constexpr bool Ok() const noexcept { return _ok; }

    [[nodiscard]] constexpr const auto DosHeader() const noexcept { return _dosHeader; }
    [[nodiscard]] constexpr const auto NtHeader() const noexcept { return _ntHeader; }
    [[nodiscard]] const IMAGE_IMPORT_DESCRIPTOR* ImportDirectory() const noexcept
    {
        auto importDataDirectory = DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (importDataDirectory.Size == 0)
        {
            return nullptr;
        }

        auto importDirectoryRaw = Rva2Raw(importDataDirectory.VirtualAddress);
        return reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(_data.data() + importDirectoryRaw);
    }
    [[nodiscard]] constexpr const auto& SectionHeaders() const noexcept { return _sectionHeaders; }
    [[nodiscard]] constexpr std::span<const std::uint8_t> Data() const noexcept { return _data; }

    [[nodiscard]] constexpr auto ImageSize() const noexcept { return _ntHeader->OptionalHeader.SizeOfImage; }

    std::uint32_t Rva2Raw(const std::uint32_t rva) const
    {
        if (auto section = std::ranges::find_if(
                _sectionHeaders, [rva](const auto& sectionHeader) { return detail::rvaInSection(rva, sectionHeader); });
            section != _sectionHeaders.end())
        {
            const auto sectionHeader = *section;
            return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
        }

        return 0;
    }

    [[nodiscard]] constexpr auto Error() const noexcept { return _error; }

private:
    IMAGE_DOS_HEADER* _dosHeader{};
    IMAGE_NT_HEADERS* _ntHeader{};
    std::vector<IMAGE_SECTION_HEADER*> _sectionHeaders{};
    std::vector<std::uint8_t> _data{};
    PEError _error{PEError::Success};
    bool _ok{false};

    void Parse(std::ifstream& f)
    {
        StreamReader sr{f};
        _data.resize(sr.Remaining());
        sr.Read(_data);

        _dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(_data.data());
        if (_dosHeader->e_magic != IMAGE_DOS_SIGNATURE || _dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER))
        {
            SetError(PEError::InvalidPeFormat);
            return;
        }

        _ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(_data.data() + _dosHeader->e_lfanew);

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

        _ok = true;
    }

    constexpr IMAGE_DATA_DIRECTORY DataDirectory(int index) const noexcept
    {
        return _ntHeader->OptionalHeader.DataDirectory[index];
    }

    constexpr void SetError(PEError error) noexcept { _error = error; }
};

} // namespace Torpedo
