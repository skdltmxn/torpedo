#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace Torpedo
{

class BinaryWriter
{
public:
    constexpr BinaryWriter(void* buffer, std::size_t size) noexcept
        : _buffer{static_cast<std::uint8_t*>(buffer)}, _size{size}
    {
    }

    template<typename T>
    requires std::is_standard_layout_v<T> && std::is_trivially_copyable_v<T>
    auto& operator<<(const T& data)
    {
        if constexpr (std::is_pointer_v<T>)
        {
            return operator<<(*data);
        }

        if (CanWrite(sizeof(data)))
        {
            ProceedBuffer({reinterpret_cast<const std::uint8_t*>(&data), sizeof(data)});
        }

        return *this;
    }

    template<typename T> auto& operator<<(std::span<T> data)
    {
        if (CanWrite(data.size_bytes()))
        {
            ProceedBuffer(data);
        }

        return *this;
    }

    template<typename T> auto& Write(std::span<T> data)
    {
        if (not CanWrite(data.size_bytes()))
        {
            return *this;
        }

        ProceedBuffer(data);
        return *this;
    }

    void Seek(std::size_t offset)
    {
        if (offset < _size)
        {
            _pos = offset;
        }
    }

    void Skip(std::size_t offset)
    {
        if (CanWrite(offset))
        {
            _pos += offset;
        }
    }

    [[nodiscard]] constexpr std::span<std::uint8_t> Buffer() const noexcept { return {_buffer, _size}; }
    [[nodiscard]] constexpr void* Current() const noexcept { return _buffer + _pos; }

private:
    std::uint8_t* _buffer{};
    std::size_t _size{};
    std::size_t _pos{};

    [[nodiscard]] constexpr bool CanWrite(std::size_t size) const noexcept { return _pos + size <= _size; }

    void ProceedBuffer(std::span<const std::uint8_t> data)
    {
        std::memcpy(&_buffer[_pos], data.data(), data.size_bytes());
        _pos += data.size_bytes();
    }
};

} // namespace Torpedo
