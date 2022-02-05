#pragma once

#include <iostream>
#include <span>

namespace Torpedo
{

template<typename T> class StreamReader
{
public:
    constexpr StreamReader(T& stream) noexcept : _stream{stream}
    {
        _stream.seekg(0, std::ios_base::end);
        _size = _stream.tellg();
        _stream.seekg(0);
    }
    StreamReader(StreamReader&) = delete;

    template<typename U> auto& operator>>(U& target)
    {
        _stream.read(reinterpret_cast<char*>(&target), sizeof(U));
        return *this;
    }

    auto& Read(std::span<std::uint8_t> buffer)
    {
        _stream.read(reinterpret_cast<char*>(buffer.data()), buffer.size_bytes());
        return *this;
    }

    constexpr void Seek(std::uint64_t pos) { _stream.seekg(pos); }
    constexpr auto Pos() const noexcept { return _stream.tellg(); }
    constexpr auto Remaining() const noexcept { return _size - Pos(); }

private:
    T& _stream;
    std::size_t _size;
};

} // namespace Torpedo
