#pragma once
#include "object.hpp"

#include <absl/types/span.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace securefs
{
using OffsetType = std::uint64_t;
using SizeType = OffsetType;
using ByteBuffer = absl::Span<unsigned char>;
using ConstByteBuffer = absl::Span<const unsigned char>;

inline ConstByteBuffer as_bytes(std::string_view view)
{
    return {reinterpret_cast<const unsigned char*>(view.data()), view.size()};
}

inline ByteBuffer as_bytes(std::string& str)
{
    return {reinterpret_cast<unsigned char*>(str.data()), str.size()};
}

class RandomIO : public Object
{
public:
    virtual SizeType read(OffsetType offset, ByteBuffer output) = 0;
    virtual void write(OffsetType offset, ConstByteBuffer input) = 0;
    virtual SizeType size() const = 0;

    // Resize to the new size. If new size is greater, filling the difference with zeros.
    virtual void resize(SizeType new_size) = 0;

    // Below are convience wrappers.

    template <typename Callback>
    void read_and_process_all(Callback&& cb)
    {
        unsigned char buffer[4000];
        OffsetType pos = 0;
        while (true)
        {
            auto size = read(pos, absl::MakeSpan(buffer));
            if (size <= 0)
            {
                break;
            }
            cb(absl::MakeConstSpan(buffer, size));
            pos += size;
        }
    }

    std::string read_all()
    {
        std::string result;
        read_and_process_all(
            [&result](auto&& buffer)
            { result.append(reinterpret_cast<const char*>(buffer.data()), buffer.size()); });
        return result;
    }
};
}    // namespace securefs
