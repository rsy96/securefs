#pragma once
#include "object.hpp"

#include <absl/types/span.h>

#include <cstdint>

namespace securefs
{
using OffsetType = std::uint64_t;
using SizeType = OffsetType;
using ByteBuffer = absl::Span<unsigned char>;
using ConstByteBuffer = absl::Span<const unsigned char>;

class RandomIO : public Object
{
public:
    virtual SizeType read(OffsetType offset, ByteBuffer output) = 0;
    virtual void write(OffsetType offset, ConstByteBuffer input) = 0;
    virtual SizeType size() const = 0;

    // Resize to the new size. If new size is greater, filling the difference with zeros.
    virtual void resize(SizeType new_size) = 0;

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
};
}    // namespace securefs
