#pragma once
#include "core/object.hpp"

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
    virtual void resize(SizeType newSize) = 0;
};
}    // namespace securefs
