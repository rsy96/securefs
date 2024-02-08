#include "memory_io.hpp"

#include <algorithm>

namespace securefs
{
MemoryRandomIO::MemoryRandomIO() {}

MemoryRandomIO::~MemoryRandomIO() {}

SizeType MemoryRandomIO::read(OffsetType offset, ByteBuffer output)
{
    if (offset >= data_.size())
    {
        return 0;
    }
    auto source = absl::MakeConstSpan(data_).subspan(offset, output.size());
    std::copy(source.begin(), source.end(), output.begin());
    return source.size();
}

void MemoryRandomIO::write(OffsetType offset, ConstByteBuffer input)
{
    if (offset + input.size() > data_.size())
    {
        data_.resize(offset + input.size());
    }
    std::copy(input.begin(), input.end(), data_.begin() + offset);
}

SizeType MemoryRandomIO::size() const { return data_.size(); }
void MemoryRandomIO::resize(SizeType new_size) { data_.resize(new_size); }
}    // namespace securefs
