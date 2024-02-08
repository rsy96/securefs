#include "memory_io.hpp"

#include <algorithm>

namespace securefs
{
MemoryRandomIO::MemoryRandomIO() {}

MemoryRandomIO::~MemoryRandomIO() {}

SizeType MemoryRandomIO::read(OffsetType offset, ByteBuffer output)
{
    auto source = absl::MakeConstSpan(data_).subspan(offset, output.size());
    std::copy(source.begin(), source.end(), output);
    return source.size();
}

void MemoryRandomIO::write(OffsetType offset, ConstByteBuffer input)
{
    if (offset + input.size() > data_.size())
    {
        data_.resize(offset + input.size());
    }
    auto target = absl::MakeSpan(data_).subspan(offset, input.size());
    std::copy(input.begin(), input.end(), target.begin());
}

SizeType MemoryRandomIO::size() const { return data_.size(); }
void MemoryRandomIO::resize(SizeType new_size) { data_.resize(new_size); }
}    // namespace securefs
