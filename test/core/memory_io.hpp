#pragma once

#include <core/io.hpp>

#include <cstdio>
#include <vector>

namespace securefs
{
class MemoryRandomIO : public RandomIO
{
private:
    std::vector<unsigned char> data_;

public:
    explicit MemoryRandomIO();
    ~MemoryRandomIO();
    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType new_size) override;
};
}    // namespace securefs
