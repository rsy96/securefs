#pragma once
#include "core/io.hpp"

namespace securefs
{
#ifdef _WIN32
using native_handle_type = void*;
#else
using native_handle_type = int;
#endif

class SystemFileIO final : public RandomIO
{
public:
    explicit SystemFileIO(native_handle_type handle) : handle_(handle) {}
    ~SystemFileIO();

    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType new_size) override;

    native_handle_type handle() noexcept { return handle_; }

private:
    native_handle_type handle_;
};

}    // namespace securefs
