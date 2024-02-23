#pragma once
#include "exceptions.hpp"
#include "io.hpp"

namespace securefs
{
#ifdef _WIN32
using native_handle_type = void*;
using new_file_permission_type = LPSECURITY_ATTRIBUTES;
inline new_file_permission_type default_permission = nullptr;
#else
using native_handle_type = int;
using new_file_permission_type = int;
inline new_file_permission_type default_permission = 0644;
#endif

enum class CreateMode
{
    kOpenOnly = 0,
    kCreateOnly = 1,
    kCreateIfNonExisting = 2,
    kTruncate = 3,
};

enum class ReadWriteMode
{
    kReadOnly = 0,
    kReadWrite = 1,
};

class SystemFileIO final : public RandomIO
{
public:
    explicit SystemFileIO(native_handle_type handle) : handle_(handle) {}
    SystemFileIO(const char* filename,
                 CreateMode create_mode,
                 ReadWriteMode read_write_mode,
                 new_file_permission_type perm = default_permission);
    ~SystemFileIO();

    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType new_size) override;

    native_handle_type handle() noexcept { return handle_; }

private:
    native_handle_type handle_;
};

/// @brief Create a directory, returns if it is successful.
/// Note: if the directory already exists, then return false. Other kinds of errors will be thrown
/// as exceptions.
/// @param name Path name of the directory.
bool create_directory(const char* name);

inline bool create_directory(const std::string& name) { return create_directory(name.c_str()); }
}    // namespace securefs
