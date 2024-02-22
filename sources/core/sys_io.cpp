#include "sys_io.hpp"
#include "exceptions.hpp"

#include <limits>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace securefs
{

#ifdef _WIN32
static DWORD map_to_create_disposition(CreateMode create_mode)
{
    switch (create_mode)
    {
    case CreateMode::kOpenOnly:
        return OPEN_EXISTING;
    case CreateMode::kCreateOnly:
        return CREATE_NEW;
    case CreateMode::kCreateIfNonExisting:
        return OPEN_ALWAYS;
    case CreateMode::kTruncate:
        return CREATE_ALWAYS;
    }
}

static DWORD map_to_access_mode(ReadWriteMode mode)
{
    switch (mode)
    {
    case ReadWriteMode::kReadOnly:
        return GENERIC_READ;
    case ReadWriteMode::kReadWrite:
        return GENERIC_READ | GENERIC_WRITE;
    }
}
SystemFileIO::SystemFileIO(const char* filename,
                           CreateMode create_mode,
                           ReadWriteMode read_write_mode,
                           new_file_permission_type perm)
{
    handle_ = CHECK_WINAPI_CALL(CreateFileA(filename,
                                            map_to_access_mode(read_write_mode),
                                            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            perm,
                                            map_to_create_disposition(create_mode),
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr),
                                INVALID_HANDLE_VALUE);
}
SystemFileIO::~SystemFileIO() { CloseHandle(handle_); }

SizeType SystemFileIO::read(OffsetType offset, ByteBuffer output)
{
    if (output.size() >= std::numeric_limits<DWORD>::max())
    {
        throw NtException(STATUS_INVALID_BUFFER_SIZE, "Too large buffer specified for read");
    }
    OVERLAPPED o = {};
    o.Offset = static_cast<DWORD>(offset);
    o.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD result = 0;
    if (!ReadFile(handle_, output.data(), (DWORD)output.size(), &result, &o))
    {
        DWORD code = GetLastError();
        if (code == ERROR_HANDLE_EOF)
        {
            return 0;
        }
        throw WindowsException(code,
                               "ReadFile(handle_, output.data(), output.size(), &result, &o)");
    }
    return result;
}

void SystemFileIO::write(OffsetType offset, ConstByteBuffer input)
{
    if (input.size() >= std::numeric_limits<DWORD>::max())
    {
        throw NtException(STATUS_INVALID_BUFFER_SIZE, "Too large buffer specified for write");
    }
    OVERLAPPED o = {};
    o.Offset = static_cast<DWORD>(offset);
    o.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD result = 0;
    CHECK_WINAPI_CALL(WriteFile(handle_, input.data(), (DWORD)input.size(), &result, &o), 0);
    if (result != input.size())
    {
        throw NtException(STATUS_IO_DEVICE_ERROR, "Failed to write all bytes in");
    }
}

SizeType SystemFileIO::size() const
{
    LARGE_INTEGER result = {};
    CHECK_WINAPI_CALL(GetFileSizeEx(handle_, &result), 0);
    return result.QuadPart;
}

void SystemFileIO::resize(SizeType new_size)
{
    LARGE_INTEGER lsize;
    lsize.QuadPart = new_size;
    CHECK_WINAPI_CALL(SetFilePointerEx(handle_, lsize, nullptr, FILE_BEGIN), 0);
    CHECK_WINAPI_CALL(SetEndOfFile(handle_), 0);
}

#else
SystemFileIO::~SystemFileIO() { close(handle_); }

SizeType SystemFileIO::read(OffsetType offset, ByteBuffer output)
{
    return CHECK_POSIX_CALL(::pread(handle_, output.data(), output.size(), offset),
                            static_cast<ssize_t>(-1));
}

void SystemFileIO::write(OffsetType offset, ConstByteBuffer input)
{
    auto size = CHECK_POSIX_CALL(::pwrite(handle_, input.data(), input.size(), offset),
                                 static_cast<ssize_t>(-1));
    if (size != input.size())
    {
        throw PosixException(EIO, "Fail to write sufficient bytes");
    }
}

SizeType SystemFileIO::size() const
{
    struct stat st;
    CHECK_POSIX_CALL(::fstat(handle_, &st), -1);
    return st.st_size;
}

void SystemFileIO::resize(SizeType new_size)
{
    CHECK_POSIX_CALL(::ftruncate(handle_, new_size), -1);
}
#endif
}    // namespace securefs
