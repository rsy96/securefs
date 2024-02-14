#include "core/sys_io.hpp"
#include "core/exceptions.hpp"

#include <limits>

namespace securefs
{

#ifdef _WIN32
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

#endif
}    // namespace securefs
