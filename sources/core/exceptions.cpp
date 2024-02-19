#include "exceptions.hpp"

#include <absl/strings/str_format.h>

namespace securefs
{

#ifdef _WIN32

static std::string format_windows_exception_message(DWORD code, std::string_view user_msg)
{
    char temp_buffer[1024] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr,
                   code,
                   0,
                   temp_buffer,
                   sizeof(temp_buffer) - 1,
                   nullptr);
    return absl::StrFormat("Windows error %X (%s): %s", code, temp_buffer, user_msg);
}

NtException::NtException(NTSTATUS code, std::string_view user_msg)
    : runtime_error(absl::StrFormat("NT error %X: %s", code, user_msg)), code_(code)
{
}

WindowsException::WindowsException(DWORD code, std::string_view user_msg)
    : runtime_error(format_windows_exception_message(code, user_msg)), code_(code)
{
}
#endif

PosixException::PosixException(int code, std::string_view user_msg)
    : runtime_error(absl::StrFormat("Posix error %X: %s", code, user_msg)), code_(code)
{
}
}    // namespace securefs
