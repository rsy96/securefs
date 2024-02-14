#include "core/exceptions.hpp"

#include <absl/strings/str_format.h>

namespace securefs
{
const char* securefs::BaseException::what() const noexcept
{
    try
    {
        message().swap(cached_msg_);
    }
    catch (...)
    {
        return typeid(*this).name();
    }
    return cached_msg_.c_str();
}

std::string NtException::message() const
{
    return absl::StrFormat("NT error %d: %s", code_, user_msg_);
}

std::string WindowsException::message() const
{
    char temp_buffer[1024] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr,
                   code_,
                   0,
                   temp_buffer,
                   sizeof(temp_buffer) - 1,
                   nullptr);
    return absl::StrFormat("Windows error %d (%s): %s", code_, temp_buffer, user_msg_);
}

}    // namespace securefs
