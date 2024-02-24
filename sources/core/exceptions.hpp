#pragma once
#include <stdexcept>
#include <string_view>
#include <typeinfo>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#pragma warning(push)
#pragma warning(disable : 4005) /* macro redefinition */
#include <ntstatus.h>
#pragma warning(pop)
#endif

namespace securefs
{
#ifdef _WIN32
class NtException : public std::runtime_error
{
private:
    NTSTATUS code_;

public:
    explicit NtException(NTSTATUS code, std::string_view user_msg);
    NTSTATUS code() const noexcept { return code_; }
};

class WindowsException : public std::runtime_error
{
private:
    DWORD code_;

public:
    explicit WindowsException(DWORD code, std::string_view user_msg);
    DWORD code() const noexcept { return code_; }
};

// We define this macro because we need to ensure that ::GetLastError is evaluated first.
#define THROW_WINDOWS_EXCEPTION(msg)                                                               \
    do                                                                                             \
    {                                                                                              \
        DWORD code = ::GetLastError();                                                             \
        throw WindowsException(code, msg);                                                         \
    } while (0)

namespace internal
{
    template <typename Ret>
    inline Ret check_winapi_call(Ret result, Ret invalid_value, std::string_view expr)
    {
        if (result == invalid_value)
        {
            THROW_WINDOWS_EXCEPTION(expr);
        }
        return result;
    }
}    // namespace internal

#define CHECK_WINAPI_CALL(expr, invalid_value)                                                     \
    ::securefs::internal::check_winapi_call((expr), invalid_value, #expr)

#endif

class PosixException : public std::runtime_error
{
private:
    int code_;

public:
    explicit PosixException(int code, std::string_view user_msg);
    int code() const noexcept { return code_; }
};

// We define this macro because we need to ensure that errno (a macro) is evaluated first.
#define THROW_POSIX_EXCEPTION(msg)                                                                 \
    do                                                                                             \
    {                                                                                              \
        int code = errno;                                                                          \
        throw PosixException(code, msg);                                                           \
    } while (0)

namespace internal
{
    template <typename Ret>
    inline Ret check_posix_call(Ret result, Ret invalid_value, std::string_view expr)
    {
        if (result == invalid_value)
        {
            THROW_POSIX_EXCEPTION(expr);
        }
        return result;
    }
}    // namespace internal

#define CHECK_POSIX_CALL(expr, invalid_value)                                                      \
    ::securefs::internal::check_posix_call((expr), invalid_value, #expr)

class InternalError : public std::runtime_error
{
    using runtime_error::runtime_error;
};

#define VALIDATE_CONSTRAINT(x)                                                                     \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
            throw InternalError(#x);                                                               \
    } while (0)
}    // namespace securefs
