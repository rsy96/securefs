#pragma once
#include <exception>
#include <string>
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
class BaseException : public std::exception
{
public:
    const char* what() const noexcept override;

    virtual std::string message() const = 0;

private:
    mutable std::string cached_msg_;
};

#ifdef _WIN32
class NtException : public BaseException
{
private:
    NTSTATUS code_;
    std::string user_msg_;

public:
    explicit NtException(NTSTATUS code, std::string user_msg)
        : code_(code), user_msg_(std::move(user_msg))
    {
    }
    virtual std::string message() const override;
    NTSTATUS code() const noexcept { return code_; }
};

class WindowsException : public BaseException
{
private:
    DWORD code_;
    std::string user_msg_;

public:
    explicit WindowsException(DWORD code, std::string user_msg)
        : code_(code), user_msg_(std::move(user_msg))
    {
    }
    virtual std::string message() const override;
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
    inline Ret check_winapi_call(Ret result, Ret invalid_value, const char* expr)
    {
        if (result == invalid_value)
        {
            THROW_WINDOWS_EXCEPTION(expr);
        }
        return result;
    }
}    // namespace internal

#define CHECK_WINAPI_CALL(expr, invalid_value)                                                     \
    ::securefs::internal::check_winapi_call((expr), invalid_value, #expr);

#endif

}    // namespace securefs
