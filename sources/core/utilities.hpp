#pragma once

#include <absl/cleanup/cleanup.h>
#include <absl/types/span.h>

#include <cstdlib>
#include <exception>
#include <memory>
#include <string_view>
#include <type_traits>

namespace securefs
{
template <typename T>
struct CDeleter
{
    void operator()(T* ptr)
    {
        static_assert(std::is_trivially_destructible_v<T>);
        if (ptr)
        {
            free(ptr);
        }
    }
};
template <typename T>
using C_unique_ptr = std::unique_ptr<T, CDeleter<T>>;

std::string hexify(absl::Span<const unsigned char> buffer);
inline std::string hexify(std::string_view view)
{
    return hexify(
        absl::MakeConstSpan(reinterpret_cast<const unsigned char*>(view.data()), view.size()));
}

template <typename Resource, typename ResourceTraits>
class RAII
{
private:
    Resource r_;

public:
    explicit RAII(Resource r) noexcept : r_(r)
    {
        static_assert(std::is_trivially_copyable_v<Resource>);
    }

    RAII() noexcept : r_(ResourceTraits::invalid()) {}

    ~RAII()
    {
        if (r_ != ResourceTraits::invalid())
        {
            ResourceTraits::cleanup(r_);
        }
    }

    RAII(RAII&& other) noexcept : r_(other.r_) { other.r_ = ResourceTraits::invalid(); }

    RAII& operator=(RAII&& other) noexcept
    {
        std::swap(r_, other.r_);
        return *this;
    }

    Resource& get() noexcept { return r_; }

    const Resource& get() const noexcept { return r_; }

    template <typename = std::enable_if_t<std::is_pointer_v<Resource>>>
    Resource operator->() noexcept
    {
        return r_;
    }

    template <typename = std::enable_if_t<std::is_pointer_v<Resource>>>
    const Resource operator->() const noexcept
    {
        return r_;
    }

    Resource release() noexcept
    {
        Resource r = r_;
        r_ = ResourceTraits::invalid();
        return r;
    }
};

std::string random_hex_string(size_t num_bytes);

void warn_on_unlock_error(const std::exception& e) noexcept;

/// @brief A class to enforce that access to the object is always synchronized.
/// @tparam Lockable A class with lock() and unlock() methods. Typically it should be a struct
/// bunding a mutex with the data it protects.
template <class Lockable>
class SynchronizedInPlace
{
public:
    template <typename... Args>
    explicit SynchronizedInPlace(Args&&... args) : lockable_(std::forward<Args>(args)...)
    {
    }

    SynchronizedInPlace(SynchronizedInPlace&&) = delete;
    SynchronizedInPlace& operator=(SynchronizedInPlace&&) = delete;

    template <typename Callback>
    auto synchronized(Callback&& cb)
    {
        lockable_.lock();
        auto cleanup = absl::MakeCleanup(
            [this]()
            {
                try
                {
                    lockable_.unlock();
                }
                catch (const std::exception& e)
                {
                    warn_on_unlock_error(e);
                }
            });
        return cb(lockable_);
    }

private:
    Lockable lockable_;
};

/// @brief A class to enforce that access to the object is always synchronized.
template <class T, class Mutex>
class SynchronizedWithMutex
{
public:
    template <typename... Args>
    explicit SynchronizedWithMutex(Args&&... args) : t_(std::forward<Args>(args)...)
    {
    }

    SynchronizedWithMutex(SynchronizedWithMutex&&) = delete;
    SynchronizedWithMutex& operator=(SynchronizedWithMutex&&) = delete;

    template <typename Callback>
    auto synchronized(Callback&& cb)
    {
        mu_.lock();
        auto cleanup = absl::MakeCleanup(
            [this]()
            {
                try
                {
                    mu_.unlock();
                }
                catch (const std::exception& e)
                {
                    warn_on_unlock_error(e);
                }
            });
        return cb(t_);
    }

private:
    Mutex mu_;
    T t_;
};
}    // namespace securefs
