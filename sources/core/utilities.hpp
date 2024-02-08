#pragma once

#include <cstdlib>
#include <memory>
#include <type_traits>

namespace securefs
{
template <typename T>
struct CDeleter
{
    void operator()(T* ptr)
    {
        static_assert(std::is_aggregate_v<T>);
        if (ptr)
        {
            free(ptr);
        }
    }
};
template <typename T>
using C_unique_ptr = std::unique_ptr<T, CDeleter<T>>;
}    // namespace securefs
