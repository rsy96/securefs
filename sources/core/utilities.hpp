#pragma once

#include <absl/types/span.h>

#include <cstdlib>
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
        static_assert(std::is_aggregate_v<T>);
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
}    // namespace securefs
