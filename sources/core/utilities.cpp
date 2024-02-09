#include "core/utilities.hpp"

#include <fmt/compile.h>
#include <fmt/format.h>

namespace securefs
{
std::string hexify(absl::Span<const unsigned char> buffer)
{
    std::string s;
    s.reserve(buffer.size() * 2);
    for (auto c : buffer)
    {
        s.append(fmt::format(FMT_COMPILE("{:02x}"), c));
    }
    return s;
}

}    // namespace securefs
