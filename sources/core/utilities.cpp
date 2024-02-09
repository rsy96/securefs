#include "core/rng.hpp"
#include "core/utilities.hpp"

#include <fmt/compile.h>
#include <fmt/format.h>

#include <vector>

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
std::string random_hex_string(size_t num_bytes)
{
    std::vector<unsigned char> bytes(num_bytes);
    generate_random(bytes.data(), bytes.size());
    return hexify(absl::MakeConstSpan(bytes));
}
}    // namespace securefs
