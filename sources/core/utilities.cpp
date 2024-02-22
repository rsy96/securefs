#include "utilities.hpp"
#include "rng.hpp"

#include <absl/strings/escaping.h>
#include <absl/strings/str_format.h>

#include <vector>

namespace securefs
{
std::string hexify(absl::Span<const unsigned char> buffer)
{
    return absl::BytesToHexString({reinterpret_cast<const char*>(buffer.data()), buffer.size()});
}
std::string random_hex_string(size_t num_bytes)
{
    std::vector<unsigned char> bytes(num_bytes);
    generate_random(bytes.data(), bytes.size());
    return hexify(absl::MakeConstSpan(bytes));
}
}    // namespace securefs
