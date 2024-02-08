#pragma once

#include <absl/types/span.h>

#include <cstddef>

namespace securefs
{
void generate_random(void* buffer, size_t size);

inline void generate_random(absl::Span<unsigned char> buffer)
{
    generate_random(buffer.data(), buffer.size());
}
}    // namespace securefs
