#include "core/rng.hpp"

#include <cryptopp/osrng.h>

namespace securefs
{
void generate_random(void* buffer, size_t size)
{
    static thread_local CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(static_cast<CryptoPP::byte*>(buffer), size);
}
}    // namespace securefs
