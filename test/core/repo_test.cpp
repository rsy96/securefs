#include "core/repo.hpp"
#include "core/utilities.hpp"

#include <absl/cleanup/cleanup.h>
#include <absl/strings/escaping.h>
#include <doctest/doctest.h>

#include <fstream>

namespace securefs
{
TEST_CASE("Derive user key without key file")
{
    std::array<unsigned char, 32> salt{};
    std::fill(salt.begin(), salt.end(), 2);
    Argon2idParams params;
    params.set_memory_cost(1);
    params.set_time_cost(1);
    params.set_parallelism(2);
    auto derived_key = derive_user_key("password", "", absl::MakeConstSpan(salt), params);
    CHECK(hexify(absl::MakeConstSpan(derived_key))
          == "d6c41d93bc2cbf1c02e7c7fef2e25281e281b97d0a884ad6857c12e74905a381");
}

TEST_CASE("Derive user key without key file")
{
    std::array<unsigned char, 32> salt{};
    std::fill(salt.begin(), salt.end(), 2);
    Argon2idParams params;
    params.set_memory_cost(1);
    params.set_time_cost(1);
    params.set_parallelism(2);

    auto key_file_path = random_hex_string(16);
    auto cleanup = absl::MakeCleanup([&]() { remove(key_file_path.c_str()); });
    {
        std::ofstream of(key_file_path);
        of << "000";
    }

    auto derived_key
        = derive_user_key("password", key_file_path, absl::MakeConstSpan(salt), params);
    CHECK(hexify(absl::MakeConstSpan(derived_key))
          == "f07fec06343a7a7a144db88eaba9d9e9a4832d2b5d83e210a3cd568a2c300fa4");
}
}    // namespace securefs
