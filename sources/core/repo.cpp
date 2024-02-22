#include "repo.hpp"
#include "sys_io.hpp"

#include <absl/strings/str_cat.h>
#include <argon2.h>
#include <blake3.h>

#include <stdexcept>

namespace securefs
{

std::array<unsigned char, 32> derive_user_key(std::string_view password,
                                              const std::string& key_file_path,
                                              ConstByteBuffer salt,
                                              const Argon2idParams& params)
{
    std::array<unsigned char, 32> result{};

    if (salt.size() != 32)
    {
        throw std::invalid_argument("Salt must be exactly 32 bytes long");
    }
    std::array<unsigned char, 32> combined_salt;
    if (!key_file_path.empty())
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, salt.data());

        SystemFileIO file(key_file_path.c_str(), CreateMode::kOpenOnly, ReadWriteMode::kReadOnly);
        file.read_and_process_all([&](ConstByteBuffer buffer)
                                  { blake3_hasher_update(&hasher, buffer.data(), buffer.size()); });
        blake3_hasher_finalize(&hasher, combined_salt.data(), combined_salt.size());
        salt = absl::MakeConstSpan(combined_salt);
    }
    int rc = argon2id_hash_raw(params.time_cost(),
                               params.memory_cost() * 1024,
                               params.parallelism(),
                               password.data(),
                               password.size(),
                               salt.data(),
                               salt.size(),
                               result.data(),
                               result.size());
    if (rc != ARGON2_OK)
    {
        throw std::runtime_error(absl::StrCat("argon2 failure: ", argon2_error_message(rc)));
    }
    return result;
}

}    // namespace securefs
