#pragma once

#include "io.hpp"

#include "protos/cmdline.pb.h"
#include "protos/params.pb.h"

#include <array>
#include <memory>

namespace securefs
{

std::array<unsigned char, 32> derive_user_key(std::string_view password,
                                              const std::string& key_file_path,
                                              ConstByteBuffer salt,
                                              const Argon2idParams& argon_params);

EncryptedData encrypt_master_keys(const MasterKeys& keys,
                                  const std::array<unsigned char, 32>& user_key);

void create_repo(const CreateCmd& cmd);
}    // namespace securefs
