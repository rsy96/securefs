#include "repo.hpp"
#include "encrypted_sqlitevfs.hpp"
#include "rng.hpp"
#include "sys_io.hpp"
#include "tree_db.hpp"

#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <argon2.h>
#include <blake3.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include <stdexcept>

#ifndef _WIN32
#include <unistd.h>
#endif

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

EncryptedData encrypt_master_keys(const MasterKeys& keys,
                                  const std::array<unsigned char, 32>& user_key)
{
    EncryptedData result;
    std::string serialized_keys = keys.SerializeAsString();
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;

    result.mutable_iv()->resize(enc.DefaultIVLength());
    result.mutable_mac()->resize(enc.DigestSize());
    result.mutable_ciphertext()->resize(serialized_keys.size());

    generate_random(result.mutable_iv()->data(), result.mutable_iv()->size());

    enc.SetKeyWithIV(user_key.data(),
                     user_key.size(),
                     reinterpret_cast<const unsigned char*>(result.iv().data()),
                     result.iv().size());
    enc.EncryptAndAuthenticate(
        reinterpret_cast<unsigned char*>(result.mutable_ciphertext()->data()),
        reinterpret_cast<unsigned char*>(result.mutable_mac()->data()),
        result.mutable_mac()->size(),
        reinterpret_cast<const unsigned char*>(result.iv().data()),
        result.iv().size(),
        nullptr,
        0,
        reinterpret_cast<const unsigned char*>(serialized_keys.data()),
        serialized_keys.size());
    return result;
}

static MasterKeys init_master_key()
{
    MasterKeys keys;
    for (int i = 0; i < keys.descriptor()->field_count(); ++i)
    {
        auto* f = keys.descriptor()->field(i);
        VALIDATE_CONSTRAINT(f->type() == f->TYPE_BYTES && !f->is_repeated());
        std::string key(32, 0);
        generate_random(key.data(), key.size());
        keys.GetReflection()->SetString(&keys, f, std::move(key));
    }
    return keys;
}

void create_repo(const CreateCmd& cmd)
{
    if (cmd.password().empty())
    {
        throw std::invalid_argument("Password must not be empty");
    }
    std::vector<std::string> files_to_remove_on_failure, dirs_to_remove_on_failure;
    auto cleanup = absl::MakeCleanup(
        [&]()
        {
            if (std::uncaught_exceptions() <= 0)
            {
                return;
            }
            for (auto it = files_to_remove_on_failure.rbegin();
                 it != files_to_remove_on_failure.rend();
                 ++it)
            {
                remove(it->c_str());
            }
            for (auto it = dirs_to_remove_on_failure.rbegin();
                 it != dirs_to_remove_on_failure.rend();
                 ++it)
            {
#ifdef _WIN32
                RemoveDirectoryA(it->c_str());
#else
                rmdir(it->c_str());
#endif
            }
        });

    auto create_directory_and_remember = [&](std::string dir)
    {
        create_directory(dir);
        dirs_to_remove_on_failure.emplace_back(std::move(dir));
    };
    create_directory_and_remember(cmd.repository());
    create_directory_and_remember(
        absl::StrCat(cmd.repository(), "/", outer_dir_for_inode(TreeDB::kRootINode)));
    create_directory_and_remember(
        absl::StrCat(cmd.repository(), "/", inner_dir_for_inode(TreeDB::kRootINode)));

    auto create_file_and_remember = [&](std::string fn)
    {
        auto result = std::make_unique<SystemFileIO>(
            fn.c_str(), CreateMode::kCreateOnly, ReadWriteMode::kReadWrite);
        files_to_remove_on_failure.emplace_back(std::move(fn));
        return result;
    };

    {
        unsigned char random_data[4096];
        generate_random(random_data, sizeof(random_data));
        create_file_and_remember(
            absl::StrCat(cmd.repository(), "/", full_file_name_for_inode(TreeDB::kRootINode)))
            ->write(0, absl::MakeConstSpan(random_data));
    }
    SecureFSSerializedConfig config;
    config.mutable_params()->CopyFrom(cmd.params());
    config.mutable_argon2_params()->CopyFrom(cmd.argon2_params());
    config.mutable_salt()->resize(32);
    generate_random(as_bytes(*config.mutable_salt()));

    auto master_keys = init_master_key();
    encrypt_master_keys(
        master_keys,
        derive_user_key(
            cmd.password(), cmd.key_file(), as_bytes(config.salt()), config.argon2_params()))
        .Swap(config.mutable_encrypted_master_keys());
    create_file_and_remember(cmd.config().empty() ? absl::StrCat(cmd.repository(), "/config.pb")
                                                  : cmd.config())
        ->write(0, as_bytes(config.SerializeAsString()));

    {
        EncryptedSqliteVfsRegistry::Params params{};
        params.encryption_params.underlying_block_size
            = config.params().virtual_block_size_for_tree_db() + 28;
        std::copy(master_keys.tree_key().begin(),
                  master_keys.tree_key().end(),
                  params.encryption_params.key.begin());
        EncryptedSqliteVfsRegistry vfs_registry(params);
        auto tree_db_path
            = (cmd.tree_db().empty() ? absl::StrCat(cmd.repository(), "/tree.db") : cmd.tree_db());
        files_to_remove_on_failure.emplace_back(tree_db_path);
        TreeDB tree(SQLiteDB(tree_db_path.c_str(),
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE
                                 | SQLITE_OPEN_NOMUTEX,
                             vfs_registry.vfs_name().c_str()));
        tree.create_tables(config.params().exact_name_only());
    }
}

std::string outer_dir_for_inode(uint64_t inode)
{
    return absl::StrFormat("%02x", inode >> (64 - 8));
}

std::string inner_dir_for_inode(uint64_t inode)
{
    return absl::StrFormat("%02x/%02x", inode >> (64 - 8), (inode >> (64 - 16)) & 0xFFull);
}

std::string full_file_name_for_inode(uint64_t inode)
{
    return absl::StrFormat("%02x/%02x/%02x%02x%02x%02x%02x%02x%02x%02x",
                           inode >> (64 - 8),
                           (inode >> (64 - 16)) & 0xFFull,
                           inode >> (64 - 8),
                           (inode >> (64 - 16)) & 0xFFull,
                           (inode >> (64 - 24)) & 0xFFull,
                           (inode >> (64 - 32)) & 0xFFull,
                           (inode >> (64 - 40)) & 0xFFull,
                           (inode >> (64 - 48)) & 0xFFull,
                           (inode >> (64 - 56)) & 0xFFull,
                           (inode >> (64 - 64)) & 0xFFull);
}

}    // namespace securefs
