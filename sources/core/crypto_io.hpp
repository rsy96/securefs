#pragma once
#include "core/io.hpp"
#include "protos/params.pb.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include <array>
#include <memory>

namespace securefs
{
class AesGcmRandomIO final : public RandomIO
{
public:
    static constexpr SizeType IV_SIZE = 12, MAC_SIZE = 16, OVERHEAD = IV_SIZE + MAC_SIZE;
    AesGcmRandomIO(std::shared_ptr<RandomIO> delegate, EncryptionParams params);
    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType new_size) override;

    SizeType virtual_block_size() const noexcept { return underlying_block_size() - OVERHEAD; }
    SizeType underlying_block_size() const noexcept { return params_.underlying_block_size(); }

    static SizeType compute_virtual_size(SizeType underlying_size, SizeType underlying_block_size);

private:
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor_;
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor_;
    std::shared_ptr<RandomIO> delegate_;
    EncryptionParams params_;

    void encrypt_block(ConstByteBuffer plaintext, ByteBuffer ciphertext, OffsetType block_num);
    bool decrypt_block(ByteBuffer plaintext, ConstByteBuffer ciphertext, OffsetType block_num);
};

class CryptoVerificationException : public std::runtime_error
{
public:
    using runtime_error::runtime_error;
};
}    // namespace securefs
