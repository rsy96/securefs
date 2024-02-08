#pragma once
#include "core/io.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include <memory>

namespace securefs
{
class AesGcmRandomIO : public RandomIO
{
public:
    static constexpr SizeType IV_SIZE = 12, MAC_SIZE = 16, OVERHEAD = IV_SIZE + MAC_SIZE;

    AesGcmRandomIO(ConstByteBuffer key,
                   SizeType virtual_block_size,
                   std::shared_ptr<RandomIO> delegate);
    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType newSize) override;

    SizeType virtual_block_size() const noexcept { return virtual_block_size_; }
    SizeType underlying_block_size() const noexcept { return virtual_block_size_ + OVERHEAD; }

    static SizeType compute_virtual_size(SizeType underlyingSize);

private:
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor_;
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor_;
    std::shared_ptr<RandomIO> delegate_;
    SizeType virtual_block_size_;
};

class CryptoVerificationException : public std::runtime_error
{
public:
    using runtime_error::runtime_error;
};
}    // namespace securefs
