#include "core/crypto_io.hpp"
#include "crypto_io.hpp"

#include <fmt/format.h>

namespace securefs
{
static constexpr unsigned char NULL_IV[AesGcmRandomIO::IV_SIZE] = {0};

template <class Number>
static inline std::pair<Number, Number> divmod(Number x, Number y)
{
    return std::make_pair(x / y, x % y);
}

AesGcmRandomIO::AesGcmRandomIO(ConstByteBuffer key,
                               SizeType virtual_block_size,
                               std::shared_ptr<RandomIO> delegate)
    : delegate_(std::move(delegate)), virtual_block_size_(virtual_block_size)
{
    if (virtual_block_size <= 0)
    {
        throw std::invalid_argument("Negative block size");
    }
    encryptor_.SetKeyWithIV(key.data(), key.size(), NULL_IV, sizeof(NULL_IV));
    decryptor_.SetKeyWithIV(key.data(), key.size(), NULL_IV, sizeof(NULL_IV));
}

SizeType AesGcmRandomIO::read(OffsetType offset, ByteBuffer output)
{
    std::fill(output.begin(), output.end(), 0);

    auto [start_block, start_residue] = divmod(offset, virtual_block_size());
    auto [end_block, end_residue] = divmod(offset + output.size(), virtual_block_size());

    auto num_blocks = end_block + (end_residue > 0) - start_block;

    std::vector<unsigned char> working_data(num_blocks
                                            * (virtual_block_size() + underlying_block_size()));
    ByteBuffer ciphertext(working_data.data(), num_blocks * underlying_block_size());
    ByteBuffer plaintext(ciphertext.end(), num_blocks * virtual_block_size());

    const auto underlying_read = delegate_->read(start_block * underlying_block_size(), ciphertext);
    if (underlying_read <= OVERHEAD)
    {
        return 0;
    }
    ciphertext = ByteBuffer(ciphertext.begin(), underlying_read);
    auto [read_blocks, read_residue] = divmod(underlying_read, underlying_block_size());

    SizeType plaintext_true_size = 0;
    for (OffsetType i = 0; i <= read_blocks; ++i)
    {
        auto current_block_ciphertext
            = ciphertext.subspan(i * underlying_block_size(), underlying_block_size());
        if (current_block_ciphertext.size() <= OVERHEAD)
        {
            break;
        }
        auto current_block_plaintext = plaintext.subspan(
            i * virtual_block_size(), current_block_ciphertext.size() - OVERHEAD);
        bool success = decryptor_.DecryptAndVerify(current_block_plaintext.begin(),
                                                   current_block_ciphertext.end() - MAC_SIZE,
                                                   MAC_SIZE,
                                                   current_block_ciphertext.begin(),
                                                   IV_SIZE,
                                                   nullptr,
                                                   0,
                                                   current_block_ciphertext.begin() + IV_SIZE,
                                                   current_block_plaintext.size());
        if (!success)
        {
            throw CryptoVerificationException(
                fmt::format("File block {} failed verification", i + start_block));
        }
        plaintext_true_size += current_block_plaintext.size();
    }
    plaintext = ByteBuffer(plaintext.begin(), plaintext_true_size);
    auto copy_source = plaintext.subspan(start_residue, output.size());
    std::copy(copy_source.begin(), copy_source.end(), output.begin());
    return copy_source.size();
}
}    // namespace securefs
