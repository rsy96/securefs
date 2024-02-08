#include "core/crypto_io.hpp"
#include "core/rng.hpp"

#include <fmt/format.h>

#include "crypto_io.hpp"
#include <algorithm>

namespace securefs
{
static constexpr unsigned char NULL_IV[AesGcmRandomIO::IV_SIZE] = {0};

template <class Number>
static inline std::pair<Number, Number> divmod(Number x, Number y)
{
    return std::make_pair(x / y, x % y);
}

template <class Number>
static inline Number subtract_if_greater(Number x, Number y)
{
    return x >= y ? x - y : 0;
}

static bool is_all_zeros(ConstByteBuffer buffer)
{
    return std::all_of(buffer.begin(), buffer.end(), [](auto c) { return c == 0; });
}

AesGcmRandomIO::AesGcmRandomIO(ConstByteBuffer key,
                               SizeType underlying_block_size,
                               std::shared_ptr<RandomIO> delegate)
    : delegate_(std::move(delegate)), underlying_block_size_(underlying_block_size)
{
    if (underlying_block_size_ <= OVERHEAD)
    {
        throw std::invalid_argument("Too small block size");
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
    ciphertext = ciphertext.subspan(0, underlying_read);
    auto [read_blocks, read_residue] = divmod(underlying_read, underlying_block_size());
    plaintext = plaintext.subspan(
        0, read_blocks * virtual_block_size() + subtract_if_greater(read_residue, OVERHEAD));

    for (OffsetType i = 0; i <= read_blocks; ++i)
    {
        auto current_block_ciphertext
            = ciphertext.subspan(i * underlying_block_size(), underlying_block_size());
        if (current_block_ciphertext.size() <= OVERHEAD || is_all_zeros(current_block_ciphertext))
        {
            // All zeros ciphertext block is always mapped to all zeros plaintext.
            // This is to support sparse files efficiently.
            continue;
        }
        auto current_block_plaintext
            = plaintext.subspan(i * virtual_block_size(), virtual_block_size());
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
    }
    auto copy_source = plaintext.subspan(start_residue, output.size());
    std::copy(copy_source.begin(), copy_source.end(), output.begin());
    return copy_source.size();
}

void AesGcmRandomIO::write(OffsetType offset, ConstByteBuffer input)
{
    auto [start_block, start_residue] = divmod(offset, virtual_block_size());
    auto [end_block, end_residue] = divmod(offset + input.size(), virtual_block_size());

    auto num_blocks = end_block + (end_residue > 0) - start_block;

    std::vector<unsigned char> working_data(num_blocks
                                            * (virtual_block_size() + underlying_block_size()));
    ByteBuffer ciphertext(working_data.data(), num_blocks * underlying_block_size());
    ByteBuffer plaintext(ciphertext.end(), num_blocks * virtual_block_size());

    if (start_residue > 0 && start_block < end_block)
    {
        (void)read(start_block * virtual_block_size(), plaintext.subspan(0, virtual_block_size()));
    }
    if (end_residue > 0)
    {
        end_residue = std::max(
            end_residue,
            read(end_block * virtual_block_size(),
                 ByteBuffer(plaintext.end() - virtual_block_size(), virtual_block_size())));
    }
    if (end_residue > 0)
    {
        plaintext = plaintext.subspan(0, plaintext.size() + end_residue - virtual_block_size());
        ciphertext = ciphertext.subspan(
            0, ciphertext.size() + end_residue + OVERHEAD - underlying_block_size());
    }
    assert(input.size() <= plaintext.size() + start_residue);
    std::copy(input.begin(), input.end(), plaintext.begin() + start_residue);

    for (OffsetType i = 0; i < num_blocks; ++i)
    {
        auto current_block_plaintext
            = plaintext.subspan(i * virtual_block_size(), virtual_block_size());
        auto iv = ciphertext.subspan(i * underlying_block_size(), IV_SIZE);
        do
        {
            generate_random(iv);
        } while (is_all_zeros(iv));
        encryptor_.EncryptAndAuthenticate(iv.end(),
                                          iv.end() + current_block_plaintext.size(),
                                          MAC_SIZE,
                                          iv.begin(),
                                          IV_SIZE,
                                          nullptr,
                                          0,
                                          current_block_plaintext.begin(),
                                          current_block_plaintext.size());
    }
    delegate_->write(start_block * underlying_block_size(), ciphertext);
}

SizeType AesGcmRandomIO::size() const
{
    return compute_virtual_size(delegate_->size(), underlying_block_size());
}

void AesGcmRandomIO::resize(SizeType new_size)
{
    if (new_size <= 0)
    {
        delegate_->resize(0);
        return;
    }
    auto current_size = size();
    if (current_size == new_size)
    {
        return;
    }
    auto [blocks, residue] = divmod(new_size, virtual_block_size());
    if (new_size < current_size)
    {
        delegate_->resize(blocks * underlying_block_size());
        if (residue > 0)
        {
            // We need to resize this twice to ensure that the residual part is zeroed.
            delegate_->resize(blocks * underlying_block_size() + residue + OVERHEAD);
        }
    }
    else if (new_size > current_size)
    {
        auto [current_blocks, current_residue] = divmod(current_size, virtual_block_size());
        if (current_residue > 0)
        {
            std::vector<unsigned char> data(virtual_block_size());
            (void)read(current_blocks * virtual_block_size(), ByteBuffer(data));
            write(current_blocks * virtual_block_size(), ConstByteBuffer(data));
        }
        delegate_->resize(blocks * underlying_block_size() + residue + OVERHEAD);
    }
}

SizeType AesGcmRandomIO::compute_virtual_size(SizeType underlying_size,
                                              SizeType underlying_block_size)
{
    auto [blocks, residue] = divmod(underlying_size, underlying_block_size);
    return blocks * (underlying_block_size - OVERHEAD) + subtract_if_greater(residue, OVERHEAD);
}

}    // namespace securefs
