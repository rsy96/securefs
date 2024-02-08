#include "core/crypto_io.hpp"
#include "core/encrypted_sqlitevfs.hpp"
#include "core/rng.hpp"

#include "memory_io.hpp"

#include <doctest/doctest.h>
#include <fmt/format.h>

#include <array>
#include <random>
#include <vector>

namespace doctest
{
template <>
struct StringMaker<std::vector<unsigned char>>
{
    static String convert(const std::vector<unsigned char>& value)
    {
        std::string s;
        s.reserve(value.size() * 2);
        for (auto c : value)
        {
            s += fmt::format("{:02x}", c);
        }
        return doctest::String(s.data(), s.size());
    }
};
}    // namespace doctest

namespace securefs
{

static std::vector<unsigned char> read_all(RandomIO& io)
{
    std::vector<unsigned char> result(io.size());
    CHECK(io.read(0, absl::MakeSpan(result)) == result.size());
    return result;
}

static void validate(RandomIO& reference_io, RandomIO& tested_io)
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> opdist(0, 3);
    std::uniform_int_distribution<SizeType> offsetdist(0, 200);
    std::uniform_int_distribution<SizeType> sizedist(0, 200);
    std::uniform_int_distribution<SizeType> resizedist(0, 400);

    for (int i = 0; i < 100000; ++i)
    {
        int opcode = opdist(mt);
        switch (opcode)
        {
        case 0:
            CHECK(reference_io.size() == tested_io.size());
            break;

        case 1:
        {
            auto size = resizedist(mt);
            reference_io.resize(size);
            tested_io.resize(size);
            CHECK(read_all(reference_io) == read_all(tested_io));
            break;
        }

        case 2:
        {
            auto offset = offsetdist(mt);
            auto size = sizedist(mt);
            std::vector<unsigned char> a(size), b(size);
            CHECK(reference_io.read(offset, absl::MakeSpan(a))
                  == tested_io.read(offset, absl::MakeSpan(b)));
            CHECK(a == b);
            break;
        }

        case 3:
        {
            auto offset = offsetdist(mt);
            auto size = sizedist(mt);
            std::vector<unsigned char> data(size);
            generate_random(absl::MakeSpan(data));
            reference_io.write(offset, absl::MakeConstSpan(data));
            tested_io.write(offset, absl::MakeConstSpan(data));
            CHECK(reference_io.size() == tested_io.size());
            CHECK(read_all(reference_io) == read_all(tested_io));
            break;
        }

        default:
            break;
        }
    }
}

TEST_CASE("crypto io against memory io")
{
    std::array<unsigned char, 32> key;
    generate_random(key.data(), key.size());

    MemoryRandomIO reference_io;
    AesGcmRandomIO tested_io(key, 64, std::make_shared<MemoryRandomIO>());
    validate(reference_io, tested_io);
}

TEST_CASE("sqlite io against memory io")
{
    MemoryRandomIO referece_io;
    auto vfs = sqlite3_vfs_find(nullptr);
}
}    // namespace securefs
