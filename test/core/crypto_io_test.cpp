#include "core/crypto_io.hpp"
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

TEST_CASE("crypto io against memory io")
{
    std::array<unsigned char, 32> key;
    generate_random(key.data(), key.size());

    MemoryRandomIO mio;
    AesGcmRandomIO aesio(key, 64, std::make_shared<MemoryRandomIO>());

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> opdist(0, 3);
    std::uniform_int_distribution<SizeType> offsetdist(0, 200);
    std::uniform_int_distribution<SizeType> sizedist(0, 200);
    std::uniform_int_distribution<SizeType> resizedist(0, 400);

    for (int i = 0; i < 1000; ++i)
    {
        int opcode = opdist(mt);
        switch (opcode)
        {
        case 0:
            CHECK(mio.size() == aesio.size());
            break;

        case 1:
        {
            continue;
            auto size = resizedist(mt);
            if (size > mio.size())
            {
                continue;
            }
            mio.resize(size);
            aesio.resize(size);
            break;
        }

        case 2:
        {
            auto offset = offsetdist(mt);
            auto size = sizedist(mt);
            std::vector<unsigned char> a(size), b(size);
            CHECK(mio.read(offset, absl::MakeSpan(a)) == aesio.read(offset, absl::MakeSpan(b)));
            CHECK(a == b);
            break;
        }

        case 3:
        {
            auto offset = offsetdist(mt);
            auto size = sizedist(mt);
            std::vector<unsigned char> data(size);
            generate_random(absl::MakeSpan(data));
            mio.write(offset, absl::MakeConstSpan(data));
            aesio.write(offset, absl::MakeConstSpan(data));
            CHECK(read_all(mio) == read_all(aesio));
            break;
        }

        default:
            break;
        }
    }
}
}    // namespace securefs
