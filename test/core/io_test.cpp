#include "core/crypto_io.hpp"
#include "core/encrypted_sqlitevfs.hpp"
#include "core/rng.hpp"
#include "core/utilities.hpp"

#include "memory_io.hpp"

#include <absl/cleanup/cleanup.h>
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
        std::string s = securefs::hexify(absl::MakeConstSpan(value));
        return doctest::String(s.data(), s.size());
    }
};
}    // namespace doctest

namespace securefs
{

static std::vector<unsigned char> read_all(RandomIO& io)
{
    std::vector<unsigned char> result(io.size());
    REQUIRE(io.read(0, absl::MakeSpan(result)) == result.size());
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
            REQUIRE(reference_io.size() == tested_io.size());
            break;

        case 1:
        {
            auto size = resizedist(mt);
            reference_io.resize(size);
            tested_io.resize(size);
            REQUIRE(read_all(reference_io) == read_all(tested_io));
            break;
        }

        case 2:
        {
            auto offset = offsetdist(mt);
            auto size = sizedist(mt);
            std::vector<unsigned char> a(size), b(size);
            REQUIRE(reference_io.read(offset, absl::MakeSpan(a))
                    == tested_io.read(offset, absl::MakeSpan(b)));
            REQUIRE(a == b);
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
            REQUIRE(reference_io.size() == tested_io.size());
            REQUIRE(read_all(reference_io) == read_all(tested_io));
            break;
        }

        default:
            break;
        }
    }
}

TEST_CASE("crypto io against memory io")
{
    AesGcmRandomIO::Params params;
    generate_random(params.key.data(), params.key.size());
    params.underlying_block_size = 64;

    MemoryRandomIO reference_io;
    AesGcmRandomIO tested_io(std::make_shared<MemoryRandomIO>(), params);
    validate(reference_io, tested_io);
}

TEST_CASE("sqlite io against memory io")
{
    MemoryRandomIO referece_io;
    auto vfs = sqlite3_vfs_find(nullptr);
    auto file = static_cast<sqlite3_file*>(malloc(vfs->szOsFile));
    auto guard_file = absl::MakeCleanup([file]() { free(file); });

    REQUIRE(vfs->xOpen(vfs,
                       nullptr,
                       file,
                       SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                       nullptr)
            == SQLITE_OK);

    SqliteFileIO file_io(file);
    validate(referece_io, file_io);
}
}    // namespace securefs
