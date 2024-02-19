#include "core/crypto_io.hpp"
#include "core/encrypted_sqlitevfs.hpp"
#include "core/exceptions.hpp"
#include "core/rng.hpp"
#include "core/sys_io.hpp"
#include "core/utilities.hpp"

#include "memory_io.hpp"

#include <absl/cleanup/cleanup.h>
#include <absl/strings/str_cat.h>
#include <doctest/doctest.h>

#include <array>
#include <random>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

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

    for (int i = 0; i < 100; ++i)
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
    for (int i = 0; i < 100; ++i)
    {
        AesGcmRandomIO::Params params;
        generate_random(absl::MakeSpan(params.key));
        params.underlying_block_size = 64;

        MemoryRandomIO reference_io;
        AesGcmRandomIO tested_io(std::make_shared<MemoryRandomIO>(), params);
        validate(reference_io, tested_io);
    }
}

TEST_CASE("sqlite io against memory io")
{
    for (int i = 0; i < 100; ++i)
    {
        auto filename = random_hex_string(8) + ".sqliteraw";
#ifndef _WIN32
        char cwd[1024];
        filename = absl::StrCat(getcwd(cwd, sizeof(cwd)), filename);
#endif
        auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

        MemoryRandomIO referece_io;
        auto vfs = sqlite3_vfs_find(nullptr);
        auto file = static_cast<sqlite3_file*>(malloc(vfs->szOsFile));
        auto guard_file = absl::MakeCleanup([file]() { free(file); });

        REQUIRE(vfs->xOpen(vfs,
                           filename.c_str(),
                           file,
                           SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                               | SQLITE_OPEN_TRANSIENT_DB,
                           nullptr)
                == SQLITE_OK);

        SqliteFileIO file_io(file);
        validate(referece_io, file_io);
    }
}

TEST_CASE("System IO against memory IO")
{
    for (int i = 0; i < 100; ++i)
    {
        auto filename = random_hex_string(8) + ".bin";
        auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });
        MemoryRandomIO referece_io;

#ifdef _WIN32
        HANDLE h = CHECK_WINAPI_CALL(CreateFileA(filename.c_str(),
                                                 GENERIC_READ | GENERIC_WRITE,
                                                 0,
                                                 nullptr,
                                                 CREATE_ALWAYS,
                                                 FILE_ATTRIBUTE_NORMAL,
                                                 nullptr),
                                     INVALID_HANDLE_VALUE);
#else
        int h = CHECK_POSIX_CALL(open(filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644), -1);
#endif
        SystemFileIO sio(h);
        validate(referece_io, sio);
    }
}
}    // namespace securefs
