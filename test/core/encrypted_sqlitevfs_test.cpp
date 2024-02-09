#include "core/encrypted_sqlitevfs.hpp"
#include "core/rng.hpp"
#include "core/utilities.hpp"

#include <SQLiteCpp/SQLiteCpp.h>
#include <absl/cleanup/cleanup.h>
#include <doctest/doctest.h>

#include <cstdio>

namespace securefs
{
TEST_CASE("Basic SQLite operations")
{
    AesGcmRandomIO::Params params;
    generate_random(params.key.data(), params.key.size());
    params.underlying_block_size = 4096;
    EncryptedSqliteVfsRegistry registry(params);

    auto filename = random_hex_string(8) + ".db";
    auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

    SQLite::Database db(
        filename, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE, 100, registry.vfs_name().c_str());

    db.exec("PRAGMA locking_mode = EXCLUSIVE;");
    CHECK(db.execAndGet("PRAGMA journal_mode=WAL;").getString() == "wal");
    db.exec(R"(
        CREATE TABLE Movies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL UNIQUE,
            year INTEGER CHECK(year >= 1900),
            director TEXT,
            genre TEXT,
            rating REAL CHECK(rating BETWEEN 0 AND 10)
        );
    )");
    db.exec(R"(
        INSERT INTO Movies (title, year, director, genre, rating)
        VALUES ('The Shawshank Redemption', 1994, 'Frank Darabont', 'Drama', 9.3),
            ('The Godfather', 1972, 'Francis Ford Coppola', 'Crime', 9.2),
            ('The Dark Knight', 2008, 'Christopher Nolan', 'Action/Thriller', 9.0),
            ('Pulp Fiction', 1994, 'Quentin Tarantino', 'Crime', 8.9),
            ('Schindlers List', 1993, 'Steven Spielberg', 'Historical Drama', 8.9);
    )");

    CHECK(db.execAndGet("select count(*) from Movies;").getInt64() == 5);
}
}    // namespace securefs
