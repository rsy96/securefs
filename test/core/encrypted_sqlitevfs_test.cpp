#include "core/encrypted_sqlitevfs.hpp"
#include "core/rng.hpp"
#include "core/sqlitehelper.hpp"
#include "core/utilities.hpp"

#include <absl/cleanup/cleanup.h>
#include <doctest/doctest.h>

#include <cstdio>

namespace securefs
{
TEST_CASE("Basic SQLite operations")
{
    EncryptedSqliteVfsRegistry::Params params;
    generate_random(absl::MakeSpan(params.encryption_params.key));
    params.encryption_params.underlying_block_size = 4096 + 12 + 16;

    auto filename = random_hex_string(8) + ".db";
    auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

    {
        EncryptedSqliteVfsRegistry registry(params);
        SQLiteDB db(filename.c_str(),
                    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                    registry.vfs_name().c_str());
        db.exec("PRAGMA locking_mode = EXCLUSIVE; PRAGMA journal_mode=WAL;");

        SQLiteStatement get_journal_mode(db, "PRAGMA journal_mode;");
        REQUIRE(get_journal_mode.step());
        REQUIRE(get_journal_mode.get_text(0) == "wal");

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
    }
    {
        params.read_only = true;
        EncryptedSqliteVfsRegistry registry(params);
        SQLiteDB db(filename.c_str(), SQLITE_OPEN_READONLY, registry.vfs_name().c_str());
        SQLiteStatement st(db, "select count(*) from Movies;");
        REQUIRE(st.step());
        REQUIRE(st.get_int(0) == 5);
    }
}
}    // namespace securefs
