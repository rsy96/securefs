#pragma once
#include "core/utilities.hpp"

#include <sqlite3.h>

#include <absl/types/span.h>
#include <stdexcept>
#include <string_view>

namespace securefs
{
class SQLiteStatement;

struct SQLiteTraits
{
    static sqlite3* invalid() { return nullptr; }
    static void cleanup(sqlite3* db) { sqlite3_close(db); }
};

class SQLiteDB : public RAII<sqlite3*, SQLiteTraits>
{
public:
    SQLiteDB() {}
    SQLiteDB(const char* filename, int flags, const char* vfs);

    void exec(const char* sql);
    SQLiteStatement statement(std::string_view sql);
};

struct SQLiteStatementTraits
{
    static sqlite3_stmt* invalid() { return nullptr; }
    static void cleanup(sqlite3_stmt* stmt) { sqlite3_finalize(stmt); }
};

class SQLiteStatement : public RAII<sqlite3_stmt*, SQLiteStatementTraits>
{
public:
    SQLiteStatement() : RAII() {}
    SQLiteStatement(sqlite3* db, std::string_view sql);
    SQLiteStatement(const SQLiteDB& db, std::string_view sql) : SQLiteStatement(db.get(), sql) {}

    bool step();
    void bind_int(int column, int64_t value);
    void bind_text(int column, std::string_view value);
    void bind_blob(int column, absl::Span<const unsigned char> value);

    int64_t get_int(int column);
    std::string_view get_text(int column);
    absl::Span<const unsigned char> get_blob(int column);
};

class SQLiteException : public std::runtime_error
{
public:
    explicit SQLiteException(int code);
    explicit SQLiteException(sqlite3* db, int code);
};

void check_sqlite_call(int code);
void check_sqlite_call(sqlite3* db, int code);
}    // namespace securefs
