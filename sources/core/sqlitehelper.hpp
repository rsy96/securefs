#pragma once
#include "utilities.hpp"

#include <sqlite3.h>

#include <absl/types/span.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securefs
{
class SQLiteStatement;

struct SQLiteTraits
{
    static sqlite3* invalid() { return nullptr; }
    static void cleanup(sqlite3* db) { sqlite3_close(db); }
};

class SQLiteDB
{
public:
    SQLiteDB() {}
    SQLiteDB(const char* filename, int flags, const char* vfs);

    void exec(const char* sql);

    sqlite3* get() noexcept { return ptr_->get(); }
    explicit operator bool() const noexcept { return ptr_->get(); }
    int64_t last_changes() noexcept { return sqlite3_changes64(ptr_->get()); }

private:
    std::shared_ptr<RAII<sqlite3*, SQLiteTraits>> ptr_;
};

struct SQLiteStatementTraits
{
    static sqlite3_stmt* invalid() { return nullptr; }
    static void cleanup(sqlite3_stmt* stmt) { sqlite3_finalize(stmt); }
};

class SQLiteStatement
{
public:
    SQLiteStatement() {}
    SQLiteStatement(SQLiteDB db, std::string sql);

    void reset();
    bool step();

    void bind_int(int column, int64_t value);
    void bind_text(int column, std::string_view value);
    void bind_blob(int column, absl::Span<const unsigned char> value);

    int64_t get_int(int column);
    std::string_view get_text(int column);
    absl::Span<const unsigned char> get_blob(int column);
    bool is_null(int column);

    explicit operator bool() const noexcept { return holder_.get(); }

private:
    SQLiteDB db_;
    std::string sql_;
    RAII<sqlite3_stmt*, SQLiteStatementTraits> holder_;

    void prologue();
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
