#include "sqlitehelper.hpp"

#include <absl/strings/str_format.h>
#include <boost/numeric/conversion/cast.hpp>

namespace securefs
{

SQLiteException::SQLiteException(int code)
    : runtime_error(absl::StrFormat("SQLite error %d: %s", code, sqlite3_errstr(code)))
{
}

SQLiteException::SQLiteException(sqlite3* db, int code)
    : runtime_error(absl::StrFormat("SQLite error %d: %s", code, sqlite3_errmsg(db)))
{
}

void check_sqlite_call(int code)
{
    if (code != SQLITE_OK)
        throw SQLiteException(code);
}
void check_sqlite_call(sqlite3* db, int code)
{
    if (code != SQLITE_OK)
        throw SQLiteException(db, code);
}

SQLiteDB::SQLiteDB(const char* filename, int flags, const char* vfs)
{
    ptr_ = std::make_shared<RAII<sqlite3*, SQLiteTraits>>();
    check_sqlite_call(sqlite3_open_v2(filename, &ptr_->get(), flags, vfs));
}

void SQLiteDB::exec(const char* sql)
{
    check_sqlite_call(sqlite3_exec(get(), sql, nullptr, nullptr, nullptr));
}

SQLiteStatement SQLiteDB::statement(std::string_view sql) { return SQLiteStatement(*this, sql); }

SQLiteStatement::SQLiteStatement(SQLiteDB db, std::string_view sql) : db_(std::move(db))
{
    check_sqlite_call(
        db_.get(),
        sqlite3_prepare_v2(
            db_.get(), sql.data(), boost::numeric_cast<int>(sql.size()), &holder_.get(), nullptr));
}

void SQLiteStatement::reset() { check_sqlite_call(db_.get(), sqlite3_reset(holder_.get())); }

bool SQLiteStatement::step()
{
    int rc = sqlite3_step(holder_.get());

    switch (rc)
    {
    case SQLITE_ROW:
        return true;
    case SQLITE_DONE:
    case SQLITE_OK:
        return false;
    default:
        throw SQLiteException(db_.get(), rc);
    }
}

void SQLiteStatement::bind_int(int column, int64_t value)
{
    check_sqlite_call(db_.get(), sqlite3_bind_int64(holder_.get(), column, value));
}

void SQLiteStatement::bind_text(int column, std::string_view value)
{
    check_sqlite_call(
        db_.get(),
        sqlite3_bind_text64(
            holder_.get(), column, value.data(), value.size(), SQLITE_STATIC, SQLITE_UTF8));
}

void SQLiteStatement::bind_blob(int column, absl::Span<const unsigned char> value)
{
    check_sqlite_call(
        db_.get(),
        sqlite3_bind_blob64(holder_.get(), column, value.data(), value.size(), SQLITE_STATIC));
}

int64_t SQLiteStatement::get_int(int column) { return sqlite3_column_int64(holder_.get(), column); }

std::string_view SQLiteStatement::get_text(int column)
{
    return {reinterpret_cast<const char*>(sqlite3_column_text(holder_.get(), column)),
            boost::numeric_cast<size_t>(sqlite3_column_bytes(holder_.get(), column))};
}

absl::Span<const unsigned char> SQLiteStatement::get_blob(int column)
{
    return {static_cast<const unsigned char*>(sqlite3_column_blob(holder_.get(), column)),
            boost::numeric_cast<size_t>(sqlite3_column_bytes(holder_.get(), column))};
}

bool SQLiteStatement::is_null(int column)
{
    return sqlite3_column_type(holder_.get(), column) == SQLITE_NULL;
}

}    // namespace securefs
