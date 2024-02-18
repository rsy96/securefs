#include "core/sqlitehelper.hpp"

#include "sqlitehelper.hpp"
#include <absl/strings/str_format.h>

securefs::SQLiteException::SQLiteException(int code)
    : runtime_error(absl::StrFormat("SQLite error %d: %s", code, sqlite3_errstr(code)))
{
}

securefs::SQLiteException::SQLiteException(sqlite3* db, int code)
    : runtime_error(absl::StrFormat("SQLite error %d: %s", code, sqlite3_errmsg(db)))
{
}
