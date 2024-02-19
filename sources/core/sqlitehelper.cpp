#include "core/sqlitehelper.hpp"

#include <absl/strings/str_format.h>

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
}    // namespace securefs
