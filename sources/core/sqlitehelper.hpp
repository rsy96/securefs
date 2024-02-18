#pragma once
#include "core/utilities.hpp"

#include <sqlite3.h>

#include <stdexcept>

namespace securefs
{
struct SQLiteTraits
{
    static sqlite3* invalid() { return nullptr; }
    static void cleanup(sqlite3* db) { sqlite3_close(db); }
};

using SQLiteDB = RAII<sqlite3*, SQLiteTraits>;

class SQLiteException : public std::runtime_error
{
public:
    explicit SQLiteException(int code);
    explicit SQLiteException(sqlite3* db, int code);
};
}    // namespace securefs
