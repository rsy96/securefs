#include "tree_db.hpp"
#include "utilities.hpp"

#include <absl/cleanup/cleanup.h>
#include <boost/numeric/conversion/cast.hpp>
#include <string_view>
#include <utf8proc.h>

namespace securefs
{
namespace
{
    constexpr utf8proc_option_t kCaseFold = UTF8PROC_CASEFOLD;
    constexpr utf8proc_option_t kUniNorm = UTF8PROC_COMPOSE;

    /// @brief A custom scalar SQLite function.
    /// The function takes a single text argument, and either case fold or perform unicode
    /// normalization on it. However, if the value is unchanged, the return value is NULL. This
    /// special behavior is to save storage when the original is already in its final form.
    void custom_sqlite_utfproc_map(sqlite3_context* ctx, int nArg, sqlite3_value** values)
    {
        if (nArg != 1)
        {
            return sqlite3_result_error_code(ctx, SQLITE_MISUSE);
        }
        auto option = *static_cast<const utf8proc_option_t*>(sqlite3_user_data(ctx));
        std::string_view input_text(reinterpret_cast<const char*>(sqlite3_value_text(values[0])),
                                    boost::numeric_cast<size_t>(sqlite3_value_bytes(values[0])));
        unsigned char* mapped = nullptr;
        auto size = utf8proc_map(reinterpret_cast<const unsigned char*>(input_text.data()),
                                 input_text.size(),
                                 &mapped,
                                 option);
        if (size <= 0)
        {
            return sqlite3_result_null(ctx);
        }
        if (std::string_view(reinterpret_cast<const char*>(mapped), size) == input_text)
        {
            free(mapped);
            return sqlite3_result_null(ctx);
        }
        return sqlite3_result_text64(
            ctx, reinterpret_cast<const char*>(mapped), size, &free, SQLITE_UTF8);
    }

}    // namespace

void TreeDB::create_tables(bool exact_only)
{
    db_.exec(R"(
            create table Entries (
                inode integer not null,
                parent_inode integer not null,
                name text not null,
                mode integer not null,
                link_count integer not null,
                uid integer,
                gid integer,
                security_descriptor blob
            );
            create index InodeOnEntries on Entries (inode);
            create unique index ParentNameOnEntries on Entries (parent_inode, name);

            create table Xattr (
                inode integer primary key,
                xattr_key text not null,
                xattr_value blob not null
            );
        )");
    if (!exact_only)
    {
        db_.exec(R"(
            alter table Entries add column casefolded_name as (casefold_if_changed(name));
            alter table Entries add column uninormed_name as (uninorm_if_changed(name));
            create index ParentCaseFoldedNameOnEntries on Entries (parent_inode, casefolded_name);
            create index ParentUniNormedNameOnEntries on Entries (parent_inode, uninormed_name);
        )");
    }
}

TreeDB::TreeDB(SQLiteDB db)
    : db_(std::move(db))
    , begin_(db_, "begin immediate;")
    , commit_(db_, "commit")
    , rollback_(db_, "rollback")
{
    check_sqlite_call(db_.get(),
                      sqlite3_create_function_v2(db_.get(),
                                                 "casefold_if_changed",
                                                 1,
                                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                                 (void*)&kCaseFold,
                                                 &custom_sqlite_utfproc_map,
                                                 nullptr,
                                                 nullptr,
                                                 SQLITE_STATIC));
    check_sqlite_call(db_.get(),
                      sqlite3_create_function_v2(db_.get(),
                                                 "uninorm_if_changed",
                                                 1,
                                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                                 (void*)&kUniNorm,
                                                 &custom_sqlite_utfproc_map,
                                                 nullptr,
                                                 nullptr,
                                                 SQLITE_STATIC));
}

void TreeDB::lock_and_enter_transaction()
{
    mu_.Lock();
    begin_.reset();
    begin_.step();
}

void TreeDB::unlock_and_leave_transaction(bool rollback)
{
    if (rollback)
    {
        rollback_.reset();
        rollback_.step();
    }
    else
    {
        commit_.reset();
        commit_.step();
    }
    mu_.Unlock();
}

}    // namespace securefs
