#pragma once

#include "sqlitehelper.hpp"

#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>

#include <limits>
#include <optional>
#include <string_view>

namespace securefs
{
enum class NameLookupMode
{
    EXACT = 0,
    CASE_INSENSITIVE = 1,
    UNINORM = 2,
};

enum class FileType
{
    REGULAR = 0,
    DIRECTORY = 1,
    SYMLINK = 2,
};

/// @brief The filesystem tree, saved in a SQLite database.
class ABSL_LOCKABLE TreeDB
{
public:
    static constexpr int64_t kRootINode = std::numeric_limits<int64_t>::min();

    explicit TreeDB(SQLiteDB db);

    /// @brief Create all the tables needed.
    /// @param exact_only If true, skips the case folded and unicode normalized names in the table.
    void create_tables(bool exact_only);

    int64_t create_entry(int64_t parent_inode, std::string_view name, FileType file_type);

    struct LookupResult
    {
        int64_t inode{};
        FileType file_type{};
        int64_t link_count{};
    };

    std::optional<LookupResult>
    lookup_entry(int64_t parent_inode, std::string_view name, NameLookupMode lookup_mode);

    void lock_and_enter_transaction() ABSL_EXCLUSIVE_LOCK_FUNCTION(mu_);
    void leave_transaction_and_unlock(bool rollback) ABSL_UNLOCK_FUNCTION(mu_);

    void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION(mu_) { lock_and_enter_transaction(); }
    void unlock() ABSL_UNLOCK_FUNCTION(mu_)
    {
        leave_transaction_and_unlock(std::uncaught_exceptions() > 0);
    }

private:
    absl::Mutex mu_;
    SQLiteDB db_;
    SQLiteStatement begin_, commit_, rollback_, lookup_count_of_inode_, lookup_exact_,
        lookup_case_insensitive_, lookup_uninormed_, create_, remove_;
};

}    // namespace securefs
