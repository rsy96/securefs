#pragma once

#include "sqlitehelper.hpp"

#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>

namespace securefs
{
/// @brief The filesystem tree, saved in a SQLite database.
class ABSL_LOCKABLE TreeDB
{
public:
    explicit TreeDB(SQLiteDB db);

    /// @brief Create all the tables needed.
    /// @param exact_only If true, skips the case folded and unicode normalized names in the table.
    void create_tables(bool exact_only) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

    void lock_and_enter_transaction() ABSL_EXCLUSIVE_LOCK_FUNCTION(mu_);
    void unlock_and_leave_transaction(bool rollback) ABSL_UNLOCK_FUNCTION(mu_);

private:
    absl::Mutex mu_;
    SQLiteDB db_ ABSL_GUARDED_BY(mu_);
    SQLiteStatement begin_ ABSL_GUARDED_BY(mu_), commit_ ABSL_GUARDED_BY(mu_),
        rollback_ ABSL_GUARDED_BY(mu_), lookup_ ABSL_GUARDED_BY(mu_), create_ ABSL_GUARDED_BY(mu_),
        remove_ ABSL_GUARDED_BY(mu_);

    friend class TreeDBScopedLocker;
};

class ABSL_SCOPED_LOCKABLE TreeDBScopedLocker
{
private:
    TreeDB& db_;

public:
    explicit TreeDBScopedLocker(TreeDB& db) ABSL_EXCLUSIVE_LOCK_FUNCTION(db.mu_) : db_(db)
    {
        db.lock_and_enter_transaction();
    }

    ~TreeDBScopedLocker() ABSL_UNLOCK_FUNCTION();
};

}    // namespace securefs
