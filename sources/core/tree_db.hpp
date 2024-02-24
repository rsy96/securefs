#pragma once

#include "sqlitehelper.hpp"

#include <limits>
#include <mutex>
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
class TreeDB
{
public:
    static constexpr uint64_t kRootINode = static_cast<uint64_t>(-1);

    explicit TreeDB(SQLiteDB db);

    /// @brief Create all the tables needed.
    /// @param exact_only If true, skips the case folded and unicode normalized names in the table.
    void create_tables(bool exact_only);

    uint64_t create_entry(uint64_t parent_inode, std::string_view name, FileType file_type);

    struct LookupResult
    {
        uint64_t inode{};
        FileType file_type{};
        int64_t link_count{};
    };

    std::optional<LookupResult>
    lookup_entry(uint64_t parent_inode, std::string_view name, NameLookupMode lookup_mode);

    /// @brief Remove an entry.
    /// @param parent_inode The inode of the parent directory.
    /// @param inode The inode to remove a link.
    /// @return Whether all references to the inode are removed in the table. The underlying storage
    /// should be cleaned up if this is true.
    bool remove_entry(uint64_t parent_inode, uint64_t inode);

    void lock_and_enter_transaction();
    void leave_transaction_and_unlock(bool rollback);

    void lock() { lock_and_enter_transaction(); }
    void unlock() { leave_transaction_and_unlock(std::uncaught_exceptions() > 0); }

private:
    std::mutex mu_;
    SQLiteDB db_;
    SQLiteStatement begin_, commit_, rollback_, lookup_count_of_inode_, lookup_exact_,
        lookup_case_insensitive_, lookup_uninormed_, create_, decrement_link_count_, remove_;
};

}    // namespace securefs
