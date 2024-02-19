#include "core/crypto_io.hpp"
#include "core/exceptions.hpp"
#include "core/rng.hpp"
#include "core/sys_io.hpp"
#include "core/tree_db.hpp"
#include "core/utilities.hpp"

#include "memory_io.hpp"

#include <absl/cleanup/cleanup.h>
#include <doctest/doctest.h>

namespace securefs
{
void treedb_test(bool exact_name_lookup)
{
    auto filename = random_hex_string(8) + ".db";
    auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

    TreeDB tree(SQLiteDB(filename.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr));

    {
        TreeDBScopedLocker locker(tree);
        tree.create_tables(exact_name_lookup);
    }

    {
        TreeDBScopedLocker locker(tree);
        tree.create_entry(tree.kRootINode, "abc", FileType::DIRECTORY);
    }
}

TEST_CASE("TreeDB")
{
    treedb_test(true);
    treedb_test(false);
}
}    // namespace securefs
