#include "core/crypto_io.hpp"
#include "core/exceptions.hpp"
#include "core/rng.hpp"
#include "core/sys_io.hpp"
#include "core/tree_db.hpp"
#include "core/utilities.hpp"

#include "memory_io.hpp"

#include <absl/cleanup/cleanup.h>
#include <doctest/doctest.h>
#include <magic_enum.hpp>

namespace securefs
{
void treedb_test(bool exact_name_lookup)
{
    CAPTURE(exact_name_lookup);

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

    {
        TreeDBScopedLocker locker(tree);

        for (auto [mode, mode_name] : magic_enum::enum_entries<NameLookupMode>())
        {
            if (exact_name_lookup && mode != NameLookupMode::EXACT)
            {
                continue;
            }
            auto result = tree.lookup_entry(TreeDB::kRootINode, "abc", mode);
            REQUIRE(result);
            CHECK(result->inode != 0);
            CHECK(result->file_type == FileType::DIRECTORY);
            CHECK(result->link_count == 1);
        }
    }
}

TEST_CASE("TreeDB")
{
    treedb_test(true);
    treedb_test(false);
}
}    // namespace securefs
