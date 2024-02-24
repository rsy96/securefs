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

    SynchronizedInPlace<TreeDB> synchronized_tree(
        SQLiteDB(filename.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr));

    synchronized_tree.synchronized([&](auto&& tree) { tree.create_tables(exact_name_lookup); });

    std::vector<int64_t> inodes;

    synchronized_tree.synchronized(
        [&](TreeDB& tree)
        {
            inodes.push_back(tree.create_entry(1, "abc", FileType::DIRECTORY));
            inodes.push_back(tree.create_entry(1, "AaBbCc", FileType::REGULAR));
            inodes.push_back(tree.create_entry(1, "caf\xc3\xa9\xcc\x81", FileType::SYMLINK));
            inodes.push_back(tree.create_entry(2, "--AaBbCc--", FileType::REGULAR));
        });

    synchronized_tree.synchronized(
        [&](TreeDB& tree)
        {
            for (auto [mode, mode_name] : magic_enum::enum_entries<NameLookupMode>())
            {
                if (exact_name_lookup && mode != NameLookupMode::EXACT)
                {
                    continue;
                }
                auto result = tree.lookup_entry(1, "abc", mode);
                REQUIRE(result);
                CHECK(result->inode != 0);
                CHECK(result->file_type == FileType::DIRECTORY);
                CHECK(result->link_count == 1);
            }

            CHECK(tree.lookup_entry(1, "AaBbCc", NameLookupMode::EXACT).value().inode
                  == inodes.at(1));
            CHECK(
                tree.lookup_entry(1, "caf\xc3\xa9\xcc\x81", NameLookupMode::EXACT).value().file_type
                == FileType::SYMLINK);
            if (!exact_name_lookup)
            {
                CHECK(tree.lookup_entry(1, "aabbcc", NameLookupMode::CASE_INSENSITIVE)
                          .value()
                          .file_type
                      == FileType::REGULAR);
                CHECK(tree.lookup_entry(1, "caF\xc3\xa9\xcc\x81", NameLookupMode::CASE_INSENSITIVE)
                          .value()
                          .file_type
                      == FileType::SYMLINK);
                CHECK(tree.lookup_entry(1, "cafe\xcc\x81\xcc\x81", NameLookupMode::UNINORM)
                          .value()
                          .file_type
                      == FileType::SYMLINK);
            }
        });

    synchronized_tree.synchronized([&](TreeDB& tree)
                                   { CHECK(tree.remove_entry(1, inodes.at(0))); });

    synchronized_tree.synchronized(
        [&](TreeDB& tree)
        {
            CHECK(!tree.lookup_entry(1, "abc", NameLookupMode::EXACT).has_value());
            CHECK(tree.lookup_entry(1, "AaBbCc", NameLookupMode::EXACT).has_value());
        });
}

TEST_CASE("TreeDB")
{
    treedb_test(true);
    treedb_test(false);
}
}    // namespace securefs
