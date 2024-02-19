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
TEST_CASE("TreeDB")
{
    auto filename = random_hex_string(8) + ".db";
    auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

    TreeDB tree(SQLiteDB(filename.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr));
    tree.lock_and_enter_transaction();
    tree.create_tables(false);
    tree.unlock_and_leave_transaction(false);
}
}    // namespace securefs
