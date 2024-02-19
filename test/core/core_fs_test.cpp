#include "core/corefs.hpp"
#include "core/utilities.hpp"

#include <absl/cleanup/cleanup.h>
#include <doctest/doctest.h>

#include <cstdio>

namespace securefs
{
namespace
{
    void test_basics_of_core_fs(bool exact_only,
                                FileSystemMountParams::NameLookupMode name_lookup_mode)
    {
        if (exact_only && name_lookup_mode != FileSystemMountParams::NAME_LOOKUP_EXACT)
        {
            return;
        }
        FileSystemInherentParams inherent_params;
        inherent_params.set_exact_name_only(exact_only);
        inherent_params.set_underlying_block_size(512);

        FileSystemMountParams mount_params;
        mount_params.set_name_lookup_mode(name_lookup_mode);

        auto filename = random_hex_string(8) + ".db";
        auto cleanup = absl::MakeCleanup([&]() { remove(filename.c_str()); });

        SQLiteDB db;
        int rc = sqlite3_open_v2(filename.c_str(),
                                 &db.get(),
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                                 nullptr);
        REQUIRE(rc == SQLITE_OK);

        CoreFileSystem cfs(std::move(db), inherent_params, mount_params);

        absl::MutexLock lock_guard(&cfs.mutex());
        REQUIRE(cfs.lookup("/a/b/c").file_id.has_value());
    }
}    // namespace

TEST_CASE("Basics of CoreFS")
{
    for (auto exact_only : {false, true})
    {
        auto mode_desc = FileSystemMountParams::NameLookupMode_descriptor();
        for (int i = 0; i < mode_desc->value_count(); ++i)
        {
            auto mode
                = static_cast<FileSystemMountParams::NameLookupMode>(mode_desc->value(i)->number());
            if (mode == FileSystemMountParams::NAME_LOOKUP_UNSPECIFIED)
            {
                continue;
            }
            test_basics_of_core_fs(exact_only, mode);
        }
    }
}
}    // namespace securefs
