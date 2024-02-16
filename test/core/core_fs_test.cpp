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

        CoreFileSystem cfs(
            SQLite::Database(filename, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE, 200),
            inherent_params,
            mount_params);
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
