#include "core/corefs.hpp"

#include <SQLiteCpp/Exception.h>
#include <sqlite3.h>
#include <utf8proc.h>

namespace securefs
{

namespace
{
    void register_utf8proc_map(sqlite3* db,
                               const char* name,
                               utf8proc_option_t map_option,
                               bool skip_same)
    {
        struct CustomFuncData
        {
            utf8proc_option_t map_option;
            bool skip_same;
        };

        int rc = sqlite3_create_function_v2(
            db,
            name,
            1,
            SQLITE_UTF8 | SQLITE_DETERMINISTIC,
            new CustomFuncData{map_option, skip_same},
            [](sqlite3_context* context, int num_args, sqlite3_value** args)
            {
                auto data = static_cast<const CustomFuncData*>(sqlite3_user_data(context));
                if (num_args != 1)
                {
                    sqlite3_result_error_code(context, SQLITE_MISUSE);
                    return;
                }
                auto input = static_cast<const unsigned char*>(sqlite3_value_blob(args[0]));
                if (!input)
                {
                    sqlite3_result_error_code(context, SQLITE_MISUSE);
                    return;
                }
                auto input_size = sqlite3_value_bytes(args[0]);
                utf8proc_uint8_t* transformed = nullptr;
                auto transformed_size
                    = utf8proc_map(input, input_size, &transformed, data->map_option);
                if (transformed_size < 0)
                {
                    sqlite3_result_null(context);
                    return;
                }
                if (data->skip_same
                    && std::equal(
                        input, input + input_size, transformed, transformed + transformed_size))
                {
                    free(transformed);
                    sqlite3_result_null(context);
                    return;
                }
                sqlite3_result_text(
                    context, reinterpret_cast<const char*>(transformed), transformed_size, &free);
            },
            nullptr,
            nullptr,
            [](void* p) { delete static_cast<CustomFuncData*>(p); });
        if (rc != SQLITE_OK)
        {
            throw SQLite::Exception(db, rc);
        }
    }
}    // namespace

void CoreFileSystem::initialize_tables()
{
    if (inherent_params_.exact_name_only())
    {
        db_.exec(R"(
        CREATE TABLE DirEntries (
            EntryId INTEGER PRIMARY KEY AUTOINCREMENT,
            ParentId BLOB NOT NULL,
            Name BLOB NOT NULL,
            FileId BLOB NOT NULL,
            LinkCount INTEGER NOT NULL DEFAULT 1
        );

        CREATE UNIQUE INDEX ParentAndName ON DirEntries (ParentId, Name);
        CREATE INDEX FileIdIndex ON DirEntries (FileId);
    )");
    }
    else
    {
        db_.exec(R"(
        CREATE TABLE DirEntries (
            EntryId INTEGER PRIMARY KEY AUTOINCREMENT,
            ParentId BLOB NOT NULL,
            Name BLOB NOT NULL,
            FileId BLOB NOT NULL,
            LinkCount INTEGER NOT NULL DEFAULT 1,
            CaseFoldedName TEXT AS (CASEFOLD_IF_CHANGED(Name)) STORED,
            UniNormedName TEXT AS (UNINORM_IF_CHANGED(Name)) STORED
        );

        CREATE UNIQUE INDEX ParentAndName ON DirEntries (ParentId, Name);
        CREATE INDEX ParentAndNameCaseFoled ON DirEntries (ParentId, CaseFoldedName) WHERE CaseFoldedName IS NOT NULL;
        CREATE INDEX ParentAndNameUniNormed ON DirEntries (ParentId, UniNormedName) WHERE UniNormedName IS NOT NULL;
        CREATE INDEX FileIdIndex ON DirEntries (FileId);
    )");
    }
}

void CoreFileSystem::register_custom_functions()
{
    register_utf8proc_map(db_.getHandle(), "CASEFOLD", UTF8PROC_CASEFOLD, false);
    register_utf8proc_map(db_.getHandle(), "UNINORM", UTF8PROC_COMPOSE, false);
    register_utf8proc_map(db_.getHandle(), "CASEFOLD_IF_CHANGED", UTF8PROC_CASEFOLD, true);
    register_utf8proc_map(db_.getHandle(), "UNINORM_IF_CHANGED", UTF8PROC_COMPOSE, true);
}

}    // namespace securefs
