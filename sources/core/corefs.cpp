#include "core/corefs.hpp"
#include "core/rng.hpp"

#include <absl/cleanup/cleanup.h>
#include <absl/strings/str_split.h>
#include <sqlite3.h>
#include <utf8proc.h>

namespace securefs
{
namespace
{

#ifdef _WIN32
    const char kPathSep = '\\';
#else
    const char kPathSep = '/';
#endif

    constexpr CoreFileSystem::FileId kRootId = {};

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
                if (num_args != 1)
                {
                    sqlite3_result_error_code(context, SQLITE_MISUSE);
                    return;
                }
                auto data = static_cast<const CustomFuncData*>(sqlite3_user_data(context));
                auto input = static_cast<const unsigned char*>(sqlite3_value_blob(args[0]));
                if (!input || !data)
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
            throw SQLiteException(db, rc);
        }
    }
    std::vector<std::string_view> map_and_split(std::string_view name, utf8proc_option_t map_option)
    {
        utf8proc_uint8_t* transformed = nullptr;
        auto transformed_size = utf8proc_map(
            reinterpret_cast<const uint8_t*>(name.data()), name.size(), &transformed, map_option);
        if (transformed_size <= 0)
        {
            return {};
        }
        auto cleanup = absl::MakeCleanup([=]() { free(transformed); });
        return absl::StrSplit(
            std::string_view(reinterpret_cast<const char*>(transformed), transformed_size),
            kPathSep);
    }
}    // namespace

CoreFileSystem::CoreFileSystem(SQLiteDB db,
                               const FileSystemInherentParams& inherent_params,
                               const FileSystemMountParams& mount_params)
    : db_(std::move(db)), inherent_params_(inherent_params), mount_params_(mount_params)
{
    register_custom_functions();
    check_sqlite_call(sqlite3_prepare_v3(db_.get(),
                                         get_lookup_sql(mount_params_.name_lookup_mode()),
                                         -1,
                                         0,
                                         &create_st_.get(),
                                         nullptr));
}

void CoreFileSystem::initialize_tables()
{
    if (inherent_params_.exact_name_only())
    {
        check_sqlite_call(sqlite3_exec(db_.get(),
                                       R"(
            CREATE TABLE DirEntries (
                EntryId INTEGER PRIMARY KEY AUTOINCREMENT,
                ParentId BLOB NOT NULL,
                Name BLOB NOT NULL,
                FileId BLOB NOT NULL,
                FileType INT NOT NULL,
                LinkCount INTEGER NOT NULL DEFAULT 1 CHECK(LinkCount > 0 AND LinkCount < 65536)
            );

            CREATE UNIQUE INDEX ParentAndName ON DirEntries (ParentId, Name);
            CREATE INDEX FileIdIndex ON DirEntries (FileId);
            )",
                                       nullptr,
                                       nullptr,
                                       nullptr));
    }
    else
    {
        check_sqlite_call(sqlite3_exec(db_.get(),
                                       R"(
            CREATE TABLE DirEntries (
                EntryId INTEGER PRIMARY KEY AUTOINCREMENT,
                ParentId BLOB NOT NULL,
                Name BLOB NOT NULL,
                FileId BLOB NOT NULL,
                FileType INT NOT NULL,
                LinkCount INTEGER NOT NULL DEFAULT 1 CHECK(LinkCount > 0 AND LinkCount < 65536),
                CaseFoldedName TEXT AS (CASEFOLD_IF_CHANGED(Name)) STORED,
                UniNormedName TEXT AS (UNINORM_IF_CHANGED(Name)) STORED
            );

            CREATE UNIQUE INDEX ParentAndName ON DirEntries (ParentId, Name);
            CREATE INDEX ParentAndNameCaseFoled ON DirEntries (ParentId, CaseFoldedName) WHERE CaseFoldedName IS NOT NULL;
            CREATE INDEX ParentAndNameUniNormed ON DirEntries (ParentId, UniNormedName) WHERE UniNormedName IS NOT NULL;
            CREATE INDEX FileIdIndex ON DirEntries (FileId);
        )",
                                       nullptr,
                                       nullptr,
                                       nullptr));
    }
}

void CoreFileSystem::register_custom_functions()
{
    absl::MutexLock guard(&mutex());
    register_utf8proc_map(db_.get(), "CASEFOLD", UTF8PROC_CASEFOLD, false);
    register_utf8proc_map(db_.get(), "UNINORM", UTF8PROC_COMPOSE, false);
    register_utf8proc_map(db_.get(), "CASEFOLD_IF_CHANGED", UTF8PROC_CASEFOLD, true);
    register_utf8proc_map(db_.get(), "UNINORM_IF_CHANGED", UTF8PROC_COMPOSE, true);
}

void CoreFileSystem::throw_unsupported_name_lookup_mode(FileSystemMountParams::NameLookupMode mode)
{
    throw std::invalid_argument("Unsupported name lookup mode "
                                + FileSystemMountParams::NameLookupMode_Name(mode));
}

const char* CoreFileSystem::get_lookup_sql(FileSystemMountParams::NameLookupMode mode)
{
    switch (mode)
    {
    case FileSystemMountParams::NAME_LOOKUP_EXACT:
        return R"(
            select FileId, LinkCount, FileType from DirEntries where ParentId = ?1 and Name = ?2;
        )";

    case FileSystemMountParams::NAME_LOOKUP_CASE_INSENSITVE:
        return R"(
            select FileId, LinkCount, FileType from DirEntries where ParentId = ?1 and 
                (CaseFoldedName = ?2 or Name = ?2) limit 1;
        )";

    case FileSystemMountParams::NAME_LOOKUP_UNICODE_NORMED:
        return R"(
            select FileId, LinkCount, FileType from DirEntries where ParentId = ?1 and 
                (UniNormedName = ?2 or Name = ?2) limit 1;
        )";

    default:
        throw_unsupported_name_lookup_mode(mode);
    }
}

const char* CoreFileSystem::get_create_sql()
{
    return R"(
            insert into DirEntries (ParentId, Name, FileId, FileType, LinkCount)
                values (?, ?, ?, ?, 1);
        )";
}

void CoreFileSystem::check_sqlite_call(int rc)
{
    if (rc != SQLITE_OK)
    {
        throw SQLiteException(db_.get(), rc);
    }
}

CoreFileSystem::LookupResult CoreFileSystem::lookup(std::string_view name)
{
    CoreFileSystem::LookupResult result;
    std::vector<std::string_view> components;

    switch (mount_params_.name_lookup_mode())
    {
    case FileSystemMountParams::NAME_LOOKUP_EXACT:
        components = absl::StrSplit(name, '/');
        break;

    case FileSystemMountParams::NAME_LOOKUP_CASE_INSENSITVE:
        components = map_and_split(name, UTF8PROC_CASEFOLD);

    case FileSystemMountParams::NAME_LOOKUP_UNICODE_NORMED:
        components = map_and_split(name, UTF8PROC_COMPOSE);
        break;

    default:
        throw_unsupported_name_lookup_mode(mount_params_.name_lookup_mode());
    }

    if (components.empty())
    {
        return result;
    }

    FileId parent = kRootId;
    for (size_t i = 0; i < components.size(); ++i)
    {
        check_sqlite_call(sqlite3_reset(lookup_st_.get()));
        check_sqlite_call(
            sqlite3_bind_blob64(lookup_st_.get(), 1, parent.data(), parent.size(), SQLITE_STATIC));
        check_sqlite_call(sqlite3_bind_text64(lookup_st_.get(),
                                              2,
                                              components[i].data(),
                                              components[i].size(),
                                              SQLITE_STATIC,
                                              SQLITE_UTF8));
        int rc = sqlite3_step(lookup_st_.get());
        if (rc == SQLITE_ROW)
        {
            if (sqlite3_column_bytes(lookup_st_.get(), 1) != parent.size())
            {
                throw std::runtime_error("Wrong ID size in the database");
            }
            result.parent_id = parent;
            memcpy(parent.data(), sqlite3_column_blob(lookup_st_.get(), 1), parent.size());
            result.file_id.emplace(parent);
            result.link_count = sqlite3_column_int(lookup_st_.get(), 2);
            result.file_type = static_cast<FileType>(sqlite3_column_int(lookup_st_.get(), 3));
            if (result.file_type == FileType::FILE_TYPE_UNSPECIFED
                || !FileType_IsValid(result.file_type))
            {
                throw std::runtime_error("Invalid file type in the database");
            }
        }
        else if (i + 1 != components.size())
        {
            throw NameLookupException();
        }
        else
        {
            result.parent_id = parent;
            result.file_id.reset();
            result.link_count = 0;
            result.file_type = FileType::FILE_TYPE_UNSPECIFED;
        }
    }

    auto last_sep_index = name.rfind(kPathSep);
    result.last_component_name.assign(name.substr(last_sep_index + 1));
    return result;
}

const char* NameLookupException::what() const noexcept
{
    return "File name has non-existent component";
}

}    // namespace securefs
