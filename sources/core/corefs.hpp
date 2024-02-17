#pragma once

#include "protos/params.pb.h"

#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Statement.h>
#include <SQLiteCpp/Transaction.h>
#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>

#include <array>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace securefs
{

class CoreTransaction;

class CoreFileSystem
{
public:
    explicit CoreFileSystem(SQLite::Database db,
                            const FileSystemInherentParams& inherent_params,
                            const FileSystemMountParams& mount_params);

    void initialize_tables() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

    absl::Mutex& mutex() noexcept ABSL_LOCK_RETURNED(mu_) { return mu_; }

    using FileId = std::array<unsigned char, 32>;

    struct LookupResult
    {
        FileId parent_id{};
        std::string last_component_name;
        std::optional<FileId> file_id;
        FileType file_type{};
        int link_count = 0;
    };

    LookupResult lookup(std::string_view name) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
    void create(const FileId& parent_id,
                std::string_view component_name,
                FileType file_type,
                FileId& file_id_output) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

private:
    absl::Mutex mu_;
    SQLite::Database db_ ABSL_GUARDED_BY(mu_);
    SQLite::Statement lookup_st_ ABSL_GUARDED_BY(mu_);
    SQLite::Statement create_st_ ABSL_GUARDED_BY(mu_);
    FileSystemInherentParams inherent_params_;
    FileSystemMountParams mount_params_;

    void register_custom_functions() ABSL_LOCKS_EXCLUDED(mu_);

    [[noreturn]] static void
    throw_unsupported_name_lookup_mode(FileSystemMountParams::NameLookupMode mode);

    static const char* get_lookup_sql(FileSystemMountParams::NameLookupMode mode);
    static const char* get_create_sql();

    friend class CoreTransaction;
};

class CoreTransaction : public SQLite::Transaction
{
public:
    explicit CoreTransaction(CoreFileSystem& cfs) ABSL_EXCLUSIVE_LOCKS_REQUIRED(cfs.mu_);
    CoreTransaction(CoreTransaction&&) = delete;
    CoreTransaction& operator=(CoreTransaction&&) = delete;
};

class NameLookupException : public std::exception
{
public:
    const char* what() const noexcept override;
};
}    // namespace securefs
