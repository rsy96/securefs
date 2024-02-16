#pragma once

#include "protos/params.pb.h"

#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Transaction.h>
#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace securefs
{

class CoreFileSystem
{
public:
    explicit CoreFileSystem(SQLite::Database db,
                            const FileSystemInherentParams& inherent_params,
                            const FileSystemMountParams& mount_params)
        : db_(std::move(db)), inherent_params_(inherent_params), mount_params_(mount_params)
    {
        register_custom_functions();
    }

    void initialize_tables() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex());

    SQLite::Transaction transaction() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex())
    {
        return SQLite::Transaction(db_);
    }
    absl::Mutex& mutex() noexcept { return mu_; }

    using FileId = std::array<unsigned char, 32>;

    struct LookupResult
    {
        FileId parent_id;
        std::string last_component_name;
        std::optional<FileId> file_id;
        FileType file_type;
    };

    LookupResult lookup(std::string_view name) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex());

private:
    absl::Mutex mu_;
    SQLite::Database db_ ABSL_GUARDED_BY(mutex());
    FileSystemInherentParams inherent_params_;
    FileSystemMountParams mount_params_;

    void register_custom_functions();
};
}    // namespace securefs
