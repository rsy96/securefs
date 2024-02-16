#pragma once

#include "protos/params.pb.h"

#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Transaction.h>

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

    void initialize_tables();

    SQLite::Transaction transaction() { return SQLite::Transaction(db_); }

private:
    SQLite::Database db_;
    FileSystemInherentParams inherent_params_;
    FileSystemMountParams mount_params_;

    void register_custom_functions();
};
}    // namespace securefs
