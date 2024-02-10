#pragma once

#include "core/crypto_io.hpp"
#include "core/io.hpp"

#include "params.pb.h"

#include <sqlite3.h>

#include <string>

namespace securefs
{
class SqliteFileIO : public RandomIO
{
private:
    sqlite3_file* file_;

public:
    explicit SqliteFileIO(sqlite3_file* file);
    ~SqliteFileIO();
    virtual SizeType read(OffsetType offset, ByteBuffer output) override;
    virtual void write(OffsetType offset, ConstByteBuffer input) override;
    virtual SizeType size() const override;
    virtual void resize(SizeType new_size) override;
};

class EncryptedSqliteVfsRegistry
{
private:
    std::string vfs_name_;
    sqlite3_vfs vfs_;

    struct EncryptedVfsAppData
    {
        EncryptedVfsParams params;
        sqlite3_vfs* vfs = nullptr;
    };

    std::unique_ptr<EncryptedVfsAppData> data_;

    static EncryptedVfsAppData* get_data(sqlite3_vfs* vfs)
    {
        return static_cast<EncryptedVfsAppData*>(vfs->pAppData);
    }

public:
    explicit EncryptedSqliteVfsRegistry(EncryptedVfsParams params,
                                        const char* base_vfs_name = nullptr);
    ~EncryptedSqliteVfsRegistry();

    EncryptedSqliteVfsRegistry(const EncryptedSqliteVfsRegistry&) = delete;
    EncryptedSqliteVfsRegistry& operator=(const EncryptedSqliteVfsRegistry&) = delete;

    const std::string& vfs_name() const { return vfs_name_; }
};
}    // namespace securefs
