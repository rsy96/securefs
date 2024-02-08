#pragma once

#include "core/io.hpp"

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

public:
    explicit EncryptedSqliteVfsRegistry(ConstByteBuffer key);
    ~EncryptedSqliteVfsRegistry();

    const std::string& vfs_name() const { return vfs_name_; }
};
}    // namespace securefs
