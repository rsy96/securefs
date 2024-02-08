#pragma once

#include "core/io.hpp"

#include <sqlite3.h>

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
}    // namespace securefs
