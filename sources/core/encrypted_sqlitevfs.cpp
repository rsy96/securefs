#include "core/encrypted_sqlitevfs.hpp"
#include "encrypted_sqlitevfs.hpp"

#include <SQLiteCpp/Exception.h>

#include <limits>
#include <stdexcept>

namespace securefs
{
static void check_sqlite_call(int rc)
{
    if (rc != SQLITE_OK)
    {
        throw SQLite::Exception(sqlite3_errstr(rc), rc);
    }
}
SqliteFileIO::SqliteFileIO(sqlite3_file* file) : file_(file)
{
    if (!file)
    {
        throw std::invalid_argument("Null sqlite3_file");
    }
}

SqliteFileIO::~SqliteFileIO() { file_->pMethods->xClose(file_); }
SizeType SqliteFileIO::read(OffsetType offset, ByteBuffer output)
{
    if (output.size() >= std::numeric_limits<int>::max())
    {
        throw std::out_of_range("Too large buffer");
    }
    check_sqlite_call(
        file_->pMethods->xRead(file_, output.data(), static_cast<int>(output.size()), offset));
    return output.size();
}
void SqliteFileIO::write(OffsetType offset, ConstByteBuffer input)
{
    if (input.size() >= std::numeric_limits<int>::max())
    {
        throw std::out_of_range("Too large buffer");
    }
    check_sqlite_call(
        file_->pMethods->xWrite(file_, input.data(), static_cast<int>(input.size()), offset));
}

SizeType SqliteFileIO::size() const
{
    sqlite3_int64 size;
    check_sqlite_call(file_->pMethods->xFileSize(file_, &size));
    return static_cast<SizeType>(size);
}

void SqliteFileIO::resize(SizeType new_size)
{
    check_sqlite_call(file_->pMethods->xTruncate(file_, new_size));
}

}    // namespace securefs
