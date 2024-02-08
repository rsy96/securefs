#include "core/crypto_io.hpp"
#include "core/encrypted_sqlitevfs.hpp"
#include "core/utilities.hpp"

#include <SQLiteCpp/Exception.h>

#include <limits>
#include <memory>
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
    if (output.empty())
    {
        return 0;
    }
    if (output.size() >= std::numeric_limits<int>::max())
    {
        throw std::out_of_range("Too large buffer");
    }
    auto current_size = size();
    if (offset >= current_size)
    {
        return 0;
    }
    if (offset + output.size() > current_size)
    {
        output = output.subspan(0, current_size - offset);
    }
    check_sqlite_call(
        file_->pMethods->xRead(file_, output.data(), static_cast<int>(output.size()), offset));
    return output.size();
}
void SqliteFileIO::write(OffsetType offset, ConstByteBuffer input)
{
    if (input.empty())
    {
        return;
    }
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

class EncryptedSqliteFile : public sqlite3_file
{
private:
    C_unique_ptr<sqlite3_file> delegate_;
    std::unique_ptr<AesGcmRandomIO> io_;

public:
    explicit EncryptedSqliteFile()
    {
        static const EncryptedSqliteFilePMethods methods_holder;
        pMethods = &methods_holder.methods;
    }
    ~EncryptedSqliteFile() {}
    EncryptedSqliteFile(const EncryptedSqliteFile&) = delete;
    EncryptedSqliteFile& operator=(const EncryptedSqliteFile&) = delete;

    int xClose()
    {
        io_.reset(nullptr);
        delegate_.reset(nullptr);
        return 0;
    }

    int xRead(void* buffer, int amount, sqlite3_int64 offset)
    {
        if (amount < 0 || !io_)
        {
            return SQLITE_MISUSE;
        }
        memset(buffer, 0, amount);
        auto rc = io_->read(offset, ByteBuffer(static_cast<unsigned char*>(buffer), amount));
        if (rc < amount)
        {
            return SQLITE_IOERR_SHORT_READ;
        }
        return SQLITE_OK;
    }

private:
    struct EncryptedSqliteFilePMethods
    {
        sqlite3_io_methods methods;

        EncryptedSqliteFilePMethods()
        {
            methods.xClose = [](sqlite3_file* p)
            {
                try
                {
                    return static_cast<EncryptedSqliteFile*>(p)->xClose();
                }
                catch (const std::exception& e)
                {
                    return SQLITE_IOERR;
                }
            };
        }
    };
};

// struct sqlite3_io_methods {
//   int iVersion;
//   int (*xClose)(sqlite3_file*);
//   int (*xRead)(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
//   int (*xWrite)(sqlite3_file*, const void*, int iAmt, sqlite3_int64 iOfst);
//   int (*xTruncate)(sqlite3_file*, sqlite3_int64 size);
//   int (*xSync)(sqlite3_file*, int flags);
//   int (*xFileSize)(sqlite3_file*, sqlite3_int64 *pSize);
//   int (*xLock)(sqlite3_file*, int);
//   int (*xUnlock)(sqlite3_file*, int);
//   int (*xCheckReservedLock)(sqlite3_file*, int *pResOut);
//   int (*xFileControl)(sqlite3_file*, int op, void *pArg);
//   int (*xSectorSize)(sqlite3_file*);
//   int (*xDeviceCharacteristics)(sqlite3_file*);
//   /* Methods above are valid for version 1 */
//   int (*xShmMap)(sqlite3_file*, int iPg, int pgsz, int, void volatile**);
//   int (*xShmLock)(sqlite3_file*, int offset, int n, int flags);
//   void (*xShmBarrier)(sqlite3_file*);
//   int (*xShmUnmap)(sqlite3_file*, int deleteFlag);
//   /* Methods above are valid for version 2 */
//   int (*xFetch)(sqlite3_file*, sqlite3_int64 iOfst, int iAmt, void **pp);
//   int (*xUnfetch)(sqlite3_file*, sqlite3_int64 iOfst, void *p);
//   /* Methods above are valid for version 3 */
//   /* Additional methods may be added in future releases */
// };

}    // namespace securefs
