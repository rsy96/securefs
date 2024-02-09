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

namespace
{

    struct SqliteFileCleanup
    {
        void operator()(sqlite3_file* file)
        {
            if (!file)
            {
                return;
            }
            file->pMethods->xClose(file);
            free(file);
        }
    };

    // We separate the implementation in a separate class to ensure that `EncryptedSqliteFile` is a
    // PoD so that it can interface with C-methods of sqlite3 safely.
    class EncryptedSqliteFileImpl
    {
    private:
        std::unique_ptr<sqlite3_file, SqliteFileCleanup> delegate_;
        std::unique_ptr<AesGcmRandomIO> io_;

    public:
        explicit EncryptedSqliteFileImpl() {}
        ~EncryptedSqliteFileImpl() {}

        int xRead(void* buffer, int iAmt, sqlite3_int64 iOfst)
        {
            if (iAmt < 0 || iOfst < 0)
            {
                return SQLITE_MISUSE;
            }
            memset(buffer, 0, iAmt);
            auto rc = io_->read(iOfst, ByteBuffer(static_cast<unsigned char*>(buffer), iAmt));
            if (rc < iAmt)
            {
                return SQLITE_IOERR_SHORT_READ;
            }
            return SQLITE_OK;
        }

        int xWrite(const void* buffer, int iAmt, sqlite3_int64 iOfst)
        {
            if (iAmt < 0 || iOfst < 0)
            {
                return SQLITE_MISUSE;
            }
            io_->write(iOfst, ConstByteBuffer(static_cast<const unsigned char*>(buffer), iAmt));
            return SQLITE_OK;
        }

        int xTruncate(sqlite3_int64 size)
        {
            if (size < 0)
            {
                return SQLITE_MISUSE;
            }
            io_->resize(size);
            return SQLITE_OK;
        }

        int xFileSize(sqlite3_int64* pSize)
        {
            *pSize = io_->size();
            return SQLITE_OK;
        }

        int xLock(int flags) noexcept { return delegate_->pMethods->xLock(delegate_.get(), flags); }

        int xUnlock(int flags) noexcept
        {
            return delegate_->pMethods->xUnlock(delegate_.get(), flags);
        }

        int xSync(int flags) noexcept { return delegate_->pMethods->xSync(delegate_.get(), flags); }

        int xCheckReservedLock(int* pResOut) noexcept
        {
            return delegate_->pMethods->xCheckReservedLock(delegate_.get(), pResOut);
        }

        int xFileControl(int op, void* pArg) noexcept
        {
            switch (op)
            {
            case SQLITE_FCNTL_LOCKSTATE:
            case SQLITE_FCNTL_TEMPFILENAME:
                return delegate_->pMethods->xFileControl(delegate_.get(), op, pArg);
            case SQLITE_FCNTL_SIZE_HINT:
            {
                sqlite3_int64 newSz = *(sqlite3_int64*)pArg;
                newSz = (newSz + io_->virtual_block_size() - 1) / io_->virtual_block_size()
                    * io_->underlying_block_size();
                return delegate_->pMethods->xFileControl(delegate_.get(), op, &newSz);
            }
            default:
                break;
            }
            return SQLITE_NOTFOUND;
        }

        int xSectorSize() noexcept { return static_cast<int>(io_->virtual_block_size()); }

        int xDeviceCharacteristics() noexcept { return 0; }

    private:
    };

    struct EncryptedSqliteFile : public sqlite3_file
    {
        EncryptedSqliteFileImpl* impl;
    };

    struct EncryptedSqliteFileMethods
    {
        sqlite3_io_methods io_methods;

        EncryptedSqliteFileMethods()
        {
            memset(&io_methods, 0, sizeof(io_methods));
            io_methods.iVersion = 1;

            io_methods.xClose = [](sqlite3_file* f)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto ef = static_cast<EncryptedSqliteFile*>(f);
                        delete ef->impl;
                        ef->impl = nullptr;
                        return SQLITE_OK;
                    });
            };
            io_methods.xRead = [](sqlite3_file* f, void* buffer, int iAmt, sqlite3_int64 iOfst)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xRead(buffer, iAmt, iOfst);
                    });
            };

            io_methods.xWrite
                = [](sqlite3_file* f, const void* buffer, int iAmt, sqlite3_int64 iOfst)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xWrite(buffer, iAmt, iOfst);
                    });
            };

            io_methods.xTruncate = [](sqlite3_file* f, sqlite3_int64 size)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xTruncate(size);
                    });
            };

            io_methods.xFileSize = [](sqlite3_file* f, sqlite3_int64* pSize)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xFileSize(pSize);
                    });
            };

            io_methods.xLock = [](sqlite3_file* f, int flags)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xLock(flags);
                    });
            };

            io_methods.xUnlock = [](sqlite3_file* f, int flags)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xUnlock(flags);
                    });
            };

            io_methods.xSync = [](sqlite3_file* f, int flags)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xSync(flags);
                    });
            };

            io_methods.xCheckReservedLock = [](sqlite3_file* f, int* pResOut)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xCheckReservedLock(pResOut);
                    });
            };

            io_methods.xFileControl = [](sqlite3_file* f, int op, void* pArg)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xFileControl(op, pArg);
                    });
            };
        }

        template <class Callable>
        static int safe_sqlite_call(Callable&& callable)
        {
            try
            {
                return callable();
            }
            catch (const std::exception& e)
            {
                // TODO: add debug logging.
                return SQLITE_IOERR;
            }
        }
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

}    // namespace

}    // namespace securefs
