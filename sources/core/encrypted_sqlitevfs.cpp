#include "encrypted_sqlitevfs.hpp"
#include "crypto_io.hpp"
#include "rng.hpp"
#include "sqlitehelper.hpp"
#include "utilities.hpp"

#include <absl/strings/str_format.h>

#include <limits>
#include <memory>
#include <stdexcept>

namespace securefs
{
SqliteFileIO::SqliteFileIO(sqlite3_file* file) : file_(file)
{
    if (!file)
    {
        throw SQLiteException(SQLITE_MISUSE);
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

    // We separate the implementation in a separate class to ensure that `EncryptedSqliteFile` is a
    // PoD so that it can interface with C-methods of sqlite3 safely.
    class EncryptedSqliteFileImpl
    {
    private:
        C_unique_ptr<sqlite3_file> delegate_;
        std::unique_ptr<AesGcmRandomIO> io_;
        bool read_only_;

    public:
        explicit EncryptedSqliteFileImpl(C_unique_ptr<sqlite3_file> delegate,
                                         EncryptedVfsParams params)
            : delegate_(std::move(delegate)), read_only_(params.read_only())
        {
            io_ = std::make_unique<AesGcmRandomIO>(std::make_shared<SqliteFileIO>(delegate_.get()),
                                                   std::move(*params.mutable_encryption_params()));
        }
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

        int xDeviceCharacteristics() noexcept
        {
            int flags =
#ifdef _WIN32
                SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
#else
                0
#endif
                ;
            if (read_only_)
            {
                flags |= SQLITE_IOCAP_IMMUTABLE;
            }
            return flags;
        }

    private:
    };

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

            io_methods.xDeviceCharacteristics = [](sqlite3_file* f)
            {
                return safe_sqlite_call(
                    [=]()
                    {
                        auto impl = static_cast<EncryptedSqliteFile*>(f)->impl;
                        if (!impl)
                        {
                            return SQLITE_MISUSE;
                        }
                        return impl->xDeviceCharacteristics();
                    });
            };
        }
    };

    // struct sqlite3_vfs {
    //   int iVersion;            /* Structure version number (currently 3) */
    //   int szOsFile;            /* Size of subclassed sqlite3_file */
    //   int mxPathname;          /* Maximum file pathname length */
    //   sqlite3_vfs *pNext;      /* Next registered VFS */
    //   const char *zName;       /* Name of this virtual file system */
    //   void *pAppData;          /* Pointer to application-specific data */
    //   int (*xOpen)(sqlite3_vfs*, sqlite3_filename zName, sqlite3_file*,
    //                int flags, int *pOutFlags);
    //   int (*xDelete)(sqlite3_vfs*, const char *zName, int syncDir);
    //   int (*xAccess)(sqlite3_vfs*, const char *zName, int flags, int *pResOut);
    //   int (*xFullPathname)(sqlite3_vfs*, const char *zName, int nOut, char *zOut);
    //   void *(*xDlOpen)(sqlite3_vfs*, const char *zFilename);
    //   void (*xDlError)(sqlite3_vfs*, int nByte, char *zErrMsg);
    //   void (*(*xDlSym)(sqlite3_vfs*,void*, const char *zSymbol))(void);
    //   void (*xDlClose)(sqlite3_vfs*, void*);
    //   int (*xRandomness)(sqlite3_vfs*, int nByte, char *zOut);
    //   int (*xSleep)(sqlite3_vfs*, int microseconds);
    //   int (*xCurrentTime)(sqlite3_vfs*, double*);
    //   int (*xGetLastError)(sqlite3_vfs*, int, char *);
    //   /*
    //   ** The methods above are in version 1 of the sqlite_vfs object
    //   ** definition.  Those that follow are added in version 2 or later
    //   */
    //   int (*xCurrentTimeInt64)(sqlite3_vfs*, sqlite3_int64*);
    //   /*
    //   ** The methods above are in versions 1 and 2 of the sqlite_vfs object.
    //   ** Those below are for version 3 and greater.
    //   */
    //   int (*xSetSystemCall)(sqlite3_vfs*, const char *zName, sqlite3_syscall_ptr);
    //   sqlite3_syscall_ptr (*xGetSystemCall)(sqlite3_vfs*, const char *zName);
    //   const char *(*xNextSystemCall)(sqlite3_vfs*, const char *zName);
    //   /*
    //   ** The methods above are in versions 1 through 3 of the sqlite_vfs object.
    //   ** New fields may be appended in future versions.  The iVersion
    //   ** value will increment whenever this happens.
    //   */
    // };
}    // namespace

EncryptedSqliteVfsRegistry::EncryptedSqliteVfsRegistry(EncryptedVfsParams params,
                                                       const char* base_vfs_name)
{
    vfs_name_ = "securefs-" + random_hex_string(8);

    data_.reset(new EncryptedVfsAppData());
    data_->vfs = sqlite3_vfs_find(base_vfs_name);
    data_->params = std::move(params);
    if (!data_->vfs)
    {
        throw std::invalid_argument(
            absl::StrFormat("No registered sqlite3 vfs with name %s", base_vfs_name));
    }

    memset(&vfs_, 0, sizeof(vfs_));
    vfs_.iVersion = 2;
    vfs_.pAppData = data_.get();
    vfs_.mxPathname = data_->vfs->mxPathname;
    vfs_.szOsFile = sizeof(EncryptedSqliteFile);
    vfs_.zName = vfs_name_.c_str();
    vfs_.xOpen = [](sqlite3_vfs* vfs,
                    sqlite3_filename zName,
                    sqlite3_file* outfile,
                    int flags,
                    int* pOutFlags)
    {
        return safe_sqlite_call(
            [=]()
            {
                memset(outfile, 0, sizeof(EncryptedSqliteFile));
                static const EncryptedSqliteFileMethods file_methods;
                outfile->pMethods = &file_methods.io_methods;

                auto data = get_data(vfs);
                C_unique_ptr<sqlite3_file> underlying_sqlite_file(
                    static_cast<sqlite3_file*>(malloc(data->vfs->szOsFile)));
                if (!underlying_sqlite_file)
                {
                    return SQLITE_NOMEM;
                }
                int rc = data->vfs->xOpen(
                    data->vfs, zName, underlying_sqlite_file.get(), flags, pOutFlags);
                if (rc != SQLITE_OK)
                {
                    return rc;
                }
                static_cast<EncryptedSqliteFile*>(outfile)->impl
                    = new EncryptedSqliteFileImpl(std::move(underlying_sqlite_file), data->params);
                return SQLITE_OK;
            });
    };

    vfs_.xRandomness = [](sqlite3_vfs*, int nByte, char* zOut)
    {
        if (nByte < 0)
        {
            return SQLITE_MISUSE;
        }
        generate_random(zOut, static_cast<size_t>(nByte));
        return SQLITE_OK;
    };

    vfs_.xDelete = [](sqlite3_vfs* vfs, const char* zName, int syncDir)
    {
        auto data = get_data(vfs);
        return data->vfs->xDelete(data->vfs, zName, syncDir);
    };

    vfs_.xAccess = [](sqlite3_vfs* vfs, const char* zName, int flags, int* pResOut)
    {
        auto data = get_data(vfs);
        return data->vfs->xAccess(data->vfs, zName, flags, pResOut);
    };

    vfs_.xFullPathname = [](sqlite3_vfs* vfs, const char* zName, int nOut, char* zOut)
    {
        auto data = get_data(vfs);
        return data->vfs->xFullPathname(data->vfs, zName, nOut, zOut);
    };

    vfs_.xDlOpen = [](sqlite3_vfs* vfs, const char* zFilename)
    {
        auto data = get_data(vfs);
        return data->vfs->xDlOpen(data->vfs, zFilename);
    };

    vfs_.xDlError = [](sqlite3_vfs* vfs, int nByte, char* zErrMsg)
    {
        auto data = get_data(vfs);
        return data->vfs->xDlError(data->vfs, nByte, zErrMsg);
    };

    vfs_.xDlClose = [](sqlite3_vfs* vfs, void* handle)
    {
        auto data = get_data(vfs);
        return data->vfs->xDlClose(data->vfs, handle);
    };

    vfs_.xDlSym = [](sqlite3_vfs* vfs, void* handle, const char* zSymbol)
    {
        auto data = get_data(vfs);
        return data->vfs->xDlSym(data->vfs, handle, zSymbol);
    };

    vfs_.xSleep = [](sqlite3_vfs* vfs, int microseconds)
    {
        auto data = get_data(vfs);
        return data->vfs->xSleep(data->vfs, microseconds);
    };

    vfs_.xCurrentTime = [](sqlite3_vfs* vfs, double* outTime)
    {
        auto data = get_data(vfs);
        return data->vfs->xCurrentTime(data->vfs, outTime);
    };

    vfs_.xCurrentTimeInt64 = [](sqlite3_vfs* vfs, sqlite3_int64* outTime)
    {
        auto data = get_data(vfs);
        return data->vfs->xCurrentTimeInt64(data->vfs, outTime);
    };

    check_sqlite_call(sqlite3_vfs_register(&vfs_, 0));
}

EncryptedSqliteVfsRegistry::~EncryptedSqliteVfsRegistry() { sqlite3_vfs_unregister(&vfs_); }

}    // namespace securefs
