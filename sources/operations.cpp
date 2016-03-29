#include "operations.h"
#include "xattr_compat.h"

#include <algorithm>
#include <chrono>
#include <string.h>
#include <string>
#include <typeinfo>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

using securefs::operations::FileSystem;

namespace securefs
{
namespace internal
{
    inline FileSystem* get_fs(struct fuse_context* ctx)
    {
        return static_cast<FileSystem*>(ctx->private_data);
    }

    class GenericFileGuard
    {
    private:
        FileTable* m_ft;
        FileBase* m_fb;

    public:
        explicit GenericFileGuard(FileTable* ft, FileBase* fb) : m_ft(ft), m_fb(fb) {}

        GenericFileGuard(const GenericFileGuard&) = delete;
        GenericFileGuard& operator=(const GenericFileGuard&) = delete;

        GenericFileGuard(GenericFileGuard&& other) noexcept : m_ft(other.m_ft), m_fb(other.m_fb)
        {
            other.m_ft = nullptr;
            other.m_fb = nullptr;
        }

        GenericFileGuard& operator=(GenericFileGuard&& other) noexcept
        {
            if (this == &other)
                return *this;
            swap(other);
            return *this;
        }

        ~GenericFileGuard()
        {
            try
            {
                reset(nullptr);
            }
            catch (...)
            {
            }
        }

        FileBase* get() noexcept { return m_fb; }
        template <class T>
        T* get_as() noexcept
        {
            return static_cast<T*>(m_fb);
        }
        FileBase& operator*() noexcept { return *m_fb; }
        FileBase* operator->() noexcept { return m_fb; }
        FileBase* release() noexcept
        {
            auto rt = m_fb;
            m_fb = nullptr;
            return rt;
        }
        void reset(FileBase* fb)
        {
            if (m_ft && m_fb)
            {
                m_ft->close(m_fb);
            }
            m_fb = fb;
        }
        void swap(GenericFileGuard& other) noexcept
        {
            std::swap(m_ft, other.m_ft);
            std::swap(m_fb, other.m_fb);
        }
    };

    typedef GenericFileGuard FileGuard;

    FileGuard open_base_dir(FileSystem* fs, const std::string& path, std::string& last_component)
    {
        auto components = split(path, '/');
        FileGuard result(&fs->table, fs->table.open_as(fs->root_id, FileBase::DIRECTORY));
        if (components.empty())
        {
            last_component = std::string();
            return result;
        }
        id_type id;
        int type;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            bool exists = result.get_as<Directory>()->get_entry(components[i], id, type);
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            result.reset(fs->table.open_as(id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(FileSystem* fs, const std::string& path)
    {
        std::string last_component;
        auto fg = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return fg;
        id_type id;
        int type;
        bool exists = fg.get_as<Directory>()->get_entry(last_component, id, type);
        if (!exists)
            throw OSException(ENOENT);
        fg.reset(fs->table.open_as(id, type));
        return fg;
    }

    template <class Initializer>
    FileGuard create(FileSystem* fs, const std::string& path, int type, const Initializer& init)
    {
        std::string last_component;
        auto dir = open_base_dir(fs, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());

        FileGuard result(&fs->table, fs->table.create_as(id, type));
        init(result.get());

        try
        {
            bool success = dir.get_as<Directory>()->add_entry(last_component, id, type);
            if (!success)
                throw OSException(EEXIST);
        }
        catch (...)
        {
            result->unlink();
            throw;
        }
        return result;
    }

    void remove(FileSystem* fs, const id_type& id, int type)
    {
        try
        {
            FileGuard to_be_removed(&fs->table, fs->table.open_as(id, type));
            to_be_removed->unlink();
        }
        catch (...)
        {
            // Errors in unlinking the actual underlying file can be ignored
            // They will not affect the apparent filesystem operations
        }
    }

    void remove(FileSystem* fs, const std::string& path)
    {
        std::string last_component;
        auto dir_guard = open_base_dir(fs, path, last_component);
        auto dir = dir_guard.get_as<Directory>();
        if (last_component.empty())
            throw OSException(EPERM);
        id_type id;
        int type;
        while (true)
        {
            if (!dir->get_entry(last_component, id, type))
                throw OSException(ENOENT);

            auto&& table = fs->table;
            FileGuard inner_guard(&table, table.open_as(id, type));
            auto inner_fb = inner_guard.get();
            if (inner_fb->type() == FileBase::DIRECTORY
                && !static_cast<Directory*>(inner_fb)->empty())
                throw OSException(ENOTEMPTY);
            dir->remove_entry(last_component, id, type);
            inner_fb->unlink();
            break;
        }
    }

    inline bool is_readonly(struct fuse_context* ctx) { return get_fs(ctx)->table.is_readonly(); }

    int
    log_error(FileSystem* fs, const ExceptionBase& e, const char* func, const char* file, int line)
    {
        auto logger = fs->logger.get();
        if (logger && e.level() >= logger->get_level())
            logger->log(
                e.level(), fmt::format("{}: {}", e.type_name(), e.message()), func, file, line);
        return -e.error_number();
    }

    int log_general_error(
        FileSystem* fs, const std::exception& e, const char* func, const char* file, int line)
    {
        auto logger = fs->logger.get();
        if (logger && LoggingLevel::ERROR >= logger->get_level())
            logger->log(LoggingLevel::ERROR,
                        fmt::format("An unexcepted exception of type {} occurrs: {}",
                                    typeid(e).name(),
                                    e.what()),
                        func,
                        file,
                        line);
        return -EPERM;
    }
}

namespace operations
{

    FileSystem::FileSystem(const FSOptions& opt)
        : table(opt.dir_fd, opt.master_key, opt.flags, opt.block_size, opt.iv_size)
        , root_id()
        , logger(opt.logger)
    {
    }

    FileSystem::~FileSystem() {}

#define COMMON_CATCH_BLOCK                                                                         \
    catch (const OSException& e) { return -e.error_number(); }                                     \
    catch (const ExceptionBase& e)                                                                 \
    {                                                                                              \
        return internal::log_error(fs, e, __PRETTY_FUNCTION__, __FILE__, __LINE__);                \
    }                                                                                              \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        return internal::log_general_error(fs, e, __PRETTY_FUNCTION__, __FILE__, __LINE__);        \
    }

#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);

    void* init(struct fuse_conn_info*)
    {
        auto args = static_cast<FSOptions*>(fuse_get_context()->private_data);
        return new FileSystem(*args);
    }

    void destroy(void* data) { delete static_cast<FileSystem*>(data); }

    int getattr(const char* path, struct stat* st)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->stat(st);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        return ::securefs::operations::release(path, info);
    }

    int
    readdir(const char*, void* buffer, fuse_fill_dir_t filler, off_t, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            struct stat st;
            memset(&st, 0, sizeof(st));
            auto actions = [&](const std::string& name, const id_type&, int type) -> bool {
                st.st_mode = FileBase::mode_for_type(type);
                return filler(buffer, name.c_str(), &st, 0) == 0;
            };
            static_cast<Directory*>(fb)->iterate_over_entries(actions);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int create(const char* path, mode_t mode, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFREG;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_file = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(fs, path, FileBase::REGULAR_FILE, init_file);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        // bool rdonly = info->flags & O_RDONLY;
        bool rdwr = info->flags & O_RDWR;
        bool wronly = info->flags & O_WRONLY;
        bool append = info->flags & O_APPEND;
        // bool require_read = rdonly | rdwr;
        bool require_write = wronly | append | rdwr;

        try
        {
            if (require_write && internal::is_readonly(ctx))
                return -EROFS;
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            if (info->flags & O_TRUNC)
            {
                fg.get_as<RegularFile>()->truncate(0);
            }
            info->fh = reinterpret_cast<uintptr_t>(fg.release());
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int release(const char*, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            fb->flush();
            internal::FileGuard fg(&internal::get_fs(ctx)->table, fb);
            fg.reset(nullptr);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int read(const char*, char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            return static_cast<int>(static_cast<RegularFile*>(fb)->read(buffer, off, len));
        }
        COMMON_CATCH_BLOCK
    }

    int write(const char*, const char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            static_cast<RegularFile*>(fb)->write(buffer, off, len);
            return static_cast<int>(len);
        }
        COMMON_CATCH_BLOCK
    }

    int flush(const char*, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int truncate(const char* path, off_t size)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            fg.get_as<RegularFile>()->truncate(size);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int ftruncate(const char*, off_t size, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            static_cast<RegularFile*>(fb)->truncate(size);
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int unlink(const char* path)
    {
        COMMON_PROLOGUE
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            internal::remove(fs, path);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int mkdir(const char* path, mode_t mode)
    {
        COMMON_PROLOGUE

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFDIR;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_dir = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(fs, path, FileBase::DIRECTORY, init_dir);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int rmdir(const char* path) { return ::securefs::operations::unlink(path); }

    int chmod(const char* path, mode_t mode)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            auto original_mode = fg->get_mode();
            mode &= 0777;
            mode |= original_mode & S_IFMT;
            fg->set_mode(mode);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int chown(const char* path, uid_t uid, gid_t gid)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->set_uid(uid);
            fg->set_gid(gid);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int symlink(const char* to, const char* from)
    {
        COMMON_PROLOGUE
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_symlink = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(S_IFLNK | 0755);
                static_cast<Symlink*>(fb)->set(to);
            };
            auto fg = internal::create(fs, from, FileBase::SYMLINK, init_symlink);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        if (size == 0)
            return -EINVAL;
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            auto destination = fg.get_as<Symlink>()->get();
            memset(buf, 0, size);
            memcpy(buf, destination.data(), std::min(destination.size(), size - 1));
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int rename(const char* src, const char* dst)
    {
        COMMON_PROLOGUE
        try
        {
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;

            if (!src_dir->get_entry(src_filename, src_id, src_type))
                return -ENOENT;
            bool dst_exists = (dst_dir->get_entry(dst_filename, dst_id, dst_type));

            if (dst_exists)
            {
                if (src_id == dst_id)
                    return 0;
                if (src_type != FileBase::DIRECTORY && dst_type == FileBase::DIRECTORY)
                    return -EISDIR;
                if (src_type != dst_type)
                    return -EINVAL;
                dst_dir->remove_entry(dst_filename, dst_id, dst_type);
            }
            src_dir->remove_entry(src_filename, src_id, src_type);
            dst_dir->add_entry(dst_filename, src_id, src_type);

            if (dst_exists)
                internal::remove(fs, dst_id, dst_type);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int link(const char* src, const char* dst)
    {
        COMMON_PROLOGUE
        try
        {
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;

            bool src_exists = src_dir->get_entry(src_filename, src_id, src_type);
            if (!src_exists)
                return -ENOENT;
            bool dst_exists = dst_dir->get_entry(dst_filename, dst_id, dst_type);
            if (dst_exists)
                return -EEXIST;

            auto&& table = internal::get_fs(ctx)->table;
            internal::FileGuard guard(&table, table.open_as(src_id, src_type));

            if (guard->type() != FileBase::REGULAR_FILE)
                return -EPERM;

            guard->set_nlink(guard->get_nlink() + 1);
            dst_dir->add_entry(dst_filename, src_id, src_type);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int fsync(const char*, int, struct fuse_file_info* fi)
    {
        COMMON_PROLOGUE
        try
        {
            auto fb = reinterpret_cast<FileBase*>(fi->fh);
            if (!fb)
                return -EINVAL;
            fb->flush();
            int fd = fb->file_descriptor();
            int rc = ::fsync(fd);
            if (rc < 0)
                return -errno;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi)
    {
        return ::securefs::operations::fsync(path, isdatasync, fi);
    }

    int utimens(const char* path, const struct timespec ts[2])
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            int rc = 0;
            int fd = fg->file_descriptor();

#if _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L
            rc = ::futimens(fd, ts);
#else
            if (!ts)
                rc = ::futimes(fd, nullptr);
            else
            {
                struct timeval time_values[2];
                for (size_t i = 0; i < 2; ++i)
                {
                    time_values[i].tv_sec = ts[i].tv_sec;
                    time_values[i].tv_usec
                        = static_cast<decltype(time_values[i].tv_usec)>(ts[i].tv_nsec / 1000);
                }
                rc = ::futimes(fd, time_values);
            }
#endif
            if (rc < 0)
                return -errno;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int listxattr(const char* path, char* list, size_t size)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->listxattr(list, size));
        }
        COMMON_CATCH_BLOCK
    }

#ifdef __APPLE__
    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        if (position != 0)
            return -EINVAL;
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->getxattr(name, value, size));
        }
        COMMON_CATCH_BLOCK
    }

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position)
    {
        if (position != 0)
            return -EINVAL;
        if (strcmp(name, "com.apple.quarantine") == 0)
            return 0;    // workaround for the "XXX is damaged" bug on OS X
        if (strcmp(name, "com.apple.FinderInfo") == 0)
            return -EACCES;    // FinderInfo cannot be encrypted, because its format and length is
                               // artificially restricted

        COMMON_PROLOGUE
        flags &= XATTR_CREATE | XATTR_REPLACE;
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->setxattr(name, value, size, flags);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

#else
    int getxattr(const char* path, const char* name, char* value, size_t size)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->getxattr(name, value, size));
        }
        COMMON_CATCH_BLOCK
    }

    int setxattr(const char* path, const char* name, const char* value, size_t size, int flags)
    {
        COMMON_PROLOGUE
        flags &= XATTR_CREATE | XATTR_REPLACE;
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->setxattr(name, value, size, flags);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }
#endif

    int removexattr(const char* path, const char* name)
    {
        COMMON_PROLOGUE
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->removexattr(name);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }
}
}