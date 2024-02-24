#pragma once
#ifdef _WIN32
#include "core/object.hpp"

#include <winfsp/winfsp.h>

#include <exception>

namespace securefs
{
class WinfspFileSystemBase : public Object
{
public:
    virtual NTSTATUS getVolumeInfo(FSP_FILE_SYSTEM* FileSystem, FSP_FSCTL_VOLUME_INFO* VolumeInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setVolumeLabel(FSP_FILE_SYSTEM* FileSystem,
                                    PWSTR VolumeLabel,
                                    FSP_FSCTL_VOLUME_INFO* VolumeInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                                       PWSTR FileName,
                                       PUINT32 PFileAttributes /* or ReparsePointIndex */,
                                       PSECURITY_DESCRIPTOR SecurityDescriptor,
                                       SIZE_T* PSecurityDescriptorSize)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS open(FSP_FILE_SYSTEM* FileSystem,
                          PWSTR FileName,
                          UINT32 CreateOptions,
                          UINT32 GrantedAccess,
                          PVOID* PFileContext,
                          FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS overwrite(FSP_FILE_SYSTEM* FileSystem,
                               PVOID FileContext,
                               UINT32 FileAttributes,
                               BOOLEAN ReplaceFileAttributes,
                               UINT64 AllocationSize,
                               FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS read(FSP_FILE_SYSTEM* FileSystem,
                          PVOID FileContext,
                          PVOID Buffer,
                          UINT64 Offset,
                          ULONG Length,
                          PULONG PBytesTransferred)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS write(FSP_FILE_SYSTEM* FileSystem,
                           PVOID FileContext,
                           PVOID Buffer,
                           UINT64 Offset,
                           ULONG Length,
                           BOOLEAN WriteToEndOfFile,
                           BOOLEAN ConstrainedIo,
                           PULONG PBytesTransferred,
                           FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS
    flush(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS
    getFileInfo(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setBasicInfo(FSP_FILE_SYSTEM* FileSystem,
                                  PVOID FileContext,
                                  UINT32 FileAttributes,
                                  UINT64 CreationTime,
                                  UINT64 LastAccessTime,
                                  UINT64 LastWriteTime,
                                  UINT64 ChangeTime,
                                  FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setFileSize(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 UINT64 NewSize,
                                 BOOLEAN SetAllocationSize,
                                 FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS canDelete(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS rename(FSP_FILE_SYSTEM* FileSystem,
                            PVOID FileContext,
                            PWSTR FileName,
                            PWSTR NewFileName,
                            BOOLEAN ReplaceIfExists)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getSecurity(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 PSECURITY_DESCRIPTOR SecurityDescriptor,
                                 SIZE_T* PSecurityDescriptorSize)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setSecurity(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 SECURITY_INFORMATION SecurityInformation,
                                 PSECURITY_DESCRIPTOR ModificationDescriptor)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS readDirectory(FSP_FILE_SYSTEM* FileSystem,
                                   PVOID FileContext,
                                   PWSTR Pattern,
                                   PWSTR Marker,
                                   PVOID Buffer,
                                   ULONG Length,
                                   PULONG PBytesTransferred)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS resolveReparsePoints(FSP_FILE_SYSTEM* FileSystem,
                                          PWSTR FileName,
                                          UINT32 ReparsePointIndex,
                                          BOOLEAN ResolveLastPathComponent,
                                          PIO_STATUS_BLOCK PIoStatus,
                                          PVOID Buffer,
                                          PSIZE_T PSize)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getReparsePoint(
        FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, PSIZE_T PSize)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setReparsePoint(
        FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS deleteReparsePoint(
        FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                   PVOID FileContext,
                                   PVOID Buffer,
                                   ULONG Length,
                                   PULONG PBytesTransferred)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getDirInfoByName(FSP_FILE_SYSTEM* FileSystem,
                                      PVOID FileContext,
                                      PWSTR FileName,
                                      FSP_FSCTL_DIR_INFO* DirInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS control(FSP_FILE_SYSTEM* FileSystem,
                             PVOID FileContext,
                             UINT32 ControlCode,
                             PVOID InputBuffer,
                             ULONG InputBufferLength,
                             PVOID OutputBuffer,
                             ULONG OutputBufferLength,
                             PULONG PBytesTransferred)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS
    setDelete(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, BOOLEAN DeleteFile)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS createEx(FSP_FILE_SYSTEM* FileSystem,
                              PWSTR FileName,
                              UINT32 CreateOptions,
                              UINT32 GrantedAccess,
                              UINT32 FileAttributes,
                              PSECURITY_DESCRIPTOR SecurityDescriptor,
                              UINT64 AllocationSize,
                              PVOID ExtraBuffer,
                              ULONG ExtraLength,
                              BOOLEAN ExtraBufferIsReparsePoint,
                              PVOID* PFileContext,
                              FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS getEa(FSP_FILE_SYSTEM* FileSystem,
                           PVOID FileContext,
                           PFILE_FULL_EA_INFORMATION Ea,
                           ULONG EaLength,
                           PULONG PBytesTransferred)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    virtual NTSTATUS setEa(FSP_FILE_SYSTEM* FileSystem,
                           PVOID FileContext,
                           PFILE_FULL_EA_INFORMATION Ea,
                           ULONG EaLength,
                           FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    static NTSTATUS as_nt_status(const std::exception& e) noexcept;
    const FSP_FILE_SYSTEM_INTERFACE& get_fsp_interface() noexcept;

private:
    static NTSTATUS static_GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem,
                                         FSP_FSCTL_VOLUME_INFO* VolumeInfo);
    static NTSTATUS static_SetVolumeLabel(FSP_FILE_SYSTEM* FileSystem,
                                          PWSTR VolumeLabel,
                                          FSP_FSCTL_VOLUME_INFO* VolumeInfo);
    static NTSTATUS static_GetSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                                             PWSTR FileName,
                                             PUINT32 PFileAttributes /* or ReparsePointIndex */,
                                             PSECURITY_DESCRIPTOR SecurityDescriptor,
                                             SIZE_T* PSecurityDescriptorSize);
    static NTSTATUS static_Open(FSP_FILE_SYSTEM* FileSystem,
                                PWSTR FileName,
                                UINT32 CreateOptions,
                                UINT32 GrantedAccess,
                                PVOID* PFileContext,
                                FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_Overwrite(FSP_FILE_SYSTEM* FileSystem,
                                     PVOID FileContext,
                                     UINT32 FileAttributes,
                                     BOOLEAN ReplaceFileAttributes,
                                     UINT64 AllocationSize,
                                     FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_Read(FSP_FILE_SYSTEM* FileSystem,
                                PVOID FileContext,
                                PVOID Buffer,
                                UINT64 Offset,
                                ULONG Length,
                                PULONG PBytesTransferred);
    static NTSTATUS static_Write(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 PVOID Buffer,
                                 UINT64 Offset,
                                 ULONG Length,
                                 BOOLEAN WriteToEndOfFile,
                                 BOOLEAN ConstrainedIo,
                                 PULONG PBytesTransferred,
                                 FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS
    static_Flush(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_GetFileInfo(FSP_FILE_SYSTEM* FileSystem,
                                       PVOID FileContext,
                                       FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_SetBasicInfo(FSP_FILE_SYSTEM* FileSystem,
                                        PVOID FileContext,
                                        UINT32 FileAttributes,
                                        UINT64 CreationTime,
                                        UINT64 LastAccessTime,
                                        UINT64 LastWriteTime,
                                        UINT64 ChangeTime,
                                        FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_SetFileSize(FSP_FILE_SYSTEM* FileSystem,
                                       PVOID FileContext,
                                       UINT64 NewSize,
                                       BOOLEAN SetAllocationSize,
                                       FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS
    static_CanDelete(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName);
    static NTSTATUS static_Rename(FSP_FILE_SYSTEM* FileSystem,
                                  PVOID FileContext,
                                  PWSTR FileName,
                                  PWSTR NewFileName,
                                  BOOLEAN ReplaceIfExists);
    static NTSTATUS static_GetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                       PVOID FileContext,
                                       PSECURITY_DESCRIPTOR SecurityDescriptor,
                                       SIZE_T* PSecurityDescriptorSize);
    static NTSTATUS static_SetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                       PVOID FileContext,
                                       SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR ModificationDescriptor);
    static NTSTATUS static_ReadDirectory(FSP_FILE_SYSTEM* FileSystem,
                                         PVOID FileContext,
                                         PWSTR Pattern,
                                         PWSTR Marker,
                                         PVOID Buffer,
                                         ULONG Length,
                                         PULONG PBytesTransferred);
    static NTSTATUS static_ResolveReparsePoints(FSP_FILE_SYSTEM* FileSystem,
                                                PWSTR FileName,
                                                UINT32 ReparsePointIndex,
                                                BOOLEAN ResolveLastPathComponent,
                                                PIO_STATUS_BLOCK PIoStatus,
                                                PVOID Buffer,
                                                PSIZE_T PSize);
    static NTSTATUS static_GetReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                           PVOID FileContext,
                                           PWSTR FileName,
                                           PVOID Buffer,
                                           PSIZE_T PSize);
    static NTSTATUS static_SetReparsePoint(
        FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size);
    static NTSTATUS static_DeleteReparsePoint(
        FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size);
    static NTSTATUS static_GetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                         PVOID FileContext,
                                         PVOID Buffer,
                                         ULONG Length,
                                         PULONG PBytesTransferred);
    static NTSTATUS static_GetDirInfoByName(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PWSTR FileName,
                                            FSP_FSCTL_DIR_INFO* DirInfo);
    static NTSTATUS static_Control(FSP_FILE_SYSTEM* FileSystem,
                                   PVOID FileContext,
                                   UINT32 ControlCode,
                                   PVOID InputBuffer,
                                   ULONG InputBufferLength,
                                   PVOID OutputBuffer,
                                   ULONG OutputBufferLength,
                                   PULONG PBytesTransferred);
    static NTSTATUS static_SetDelete(FSP_FILE_SYSTEM* FileSystem,
                                     PVOID FileContext,
                                     PWSTR FileName,
                                     BOOLEAN DeleteFile);
    static NTSTATUS static_CreateEx(FSP_FILE_SYSTEM* FileSystem,
                                    PWSTR FileName,
                                    UINT32 CreateOptions,
                                    UINT32 GrantedAccess,
                                    UINT32 FileAttributes,
                                    PSECURITY_DESCRIPTOR SecurityDescriptor,
                                    UINT64 AllocationSize,
                                    PVOID ExtraBuffer,
                                    ULONG ExtraLength,
                                    BOOLEAN ExtraBufferIsReparsePoint,
                                    PVOID* PFileContext,
                                    FSP_FSCTL_FILE_INFO* FileInfo);
    static NTSTATUS static_GetEa(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 PFILE_FULL_EA_INFORMATION Ea,
                                 ULONG EaLength,
                                 PULONG PBytesTransferred);
    static NTSTATUS static_SetEa(FSP_FILE_SYSTEM* FileSystem,
                                 PVOID FileContext,
                                 PFILE_FULL_EA_INFORMATION Ea,
                                 ULONG EaLength,
                                 FSP_FSCTL_FILE_INFO* FileInfo);

    struct FspInterfaceWrapper
    {
        FSP_FILE_SYSTEM_INTERFACE fsp_interface{};

        FspInterfaceWrapper() noexcept;
    };
};
}    // namespace securefs
#endif
