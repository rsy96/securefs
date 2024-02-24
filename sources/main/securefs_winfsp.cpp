#ifdef _WIN32

#include "securefs_winfsp.hpp"
#include "core/exceptions.hpp"

#include <fuse3/fuse_common.h>

namespace securefs
{
NTSTATUS WinfspFileSystemBase::as_nt_status(const std::exception& e) noexcept
{
    if (auto p = dynamic_cast<const NtException*>(&e))
    {
        return p->code();
    }
    if (auto p = dynamic_cast<const WindowsException*>(&e))
    {
        return FspNtStatusFromWin32(p->code());
    }
    if (auto p = dynamic_cast<const PosixException*>(&e))
    {
        static struct fsp_fuse_env kFspFuseEnv FSP_FUSE_ENV_INIT;
        return fsp_fuse_ntstatus_from_errno(&kFspFuseEnv, p->code());
    }
    if (auto p = dynamic_cast<const std::invalid_argument*>(&e))
    {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_INTERNAL_ERROR;
}

const FSP_FILE_SYSTEM_INTERFACE& WinfspFileSystemBase::get_fsp_interface() noexcept
{
    static const FspInterfaceWrapper kWrapper;
    return kWrapper.fsp_interface;
}

WinfspFileSystemBase::FspInterfaceWrapper::FspInterfaceWrapper() noexcept
{
    fsp_interface.GetVolumeInfo = &WinfspFileSystemBase::static_GetVolumeInfo;
    fsp_interface.SetVolumeLabel = &WinfspFileSystemBase::static_SetVolumeLabel;
    fsp_interface.GetSecurityByName = &WinfspFileSystemBase::static_GetSecurityByName;
    fsp_interface.Open = &WinfspFileSystemBase::static_Open;
    fsp_interface.Overwrite = &WinfspFileSystemBase::static_Overwrite;
    fsp_interface.Read = &WinfspFileSystemBase::static_Read;
    fsp_interface.Write = &WinfspFileSystemBase::static_Write;
    fsp_interface.Flush = &WinfspFileSystemBase::static_Flush;
    fsp_interface.GetFileInfo = &WinfspFileSystemBase::static_GetFileInfo;
    fsp_interface.SetBasicInfo = &WinfspFileSystemBase::static_SetBasicInfo;
    fsp_interface.SetFileSize = &WinfspFileSystemBase::static_SetFileSize;
    fsp_interface.CanDelete = &WinfspFileSystemBase::static_CanDelete;
    fsp_interface.Rename = &WinfspFileSystemBase::static_Rename;
    fsp_interface.GetSecurity = &WinfspFileSystemBase::static_GetSecurity;
    fsp_interface.SetSecurity = &WinfspFileSystemBase::static_SetSecurity;
    fsp_interface.ReadDirectory = &WinfspFileSystemBase::static_ReadDirectory;
    fsp_interface.ResolveReparsePoints = &WinfspFileSystemBase::static_ResolveReparsePoints;
    fsp_interface.GetReparsePoint = &WinfspFileSystemBase::static_GetReparsePoint;
    fsp_interface.SetReparsePoint = &WinfspFileSystemBase::static_SetReparsePoint;
    fsp_interface.DeleteReparsePoint = &WinfspFileSystemBase::static_DeleteReparsePoint;
    fsp_interface.GetStreamInfo = &WinfspFileSystemBase::static_GetStreamInfo;
    fsp_interface.GetDirInfoByName = &WinfspFileSystemBase::static_GetDirInfoByName;
    fsp_interface.Control = &WinfspFileSystemBase::static_Control;
    fsp_interface.SetDelete = &WinfspFileSystemBase::static_SetDelete;
    fsp_interface.CreateEx = &WinfspFileSystemBase::static_CreateEx;
    fsp_interface.GetEa = &WinfspFileSystemBase::static_GetEa;
    fsp_interface.SetEa = &WinfspFileSystemBase::static_SetEa;
}

NTSTATUS WinfspFileSystemBase::static_GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem,
                                                    FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getVolumeInfo(FileSystem, VolumeInfo);
}

NTSTATUS WinfspFileSystemBase::static_SetVolumeLabel(FSP_FILE_SYSTEM* FileSystem,
                                                     PWSTR VolumeLabel,
                                                     FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setVolumeLabel(FileSystem, VolumeLabel, VolumeInfo);
}

NTSTATUS
WinfspFileSystemBase::static_GetSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                                               PWSTR FileName,
                                               PUINT32 PFileAttributes /* or ReparsePointIndex */,
                                               PSECURITY_DESCRIPTOR SecurityDescriptor,
                                               SIZE_T* PSecurityDescriptorSize)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getSecurityByName(
            FileSystem, FileName, PFileAttributes, SecurityDescriptor, PSecurityDescriptorSize);
}

NTSTATUS WinfspFileSystemBase::static_Open(FSP_FILE_SYSTEM* FileSystem,
                                           PWSTR FileName,
                                           UINT32 CreateOptions,
                                           UINT32 GrantedAccess,
                                           PVOID* PFileContext,
                                           FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->open(FileSystem, FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_Overwrite(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                UINT32 FileAttributes,
                                                BOOLEAN ReplaceFileAttributes,
                                                UINT64 AllocationSize,
                                                FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->overwrite(FileSystem,
                    FileContext,
                    FileAttributes,
                    ReplaceFileAttributes,
                    AllocationSize,
                    FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_Read(FSP_FILE_SYSTEM* FileSystem,
                                           PVOID FileContext,
                                           PVOID Buffer,
                                           UINT64 Offset,
                                           ULONG Length,
                                           PULONG PBytesTransferred)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->read(FileSystem, FileContext, Buffer, Offset, Length, PBytesTransferred);
}

NTSTATUS WinfspFileSystemBase::static_Write(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PVOID Buffer,
                                            UINT64 Offset,
                                            ULONG Length,
                                            BOOLEAN WriteToEndOfFile,
                                            BOOLEAN ConstrainedIo,
                                            PULONG PBytesTransferred,
                                            FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->write(FileSystem,
                FileContext,
                Buffer,
                Offset,
                Length,
                WriteToEndOfFile,
                ConstrainedIo,
                PBytesTransferred,
                FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_Flush(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->flush(FileSystem, FileContext, FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_GetFileInfo(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getFileInfo(FileSystem, FileContext, FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_SetBasicInfo(FSP_FILE_SYSTEM* FileSystem,
                                                   PVOID FileContext,
                                                   UINT32 FileAttributes,
                                                   UINT64 CreationTime,
                                                   UINT64 LastAccessTime,
                                                   UINT64 LastWriteTime,
                                                   UINT64 ChangeTime,
                                                   FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setBasicInfo(FileSystem,
                       FileContext,
                       FileAttributes,
                       CreationTime,
                       LastAccessTime,
                       LastWriteTime,
                       ChangeTime,
                       FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_SetFileSize(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  UINT64 NewSize,
                                                  BOOLEAN SetAllocationSize,
                                                  FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setFileSize(FileSystem, FileContext, NewSize, SetAllocationSize, FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_CanDelete(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PWSTR FileName)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->canDelete(FileSystem, FileContext, FileName);
}

NTSTATUS WinfspFileSystemBase::static_Rename(FSP_FILE_SYSTEM* FileSystem,
                                             PVOID FileContext,
                                             PWSTR FileName,
                                             PWSTR NewFileName,
                                             BOOLEAN ReplaceIfExists)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->rename(FileSystem, FileContext, FileName, NewFileName, ReplaceIfExists);
}

NTSTATUS WinfspFileSystemBase::static_GetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                  SIZE_T* PSecurityDescriptorSize)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getSecurity(FileSystem, FileContext, SecurityDescriptor, PSecurityDescriptorSize);
}

NTSTATUS WinfspFileSystemBase::static_SetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  SECURITY_INFORMATION SecurityInformation,
                                                  PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setSecurity(FileSystem, FileContext, SecurityInformation, ModificationDescriptor);
}

NTSTATUS WinfspFileSystemBase::static_ReadDirectory(FSP_FILE_SYSTEM* FileSystem,
                                                    PVOID FileContext,
                                                    PWSTR Pattern,
                                                    PWSTR Marker,
                                                    PVOID Buffer,
                                                    ULONG Length,
                                                    PULONG PBytesTransferred)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->readDirectory(
            FileSystem, FileContext, Pattern, Marker, Buffer, Length, PBytesTransferred);
}

NTSTATUS WinfspFileSystemBase::static_ResolveReparsePoints(FSP_FILE_SYSTEM* FileSystem,
                                                           PWSTR FileName,
                                                           UINT32 ReparsePointIndex,
                                                           BOOLEAN ResolveLastPathComponent,
                                                           PIO_STATUS_BLOCK PIoStatus,
                                                           PVOID Buffer,
                                                           PSIZE_T PSize)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->resolveReparsePoints(FileSystem,
                               FileName,
                               ReparsePointIndex,
                               ResolveLastPathComponent,
                               PIoStatus,
                               Buffer,
                               PSize);
}

NTSTATUS WinfspFileSystemBase::static_GetReparsePoint(
    FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, PSIZE_T PSize)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getReparsePoint(FileSystem, FileContext, FileName, Buffer, PSize);
}

NTSTATUS WinfspFileSystemBase::static_SetReparsePoint(
    FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setReparsePoint(FileSystem, FileContext, FileName, Buffer, Size);
}

NTSTATUS WinfspFileSystemBase::static_DeleteReparsePoint(
    FSP_FILE_SYSTEM* FileSystem, PVOID FileContext, PWSTR FileName, PVOID Buffer, SIZE_T Size)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->deleteReparsePoint(FileSystem, FileContext, FileName, Buffer, Size);
}

NTSTATUS WinfspFileSystemBase::static_GetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                                    PVOID FileContext,
                                                    PVOID Buffer,
                                                    ULONG Length,
                                                    PULONG PBytesTransferred)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getStreamInfo(FileSystem, FileContext, Buffer, Length, PBytesTransferred);
}

NTSTATUS WinfspFileSystemBase::static_GetDirInfoByName(FSP_FILE_SYSTEM* FileSystem,
                                                       PVOID FileContext,
                                                       PWSTR FileName,
                                                       FSP_FSCTL_DIR_INFO* DirInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getDirInfoByName(FileSystem, FileContext, FileName, DirInfo);
}

NTSTATUS WinfspFileSystemBase::static_Control(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              UINT32 ControlCode,
                                              PVOID InputBuffer,
                                              ULONG InputBufferLength,
                                              PVOID OutputBuffer,
                                              ULONG OutputBufferLength,
                                              PULONG PBytesTransferred)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->control(FileSystem,
                  FileContext,
                  ControlCode,
                  InputBuffer,
                  InputBufferLength,
                  OutputBuffer,
                  OutputBufferLength,
                  PBytesTransferred);
}

NTSTATUS WinfspFileSystemBase::static_SetDelete(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PWSTR FileName,
                                                BOOLEAN DeleteFile)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setDelete(FileSystem, FileContext, FileName, DeleteFile);
}

NTSTATUS WinfspFileSystemBase::static_CreateEx(FSP_FILE_SYSTEM* FileSystem,
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
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->createEx(FileSystem,
                   FileName,
                   CreateOptions,
                   GrantedAccess,
                   FileAttributes,
                   SecurityDescriptor,
                   AllocationSize,
                   ExtraBuffer,
                   ExtraLength,
                   ExtraBufferIsReparsePoint,
                   PFileContext,
                   FileInfo);
}

NTSTATUS WinfspFileSystemBase::static_GetEa(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PFILE_FULL_EA_INFORMATION Ea,
                                            ULONG EaLength,
                                            PULONG PBytesTransferred)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->getEa(FileSystem, FileContext, Ea, EaLength, PBytesTransferred);
}

NTSTATUS WinfspFileSystemBase::static_SetEa(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PFILE_FULL_EA_INFORMATION Ea,
                                            ULONG EaLength,
                                            FSP_FSCTL_FILE_INFO* FileInfo)
{
    return static_cast<WinfspFileSystemBase*>(FileSystem->UserContext)
        ->setEa(FileSystem, FileContext, Ea, EaLength, FileInfo);
}

}    // namespace securefs
#endif
