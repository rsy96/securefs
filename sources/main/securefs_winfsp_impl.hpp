#pragma once
#include "securefs_winfsp.hpp"

#include "core/crypto_io.hpp"
#include "core/encrypted_sqlitevfs.hpp"
#include "core/sys_io.hpp"
#include "core/tree_db.hpp"
#include "core/utilities.hpp"

#include "protos/params.pb.h"

#include <optional>
#include <string>

namespace securefs
{
class WinfspFileSystemImpl : public WinfspFileSystemBase
{

private:
    const SecureFSParams fs_params_;
    const MasterKeys master_keys_;
    const std::string repo_;
    OwnedNativeHandle repo_handle_;
    const EncryptedSqliteVfsRegistry vfs_reg_;
    SynchronizedInPlace<TreeDB> tree_;
};
}    // namespace securefs
