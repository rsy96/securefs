#pragma once

#include <boost/di.hpp>

namespace securefs
{
namespace di = boost::di;

#define DECLARE_TAG(name)                                                                          \
    struct name##_t                                                                                \
    {                                                                                              \
    };                                                                                             \
    extern const name##_t name;

DECLARE_TAG(tBlockSize)
DECLARE_TAG(tIvSize)
DECLARE_TAG(tNameMaterKey)
DECLARE_TAG(tContentMasterKey)
DECLARE_TAG(tPaddingMasterKey)
DECLARE_TAG(tVerifyFileIntegrity)
DECLARE_TAG(tMaxPaddingSize)

#undef DECLARE_TAG
}    // namespace securefs
