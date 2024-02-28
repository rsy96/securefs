#include "di.h"

namespace securefs
{
#define DECLARE_TAG(name) const name##_t name;

DECLARE_TAG(tBlockSize)
DECLARE_TAG(tIvSize)
DECLARE_TAG(tNameMaterKey)
DECLARE_TAG(tContentMasterKey)
DECLARE_TAG(tPaddingMasterKey)
DECLARE_TAG(tVerifyFileIntegrity)
DECLARE_TAG(tMaxPaddingSize)

#undef DECLARE_TAG
}    // namespace securefs
