#pragma once

namespace securefs
{
// Base class for all classes in this project that has a vtable.
// This simplies RTTI.
class Object
{
public:
    Object() = default;
    virtual ~Object() = default;
    Object(const Object&) = delete;
    Object& operator=(const Object&) = delete;
    Object(Object&&) = delete;
    Object& operator=(Object&&) = delete;
};
}    // namespace securefs
