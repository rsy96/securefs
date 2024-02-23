#include "cmdline.hpp"
#include "core/exceptions.hpp"

#include "protos/cmdline.pb.h"

#include <absl/strings/escaping.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_replace.h>
#include <boost/numeric/conversion/cast.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

// The Windows.h is so messy
#ifdef _WIN32
#undef GetMessage
#endif

namespace securefs
{
static std::string prepend_dash(std::string_view arg_name)
{
    if (arg_name.empty())
    {
        return {};
    }
    if (arg_name.size() > 1)
    {
        return absl::StrCat("--", arg_name);
    }
    return absl::StrCat("-", arg_name);
}

static void
set_field(google::protobuf::Message* msg, const google::protobuf::FieldDescriptor* f, int32_t v)
{
    VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_INT32);
    msg->GetReflection()->SetInt32(msg, f, v);
}

static void
set_field(google::protobuf::Message* msg, const google::protobuf::FieldDescriptor* f, int64_t v)
{
    VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_INT64);
    msg->GetReflection()->SetInt64(msg, f, v);
}

static void
set_field(google::protobuf::Message* msg, const google::protobuf::FieldDescriptor* f, uint32_t v)
{
    VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_UINT32);
    msg->GetReflection()->SetUInt32(msg, f, v);
}

static void
set_field(google::protobuf::Message* msg, const google::protobuf::FieldDescriptor* f, uint64_t v)
{
    VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_UINT64);
    msg->GetReflection()->SetUInt64(msg, f, v);
}

static void
set_field(google::protobuf::Message* msg, const google::protobuf::FieldDescriptor* f, std::string v)
{
    VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_STRING);
    msg->GetReflection()->SetString(msg, f, std::move(v));
}

template <typename T>
static T get_field(const google::protobuf::Message& msg, const google::protobuf::FieldDescriptor* f)
{
    if constexpr (std::is_same_v<T, int32_t>)
    {
        VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_INT32);
        return msg.GetReflection()->GetInt32(msg, f);
    }
    if constexpr (std::is_same_v<T, int64_t>)
    {
        VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_INT64);
        return msg.GetReflection()->GetInt64(msg, f);
    }
    if constexpr (std::is_same_v<T, uint32_t>)
    {
        VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_UINT32);
        return msg.GetReflection()->GetUInt32(msg, f);
    }
    if constexpr (std::is_same_v<T, uint64_t>)
    {
        VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_UINT64);
        return msg.GetReflection()->GetUInt64(msg, f);
    }
    if constexpr (std::is_same_v<T, std::string>)
    {
        VALIDATE_CONSTRAINT(f->cpp_type() == f->CPPTYPE_STRING);
        return msg.GetReflection()->GetString(msg, f);
    }
}

template <typename T>
static CLI::Option*
generic_handle_option(CLI::App* app,
                      std::string name,
                      std::function<google::protobuf::Message*()> mutable_msg_getter,
                      const google::protobuf::Message& default_value_template,
                      const google::protobuf::FieldDescriptor* f,
                      const ArgOption& opt)
{
    CLI::Option* o = app->add_option_function<T>(
        std::move(name),
        [getter = std::move(mutable_msg_getter), f](const T& v) { set_field(getter(), f, v); },
        opt.doc());
    if (default_value_template.GetReflection()->HasField(default_value_template, f))
    {
        o->default_val(get_field<T>(default_value_template, f));
    }
    if constexpr (std::is_integral_v<T>)
    {
        if (opt.has_min_value())
        {
            o->check(
                CLI::Range(boost::numeric_cast<T>(opt.min_value()), std::numeric_limits<T>::max()));
        }
    }
    return o;
}

static void attach_parser(CLI::App* app,
                          std::function<google::protobuf::Message*()> mutable_msg_getter,
                          const google::protobuf::Message& default_value_template,
                          std::string_view name_prefix)
{
    std::vector<const google::protobuf::FieldDescriptor*> fields(
        default_value_template.GetDescriptor()->field_count());
    for (size_t i = 0; i < fields.size(); ++i)
    {
        fields[i] = default_value_template.GetDescriptor()->field(i);
    }
    std::sort(
        fields.begin(),
        fields.end(),
        [](const google::protobuf::FieldDescriptor* f1, const google::protobuf::FieldDescriptor* f2)
        { return f1->number() < f2->number(); });
    for (const google::protobuf::FieldDescriptor* f : fields)
    {
        if (!f->options().HasExtension(::securefs::arg_option))
        {
            continue;
        }
        if (f->is_repeated())
        {
            throw std::invalid_argument("Cannot handle repeated fields yet");
        }
        const ArgOption& opt = f->options().GetExtension(::securefs::arg_option);
        if (!opt.has_doc())
        {
            throw std::invalid_argument("Each cmdline option must have doc attached");
        }
        std::string name = absl::StrCat(name_prefix, absl::StrReplaceAll(f->name(), {{"_", "-"}}));
        if (!opt.positional())
        {
            name = prepend_dash(name);
            if (!opt.alt_name().empty())
            {
                name.push_back(',');
                name.append(prepend_dash(absl::StrCat(name_prefix, opt.alt_name())));
            }
        }
        CLI::Option* o = nullptr;

        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
            o = generic_handle_option<int32_t>(
                app, name, mutable_msg_getter, default_value_template, f, opt);
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            o = generic_handle_option<int64_t>(
                app, name, mutable_msg_getter, default_value_template, f, opt);
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
            o = generic_handle_option<uint32_t>(
                app, name, mutable_msg_getter, default_value_template, f, opt);
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
            o = generic_handle_option<uint64_t>(
                app, name, mutable_msg_getter, default_value_template, f, opt);
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            VALIDATE_CONSTRAINT(f->type() != f->TYPE_BYTES);
            o = generic_handle_option<std::string>(
                app, name, mutable_msg_getter, default_value_template, f, opt);
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            if (default_value_template.GetReflection()->GetBool(default_value_template, f))
            {
                throw std::invalid_argument("A default true is confusing, don't use that");
            }
            o = app->add_flag_function(
                name,
                [=](uint64_t v)
                {
                    auto* msg = mutable_msg_getter();
                    msg->GetReflection()->SetBool(msg, f, v != 0);
                },
                opt.doc());
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
            attach_parser(
                app->add_option_group(opt.doc()),
                [=]()
                {
                    auto* msg = mutable_msg_getter();
                    return msg->GetReflection()->MutableMessage(msg, f);
                },
                default_value_template.GetReflection()->GetMessage(default_value_template, f),
                opt.prefix());
            continue;
        default:
            throw std::invalid_argument(absl::StrFormat(
                "Unsupported proto field type %s for cmdline parsing", f->type_name()));
        }
        if (opt.is_required() || opt.positional())
        {
            o->required();
        }
        if (opt.has_env_key())
        {
            o->envname(opt.env_key());
        }
    }
}

CLI::App* attach_parser(CLI::App* app, google::protobuf::Message* msg)
{
    attach_parser(
        app, [msg]() { return msg; }, *msg, "");
    return app;
}

}    // namespace securefs
