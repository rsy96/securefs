#include "cmdline.hpp"

#include "protos/cmdline.pb.h"

#include <absl/strings/escaping.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_replace.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

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
        switch (f->type())
        {
        case google::protobuf::FieldDescriptor::TYPE_BOOL:
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
        case google::protobuf::FieldDescriptor::TYPE_STRING:
            o = app->add_option_function<std::string>(
                name,
                [=](const std::string& v)
                {
                    auto* msg = mutable_msg_getter();
                    msg->GetReflection()->SetString(msg, f, v);
                },
                opt.doc());
            if (default_value_template.GetReflection()->HasField(default_value_template, f))
            {
                o->default_val(
                    default_value_template.GetReflection()->GetString(default_value_template, f));
            }
            break;
        case google::protobuf::FieldDescriptor::TYPE_INT64:
        case google::protobuf::FieldDescriptor::TYPE_SINT64:
        case google::protobuf::FieldDescriptor::TYPE_SFIXED64:
            o = app->add_option_function<int64_t>(
                name,
                [=](const int64_t& v)
                {
                    auto* msg = mutable_msg_getter();
                    msg->GetReflection()->SetInt64(msg, f, v);
                },
                opt.doc());
            if (default_value_template.GetReflection()->HasField(default_value_template, f))
            {
                o->default_val(
                    default_value_template.GetReflection()->GetInt64(default_value_template, f));
            }
            break;
        case google::protobuf::FieldDescriptor::TYPE_UINT64:
        case google::protobuf::FieldDescriptor::TYPE_FIXED64:
            o = app->add_option_function<uint64_t>(
                name,
                [=](const int64_t& v)
                {
                    auto* msg = mutable_msg_getter();
                    msg->GetReflection()->SetUInt64(msg, f, v);
                },
                opt.doc());
            if (default_value_template.GetReflection()->HasField(default_value_template, f))
            {
                o->default_val(
                    default_value_template.GetReflection()->GetUInt64(default_value_template, f));
            }
            break;
        case google::protobuf::FieldDescriptor::TYPE_MESSAGE:
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
