#include "cmdline.hpp"

#include "protos/cmdline.pb.h"

#include <absl/strings/escaping.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_replace.h>
#include <argparse/argparse.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace securefs
{

template <typename V>
static std::string
transform_help(std::string_view doc, bool has_user_specified_default, V&& default_value)
{
    return has_user_specified_default ? absl::StrFormat("%s (default: %v)", doc, default_value)
                                      : std::string{doc.data(), doc.size()};
}

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

void add_all_options_to_parser(argparse::ArgumentParser& parser,
                               const google::protobuf::Message& msg,
                               std::string_view name_prefix)
{
    auto descriptor = msg.GetDescriptor();
    auto reflection = msg.GetReflection();
    std::vector<const google::protobuf::FieldDescriptor*> fields(descriptor->field_count());
    for (size_t i = 0; i < fields.size(); ++i)
    {
        fields[i] = descriptor->field(i);
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
        std::string long_name
            = absl::StrCat(name_prefix, absl::StrReplaceAll(f->name(), {{"_", "-"}}));
        if (f->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
        {
            add_all_options_to_parser(parser,
                                      reflection->GetMessage(msg, f),
                                      opt.has_prefix() ? opt.prefix()
                                                       : absl::StrCat(long_name, "-"));
            continue;
        }
        std::string alt_name = opt.alt_name();
        if (!alt_name.empty())
        {
            alt_name = absl::StrCat(name_prefix, alt_name);
        }
        if (!opt.positional())
        {
            long_name = prepend_dash(long_name);
            alt_name = prepend_dash(alt_name);
        }

        argparse::Argument* argument = nullptr;
        if (alt_name.empty())
        {
            argument = &parser.add_argument(long_name);
        }
        else
        {
            argument = &parser.add_argument(long_name, alt_name);
        }
        if (opt.is_required())
        {
            argument->required();
        }
        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            argument->implicit_value(!reflection->GetBool(msg, f))
                .help(transform_help(
                    opt.doc(), reflection->HasField(msg, f), reflection->GetBool(msg, f)));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            argument->scan<'d', int64_t>().help(transform_help(
                opt.doc(), reflection->HasField(msg, f), reflection->GetInt64(msg, f)));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
            argument->scan<'u', uint64_t>().help(transform_help(
                opt.doc(), reflection->HasField(msg, f), reflection->GetUInt64(msg, f)));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            argument->help(transform_help(
                opt.doc(), reflection->HasField(msg, f), reflection->GetString(msg, f)));
            break;
        default:
            throw std::invalid_argument(absl::StrCat(
                "For now, the automatic conversion from proto to cmdline parsers do not support "
                "type ",
                f->cpp_type_name()));
        }
    }
}

static void
extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                   const std::function<google::protobuf::Message*()>& lazy_msg,
                                   const google::protobuf::Descriptor* descriptor,
                                   std::string_view name_prefix)
{
    for (int i = 0; i < descriptor->field_count(); ++i)
    {
        const google::protobuf::FieldDescriptor* f = descriptor->field(i);
        if (!f->options().HasExtension(::securefs::arg_option))
        {
            continue;
        }
        const ArgOption& opt = f->options().GetExtension(::securefs::arg_option);
        std::string long_name
            = absl::StrCat(name_prefix, absl::StrReplaceAll(f->name(), {{"_", "-"}}));
        if (f->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
        {
            extract_options_from_parsed_parser(
                parser,
                [&]()
                {
                    auto* msg = lazy_msg();
                    return msg->GetReflection()->MutableMessage(msg, f);
                },
                f->message_type(),
                opt.has_prefix() ? opt.prefix() : absl::StrCat(long_name, "-"));
            continue;
        }
        if (!opt.positional())
        {
            long_name = prepend_dash(long_name);
        }
        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            if (auto v = parser.present<bool>(long_name))
            {
                auto* msg = lazy_msg();
                msg->GetReflection()->SetBool(msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            if (auto v = parser.present<int64_t>(long_name))
            {
                auto* msg = lazy_msg();
                msg->GetReflection()->SetInt64(msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
            if (auto v = parser.present<uint64_t>(long_name))
            {
                auto* msg = lazy_msg();
                msg->GetReflection()->SetUInt64(msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            if (auto v = parser.present<std::string>(long_name))
            {
                auto* msg = lazy_msg();
                msg->GetReflection()->SetString(msg, f, *v);
            }
            break;
        default:
            throw std::invalid_argument("Unsupported type");
        }
    }
}

void extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                        google::protobuf::Message& msg,
                                        std::string_view name_prefix)
{
    extract_options_from_parsed_parser(
        parser, [&]() { return &msg; }, msg.GetDescriptor(), name_prefix);
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
