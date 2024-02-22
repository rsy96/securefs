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
}    // namespace securefs
