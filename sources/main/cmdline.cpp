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
std::string transform_help(std::string_view doc, bool has_user_specified_default, V&& default_value)
{
    return has_user_specified_default ? absl::StrFormat("%s (default: %v)", doc, default_value)
                                      : std::string{doc.data(), doc.size()};
}
void add_all_options_to_parser(argparse::ArgumentParser& parser,
                               const google::protobuf::Descriptor* descriptor,
                               std::string_view name_prefix)
{
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
        const ArgOption& opt = f->options().GetExtension(::securefs::arg_option);
        if (!opt.has_doc())
        {
            continue;
        }
        std::string long_name
            = absl::StrCat(name_prefix, absl::StrReplaceAll(f->name(), {{"_", "-"}}));
        if (f->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
        {
            add_all_options_to_parser(parser,
                                      f->message_type(),
                                      opt.has_prefix() ? opt.prefix()
                                                       : absl::StrCat(long_name, "-"));
            continue;
        }
        std::string short_name;
        if (!opt.positional())
        {
            long_name = absl::StrCat("--", long_name);
            if (!opt.short_name().empty())
            {
                if (!name_prefix.empty())
                {
                    throw std::invalid_argument(
                        "short_name cannot be specified on a nested message field");
                }
                short_name = absl::StrCat("-", opt.short_name());
            }
        }
        argparse::Argument* argument = nullptr;
        if (short_name.empty())
        {
            argument = &parser.add_argument(long_name);
        }
        else
        {
            argument = &parser.add_argument(long_name, short_name);
        }
        if (f->is_repeated())
        {
            throw std::invalid_argument("Cannot handle repeated fields yet");
        }
        if (opt.is_required() || f->is_required())
        {
            argument->required();
        }
        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            argument->implicit_value(!f->default_value_bool())
                .help(transform_help(opt.doc(), f->has_default_value(), f->default_value_bool()));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            argument->scan<'d', int64_t>().help(
                transform_help(opt.doc(), f->has_default_value(), f->default_value_int64()));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            argument->help(transform_help(
                opt.doc(),
                f->has_default_value(),
                absl::StrCat("\"", absl::Utf8SafeCEscape(f->default_value_string()), "\"")));
            break;
        default:
            throw std::invalid_argument(absl::StrCat(
                "For now, the automatic conversion from proto to cmdline parsers do not support "
                "type ",
                f->cpp_type_name()));
        }
    }
}
void extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                        google::protobuf::Message& msg,
                                        std::string_view name_prefix)
{
    auto descriptor = msg.GetDescriptor();
    auto reflection = msg.GetReflection();
    for (int i = 0; i < descriptor->field_count(); ++i)
    {
        const google::protobuf::FieldDescriptor* f = descriptor->field(i);
        const ArgOption& opt = f->options().GetExtension(::securefs::arg_option);
        if (!opt.has_doc())
        {
            continue;
        }
        std::string long_name
            = absl::StrCat(name_prefix, absl::StrReplaceAll(f->name(), {{"_", "-"}}));
        if (f->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
        {
            extract_options_from_parsed_parser(parser,
                                               *(reflection->MutableMessage(&msg, f)),
                                               opt.has_prefix() ? opt.prefix()
                                                                : absl::StrCat(long_name, "-"));
            continue;
        }
        if (!opt.positional())
        {
            long_name = absl::StrCat("--", long_name);
        }
        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            if (auto v = parser.present<bool>(long_name))
            {
                reflection->SetBool(&msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            if (auto v = parser.present<int64_t>(long_name))
            {
                reflection->SetInt64(&msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            if (auto v = parser.present<std::string>(long_name))
            {
                reflection->SetString(&msg, f, *v);
            }
            break;
        default:
            throw std::invalid_argument("Unsupported type");
        }
    }
}
}    // namespace securefs
