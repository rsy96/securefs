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
                                      f->message_type(),
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
            argument->implicit_value(!opt.default_bool())
                .help(transform_help(opt.doc(),
                                     opt.default_value_case() != opt.DEFAULT_VALUE_NOT_SET,
                                     f->default_value_bool()));
            if (!f->has_presence())
            {
                argument->default_value(opt.default_bool());
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            argument->scan<'d', int64_t>().help(
                transform_help(opt.doc(),
                               opt.default_value_case() != opt.DEFAULT_VALUE_NOT_SET,
                               f->default_value_int64()));
            if (!f->has_presence())
            {
                argument->default_value(opt.default_int64());
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            argument->help(transform_help(
                opt.doc(),
                opt.default_value_case() != opt.DEFAULT_VALUE_NOT_SET,
                absl::StrCat("\"", absl::Utf8SafeCEscape(f->default_value_string()), "\"")));
            if (!f->has_presence())
            {
                argument->default_value(opt.default_string());
            }
            break;
        default:
            throw std::invalid_argument(absl::StrCat(
                "For now, the automatic conversion from proto to cmdline parsers do not support "
                "type ",
                f->cpp_type_name()));
        }
    }
}

template <typename T>
static std::optional<T> extract(const argparse::ArgumentParser& parser,
                                std::string_view name,
                                const google::protobuf::FieldDescriptor* f)
{
    if (f->has_presence())
    {
        return parser.present<T>(name);
    }
    return parser.get<T>(name);
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
            long_name = prepend_dash(long_name);
        }
        switch (f->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            if (auto v = extract<bool>(parser, long_name, f))
            {
                reflection->SetBool(&msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
            if (auto v = extract<int64_t>(parser, long_name, f))
            {
                reflection->SetInt64(&msg, f, *v);
            }
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
            if (auto v = extract<std::string>(parser, long_name, f))
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
