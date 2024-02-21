#pragma once

#include <argparse/argparse.hpp>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

namespace securefs
{
void add_all_options_to_parser(argparse::ArgumentParser& parser,
                               const google::protobuf::Descriptor* descriptor,
                               std::string_view name_prefix = {});
void extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                        google::protobuf::Message& msg,
                                        std::string_view name_prefix = {});
}    // namespace securefs
