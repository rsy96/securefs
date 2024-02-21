#pragma once

#include <argparse/argparse.hpp>
#include <google/protobuf/message.h>

namespace securefs
{
void add_all_options_to_parser(argparse::ArgumentParser& parser,
                               const google::protobuf::Message& msg);
void extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                        google::protobuf::Message& msg);
}    // namespace securefs
