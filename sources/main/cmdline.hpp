#pragma once

#include <CLI/App.hpp>
#include <argparse/argparse.hpp>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include <memory>

namespace securefs
{
void add_all_options_to_parser(argparse::ArgumentParser& parser,
                               const google::protobuf::Message& msg,
                               std::string_view name_prefix = {});
void extract_options_from_parsed_parser(const argparse::ArgumentParser& parser,
                                        google::protobuf::Message& msg,
                                        std::string_view name_prefix = {});

CLI::App* attach_parser(CLI::App* app, google::protobuf::Message* msg);
}    // namespace securefs
