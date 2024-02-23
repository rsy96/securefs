#pragma once

#include <CLI/App.hpp>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include <memory>

namespace securefs
{

CLI::App* attach_parser(CLI::App* app, google::protobuf::Message* msg);
}    // namespace securefs
