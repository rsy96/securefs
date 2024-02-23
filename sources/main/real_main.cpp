#include "real_main.hpp"
#include "cmdline.hpp"
#include "core/exceptions.hpp"
#include "core/repo.hpp"

#include "protos/cmdline.pb.h"

#include <absl/log/initialize.h>
#include <absl/strings/str_format.h>
#include <argparse/argparse.hpp>
#include <google/protobuf/text_format.h>

namespace securefs
{

namespace
{
#ifdef _WIN32
    struct ConsoleCPController
    {
        ConsoleCPController()
        {
            old_cp = ::GetConsoleCP();
            old_output_cp = ::GetConsoleOutputCP();

            ::SetConsoleCP(CP_UTF8);
            ::SetConsoleOutputCP(CP_UTF8);
        }
        ~ConsoleCPController()
        {
            SetConsoleOutputCP(old_output_cp);
            SetConsoleCP(old_cp);
        }

    private:
        DWORD old_cp, old_output_cp;
    };

    ConsoleCPController console_cp_controller;
#endif
    constexpr const char* const kDefaultAllCmds = R"textproto(
        create_cmd: {
            params: {
                format_version: 5
                underlying_block_size: 4096
                virtual_block_size_for_tree_db: 4096
            }
            argon2_params: {
                time_cost: 5
                memory_cost: 256
                parallelism: 4
            }
        }
    )textproto";

    AllCmds parse_all_cmds(int argc, char** argv)
    {
        AllCmds default_cmds, result_cmds;
        VALIDATE_CONSTRAINT(
            google::protobuf::TextFormat::ParseFromString(kDefaultAllCmds, &default_cmds));

        argparse::ArgumentParser base_parser(argv[0]), create_parser("create"), c_parser("c");
        base_parser.add_description(
            "securefs is a userspace filesystem that transparently encrypts/decrypts files");
        create_parser.add_description("create a new securefs repo");
        c_parser.add_description("(same as \"create\") create a new securefs repo");

        add_all_options_to_parser(create_parser, default_cmds.create_cmd());
        add_all_options_to_parser(c_parser, default_cmds.create_cmd());

        base_parser.add_subparser(create_parser);
        base_parser.add_subparser(c_parser);

        base_parser.parse_args(argc, argv);
        if (base_parser.is_subcommand_used(create_parser))
        {
            extract_options_from_parsed_parser(create_parser, *default_cmds.mutable_create_cmd());
            result_cmds.mutable_create_cmd()->Swap(default_cmds.mutable_create_cmd());
        }
        else if (base_parser.is_subcommand_used(c_parser))
        {
            extract_options_from_parsed_parser(c_parser, *default_cmds.mutable_create_cmd());
            result_cmds.mutable_create_cmd()->Swap(default_cmds.mutable_create_cmd());
        }
        else
        {
            absl::FPrintF(stderr, "%s\n\n", base_parser.help().str());
        }
        return result_cmds;
    }
}    // namespace

int real_main(int argc, char** argv)
{
    try
    {
        absl::InitializeLog();
        AllCmds all_cmds;
        VALIDATE_CONSTRAINT(
            google::protobuf::TextFormat::ParseFromString(kDefaultAllCmds, &all_cmds));

        auto main_app = std::make_unique<CLI::App>("securefs");
        attach_parser(main_app->add_subcommand("create")->alias("c"), all_cmds.mutable_create_cmd())
            ->parse_complete_callback([&]() { create_repo(all_cmds.create_cmd()); });
        main_app->require_subcommand(1);
        CLI11_PARSE(*main_app, argc, argv);
    }
    catch (const std::exception& e)
    {
        absl::FPrintF(stderr, "Exception encountered (%s): %s\n", typeid(e).name(), e.what());
        return 1;
    }
    return 0;
}
}    // namespace securefs
