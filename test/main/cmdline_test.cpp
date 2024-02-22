#include "main/cmdline.hpp"

#include "protos/cmdline.pb.h"

#include <doctest/doctest.h>

#include <string>
#include <vector>

namespace securefs
{
TEST_CASE("Parse create options")
{
    argparse::ArgumentParser parser("create");
    CreateCmd cmd;
    cmd.mutable_argon2_params()->set_memory_cost(64);
    cmd.mutable_argon2_params()->set_parallelism(4);
    cmd.mutable_argon2_params()->set_time_cost(1);
    add_all_options_to_parser(parser, cmd);
    parser.parse_args(
        {"create", "repo", "--exact-name-only", "--password=123", "--ar-m=512", "--block", "8192"});
    extract_options_from_parsed_parser(parser, cmd);

    CHECK(cmd.repository() == "repo");
    CHECK(cmd.password() == "123");
    CHECK(cmd.tree_db().empty());
    CHECK(cmd.argon2_params().memory_cost() == 512);
    CHECK(cmd.argon2_params().parallelism() == 4);
    CHECK(cmd.params().underlying_block_size() == 8192);
}

TEST_CASE("Parse create options without argon2 params")
{
    argparse::ArgumentParser parser("create");
    CreateCmd cmd;
    add_all_options_to_parser(parser, cmd);
    parser.parse_args({
        "create",
        "repo",
        "--keyfile=./mykey",
    });
    extract_options_from_parsed_parser(parser, cmd);

    CHECK(cmd.repository() == "repo");
    CHECK(cmd.password() == "");
    CHECK(cmd.key_file() == "./mykey");
    CHECK(cmd.tree_db().empty());
    CHECK(!cmd.has_argon2_params());
    CHECK(!cmd.has_params());
}
}    // namespace securefs
