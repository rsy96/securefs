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
    CreateCmdOptions options;
    options.mutable_argon2_params()->set_memory_cost(64);
    options.mutable_argon2_params()->set_parallelism(4);
    options.mutable_argon2_params()->set_time_cost(1);
    add_all_options_to_parser(parser, options);
    parser.parse_args(
        {"create", "repo", "--exact-name-only", "--password=123", "--ar-m=512", "--block", "8192"});
    extract_options_from_parsed_parser(parser, options);

    CHECK(options.repository() == "repo");
    CHECK(options.password() == "123");
    CHECK(options.tree_db().empty());
    CHECK(options.argon2_params().memory_cost() == 512);
    CHECK(options.argon2_params().parallelism() == 4);
    CHECK(options.params().underlying_block_size() == 8192);
}

TEST_CASE("Parse create options without argon2 params")
{
    argparse::ArgumentParser parser("create");
    CreateCmdOptions options;
    add_all_options_to_parser(parser, options);
    parser.parse_args({
        "create",
        "repo",
        "--keyfile=./mykey",
    });
    extract_options_from_parsed_parser(parser, options);

    CHECK(options.repository() == "repo");
    CHECK(options.password() == "");
    CHECK(options.key_file() == "./mykey");
    CHECK(options.tree_db().empty());
    CHECK(!options.has_argon2_params());
    CHECK(!options.has_params());
}
}    // namespace securefs
