#include "main/cmdline.hpp"

#include "protos/cmdline.pb.h"

#include <CLI/CLI.hpp>
#include <doctest/doctest.h>

#include <string>
#include <vector>

namespace securefs
{
static void parse_natural(CLI::App* parser, std::vector<std::string> args)
{
    std::reverse(args.begin(), args.end());
    args.pop_back();
    parser->parse(args);
}

TEST_CASE("Parse create options")
{
    CLI::App parser("create");
    CreateCmd cmd;
    cmd.mutable_argon2_params()->set_memory_cost(64);
    cmd.mutable_argon2_params()->set_parallelism(4);
    cmd.mutable_argon2_params()->set_time_cost(1);
    parse_natural(attach_parser(&parser, &cmd),
                  {"create",
                   "repo",
                   "--exact-name-only",
                   "--password=123",
                   "--argon2-m=512",
                   "--block",
                   "8192"});

    CHECK(cmd.repository() == "repo");
    CHECK(cmd.password() == "123");
    CHECK(cmd.tree_db().empty());
    CHECK(cmd.argon2_params().memory_cost() == 512);
    CHECK(cmd.argon2_params().parallelism() == 4);
    CHECK(cmd.params().underlying_block_size() == 8192);
}

TEST_CASE("Parse create options without argon2 params")
{
    CLI::App parser("create");
    CreateCmd cmd;
    parse_natural(attach_parser(&parser, &cmd),
                  {
                      "create",
                      "repo",
                      "--keyfile=./mykey",
                  });

    CHECK(cmd.repository() == "repo");
    CHECK(cmd.password() == "");
    CHECK(cmd.key_file() == "./mykey");
    CHECK(cmd.tree_db().empty());
    CHECK(!cmd.has_argon2_params());
    CHECK(!cmd.has_params());
}
}    // namespace securefs
