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
    parser.parse_args({"create", "repo", "--exact-name", "--password=123", "--ar-m=512"});
    extract_options_from_parsed_parser(parser, options);

    CHECK(options.repository() == "repo");
    CHECK(options.exact_name());
    CHECK(options.password() == "123");
    CHECK(options.tree_db().empty());
    CHECK(options.argon2_params().memory_cost() == 512);
    CHECK(options.argon2_params().parallelism() == 4);
}
}    // namespace securefs
