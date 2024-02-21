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
    add_all_options_to_parser(parser, options.descriptor());
    parser.parse_args(
        {"create", "repo", "--exact-name", "--password=123", "--argon2-memory-cost=512"});
    extract_options_from_parsed_parser(parser, options);

    CHECK(options.repository() == "repo");
    CHECK(options.exact_name());
    CHECK(options.password() == "123");
    CHECK(!options.has_tree_db());
    CHECK(options.argon2().memory_cost() == 512);
    CHECK(!options.argon2().has_parallelism());
}
}    // namespace securefs
