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
    add_all_options_to_parser(parser, options);
    parser.parse_args({"create", "repo", "--exact-name", "--password=123"});
    extract_options_from_parsed_parser(parser, options);

    CHECK(options.repository() == "repo");
    CHECK(options.exact_name());
    CHECK(options.password() == "123");
    CHECK(!options.has_tree_db());
}
}    // namespace securefs
