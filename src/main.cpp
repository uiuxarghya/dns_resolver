
#include <iostream>

#include "cli/application.h"
#include "cli/cli_parser.h"
#include "resolver/utils.h"

int main(int argc, char *argv[]) {
  using namespace dns_resolver;

  auto options = CliParser::parse_arguments(argc, argv);

  if (options.show_help) {
    CliParser::print_usage(argv[0]);
    return 0;
  }

  if (options.show_version) {
    CliParser::print_version();
    return 0;
  }

  if (options.domain.empty()) {
    std::cerr << "Error: Domain name is required\n";
    std::cerr << "Use '" << argv[0] << " --help' for usage information\n";
    return 2;
  }

  // Validate domain name
  if (!Application::is_valid_domain(options.domain)) {
    std::cerr << "Error: Invalid domain name: " << options.domain << "\n";
    return 2;
  }

  return Application::run_resolver(options);
}
