#include "cli_parser.h"

#include <getopt.h>

#include <cstdlib>
#include <iostream>

#include "../config/config.h"
#include "output_formatter.h"

namespace dns_resolver {

CliOptions CliParser::parse_arguments(int argc, char *argv[]) {
  CliOptions options;

  static struct option long_options[] = {{"type", required_argument, 0, 't'},
                                         {"verbose", no_argument, 0, 'v'},
                                         {"all", no_argument, 0, 'a'},
                                         {"timeout", required_argument, 0, 'T'},
                                         {"help", no_argument, 0, 'h'},
                                         {"version", no_argument, 0, 1000},
                                         {0, 0, 0, 0}};

  int option_index = 0;
  int c;

  while ((c = getopt_long(argc, argv, "t:vaT:h", long_options, &option_index)) != -1) {
    switch (c) {
      case 't':
        options.query_type = parse_record_type(optarg);
        break;
      case 'v':
        options.verbose = true;
        break;
      case 'a':
        options.resolve_all = true;
        break;
      case 'T':
        try {
          int timeout_val = std::stoi(optarg);
          if (timeout_val <= 0 || timeout_val > 300) {
            std::cerr << "Error: Timeout must be between 1 and 300 seconds\n";
            exit(2);
          }
          options.timeout = std::chrono::seconds(timeout_val);
        } catch (...) {
          std::cerr << "Error: Invalid timeout value: " << optarg << "\n";
          exit(2);
        }
        break;
      case 'h':
        options.show_help = true;
        break;
      case 1000:  // --version
        options.show_version = true;
        break;
      case '?':
        exit(2);
      default:
        std::cerr << "Error: Unknown option\n";
        exit(2);
    }
  }

  // Get domain name from remaining arguments
  if (optind < argc) {
    options.domain = argv[optind];
  }

  return options;
}

void CliParser::print_usage(const char *program_name) {
  using namespace colors;

  std::cout << "\n";
  std::cout << OutputFormatter::colorize("✦ dns_resolver", BOLD + BLUE) << "\n";
  std::cout << OutputFormatter::colorize(
                   "A recursive DNS resolver implemented in modern C++ (C++23)", GREEN + BOLD)
            << "\n";
  std::cout
      << OutputFormatter::colorize(
             "────────────────────────────────────────────────────────────────────────────────────",
             GRAY)
      << "\n\n";

  std::cout << OutputFormatter::colorize("Usage: ", BOLD)
            << OutputFormatter::colorize(program_name, CYAN) << " [OPTIONS] "
            << OutputFormatter::colorize("<domain>", YELLOW) << "\n\n";

  std::cout << OutputFormatter::colorize("Options:", BOLD) << "\n";
  std::cout << "  " << OutputFormatter::colorize("-t, --type TYPE", GREEN) << "     Query type ("
            << OutputFormatter::colorize("A, AAAA, TXT, MX, NS, CNAME, SOA, ANY", YELLOW)
            << ") [default: A]\n";
  std::cout << "  " << OutputFormatter::colorize("-v, --verbose", GREEN)
            << "       Show detailed resolution path\n";
  std::cout << "  " << OutputFormatter::colorize("-a, --all", GREEN)
            << "           Resolve both A and AAAA records\n";
  std::cout << "  " << OutputFormatter::colorize("-T, --timeout SEC", GREEN)
            << "   Query timeout in seconds [default: 5]\n";
  std::cout << "  " << OutputFormatter::colorize("-h, --help", GREEN)
            << "          Show this help message\n";
  std::cout << "      " << OutputFormatter::colorize("--version", GREEN)
            << "       Show version information\n\n";

  std::cout << OutputFormatter::colorize("Examples:", BOLD) << "\n";
  std::cout << "  " << OutputFormatter::colorize(program_name, CYAN) << " example.com"
            << OutputFormatter::colorize("                    # Resolve IPv4 address", GRAY)
            << "\n";
  std::cout << "  " << OutputFormatter::colorize(program_name, CYAN) << " -t AAAA example.com"
            << OutputFormatter::colorize("           # Resolve IPv6 address", GRAY) << "\n";
  std::cout << "  " << OutputFormatter::colorize(program_name, CYAN) << " -t TXT example.com"
            << OutputFormatter::colorize("            # Get TXT records", GRAY) << "\n";
  std::cout << "  " << OutputFormatter::colorize(program_name, CYAN) << " -t MX example.com"
            << OutputFormatter::colorize("              # Get mail servers", GRAY) << "\n";
  std::cout << "  " << OutputFormatter::colorize(program_name, CYAN) << " -v --all example.com"
            << OutputFormatter::colorize("      # Verbose mode with both IPv4/IPv6", GRAY)
            << "\n\n";

  std::cout << OutputFormatter::colorize("Exit codes:", BOLD) << "\n";
  std::cout << "  0  Success\n";
  std::cout << "  1  General error\n";
  std::cout << "  2  Invalid arguments\n";
  std::cout << "  3  DNS resolution failed\n";
  std::cout << "  4  Network error\n\n";

  std::cout << "Documentation: "
            << OutputFormatter::colorize("https://github.com/uiuxarghya/dns_resolver/wiki", CYAN)
            << "\n";
  std::cout << "Report issues: "
            << OutputFormatter::colorize("https://github.com/uiuxarghya/dns_resolver/issues", CYAN)
            << "\n\n";
}

void CliParser::print_version() {
  using namespace colors;

  std::cout << "\n" << OutputFormatter::colorize("✦ dns_resolver", BOLD + BLUE) << "\n";
  std::cout << OutputFormatter::colorize(
                   "A recursive DNS resolver implemented in modern C++ (C++23)", GREEN)
            << "\n";
  std::cout << OutputFormatter::colorize("Version: ", GRAY)
            << OutputFormatter::colorize(config::APPLICATION_VERSION, YELLOW) << "\n";
  std::cout << OutputFormatter::colorize("Author: ", GRAY)
            << OutputFormatter::colorize(config::APPLICATION_AUTHOR, WHITE) << "\n";
  std::cout << OutputFormatter::colorize("Repository: ", GRAY)
            << OutputFormatter::colorize("https://github.com/uiuxarghya/dns_resolver", CYAN)
            << "\n";
  std::cout << OutputFormatter::colorize("Documentation: ", GRAY)
            << OutputFormatter::colorize("https://github.com/uiuxarghya/dns_resolver/wiki", CYAN)
            << "\n";
  std::cout << "\n";
  std::cout << OutputFormatter::colorize(
                   "⇝ Supports A, AAAA, TXT, MX, NS, CNAME, SOA, SRV, PTR records", GREEN)
            << "\n";
  std::cout << OutputFormatter::colorize("⇝ Features EDNS(0), caching, and IPv4/IPv6", GREEN)
            << "\n";
  std::cout << "\n";
}

RecordType CliParser::parse_record_type(const std::string &type_str) {
  return utils::string_to_record_type(type_str);
}

}  // namespace dns_resolver