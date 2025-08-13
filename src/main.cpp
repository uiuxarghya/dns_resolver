#include <getopt.h>
#include <unistd.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "config/config.h"
#include "resolver/resolver.h"
#include "resolver/utils.h"

#define BG_GREEN "\033[42m"
#define BG_GRAY "\033[47m"
#define FG_BLACK "\033[30m"

namespace dns_resolver {

// ANSI color codes
namespace colors {
const std::string RESET = "\033[0m";
const std::string BOLD = "\033[1m";
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string BLUE = "\033[34m";
const std::string MAGENTA = "\033[35m";
const std::string CYAN = "\033[36m";
const std::string WHITE = "\033[37m";
const std::string GRAY = "\033[90m";
}  // namespace colors

// Check if stdout supports colors
bool supports_color() { return isatty(STDOUT_FILENO); }

// Color wrapper function
std::string colorize(const std::string &text, const std::string &color) {
  if (supports_color()) {
    return color + text + colors::RESET;
  }
  return text;
}

struct CliOptions {
  std::string domain;
  RecordType query_type = RecordType::A;
  bool verbose = false;
  bool show_help = false;
  bool show_version = false;
  bool resolve_all = false;
  std::chrono::seconds timeout{5};
};

void print_usage(const char *program_name) {
  std::cout << "\n";
  std::cout << colorize("✦ dns_resolver", colors::BOLD + colors::BLUE) << "\n";
  std::cout << colorize("A recursive DNS resolver implemented in modern C++ (C++23)",
                        colors::GREEN + colors::BOLD)
            << "\n";
  std::cout
      << colorize(
             "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
             colors::GRAY)
      << "\n\n";
  std::cout << BG_GREEN << FG_BLACK << " ✓ SUCCEEDED " << colors::RESET << " Colors(9ms)\n";
  std::cout << colorize("Usage: ", colors::BOLD) << colorize(program_name, colors::CYAN)
            << " [OPTIONS] " << colorize("<domain>", colors::YELLOW) << "\n\n";

  std::cout << colorize("Options:", colors::BOLD) << "\n";
  std::cout << "  " << colorize("-t, --type TYPE", colors::GREEN) << "     Query type ("
            << colorize("A, AAAA, TXT, MX, NS, CNAME, SOA, ANY", colors::YELLOW)
            << ") [default: A]\n";
  std::cout << "  " << colorize("-v, --verbose", colors::GREEN)
            << "       Show detailed resolution path\n";
  std::cout << "  " << colorize("-a, --all", colors::GREEN)
            << "           Resolve both A and AAAA records\n";
  std::cout << "  " << colorize("-T, --timeout SEC", colors::GREEN)
            << "   Query timeout in seconds [default: 5]\n";
  std::cout << "  " << colorize("-h, --help", colors::GREEN)
            << "          Show this help message\n";
  std::cout << "      " << colorize("--version", colors::GREEN)
            << "       Show version information\n\n";

  std::cout << colorize("Examples:", colors::BOLD) << "\n";
  std::cout << "  " << colorize(program_name, colors::CYAN) << " example.com"
            << colorize("                    # Resolve IPv4 address", colors::GRAY) << "\n";
  std::cout << "  " << colorize(program_name, colors::CYAN) << " -t AAAA example.com"
            << colorize("           # Resolve IPv6 address", colors::GRAY) << "\n";
  std::cout << "  " << colorize(program_name, colors::CYAN) << " -t TXT example.com"
            << colorize("            # Get TXT records", colors::GRAY) << "\n";
  std::cout << "  " << colorize(program_name, colors::CYAN) << " -t MX example.com"
            << colorize("              # Get mail servers", colors::GRAY) << "\n";
  std::cout << "  " << colorize(program_name, colors::CYAN) << " -v --all example.com"
            << colorize("      # Verbose mode with both IPv4/IPv6", colors::GRAY) << "\n\n";

  std::cout << colorize("Exit codes:", colors::BOLD) << "\n";
  std::cout << "  0  Success\n";
  std::cout << "  1  General error\n";
  std::cout << "  2  Invalid arguments\n";
  std::cout << "  3  DNS resolution failed\n";
  std::cout << "  4  Network error\n\n";

  std::cout << "Documentation: "
            << colorize("https://github.com/uiuxarghya/dns_resolver/wiki", colors::CYAN) << "\n";
  std::cout << "Report issues: "
            << colorize("https://github.com/uiuxarghya/dns_resolver/issues", colors::CYAN)
            << "\n\n";
}

void print_version() {
  std::cout << colorize("✦ dns_resolver", colors::BOLD + colors::BLUE) << "\n";
  std::cout << colorize("A recursive DNS resolver implemented in modern C++23", colors::GREEN)
            << "\n";
  std::cout << colorize("Version: ", colors::GRAY)
            << colorize(config::APPLICATION_VERSION, colors::YELLOW) << "\n";
  std::cout << colorize("Author: ", colors::GRAY)
            << colorize(config::APPLICATION_AUTHOR, colors::WHITE) << "\n";
  std::cout << colorize("Repository: ", colors::GRAY)
            << colorize("https://github.com/uiuxarghya/dns_resolver", colors::CYAN) << "\n";
  std::cout << colorize("Documentation: ", colors::GRAY)
            << colorize("https://github.com/uiuxarghya/dns_resolver/wiki", colors::CYAN) << "\n";
  std::cout << "\n";
  std::cout << colorize("◎ Supports A, AAAA, TXT, MX, NS, CNAME records", colors::GREEN) << "\n";
  std::cout << colorize("⚙ Features EDNS(0), caching, and IPv4/IPv6", colors::GREEN) << "\n";
  std::cout << "\n";
}

CliOptions parse_arguments(int argc, char *argv[]) {
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
        options.query_type = utils::string_to_record_type(optarg);
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

void print_resolution_result(const ResolutionResult &result, const std::string &domain,
                             RecordType type, bool verbose) {
  if (!result.success) {
    // Error Section
    std::cerr << "\n" << colorize("✘ DNS Resolution Failed", colors::RED + colors::BOLD) << "\n";
    std::cerr << colorize("━━━━━━━━━━━━━━━━━━━━━━━━", colors::RED) << "\n";
    std::cerr << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::YELLOW + colors::BOLD) << "\n";
    std::cerr << colorize("→ Type: ", colors::GRAY)
              << colorize(utils::record_type_to_string(type), colors::CYAN) << "\n";
    if (!result.error_message.empty()) {
      std::cerr << colorize("→ Error: ", colors::GRAY)
                << colorize(result.error_message, colors::RED) << "\n";
    }
    std::cerr << "\n";
    return;
  }

  if (verbose) {
    // Query Information Section
    std::cout << "\n" << colorize("☰ Query Information", colors::BOLD + colors::BLUE) << "\n";
    std::cout << colorize("━━━━━━━━━━━━━━━━━━━━", colors::BLUE) << "\n";
    std::cout << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    std::cout << colorize("→ Record Type: ", colors::GRAY)
              << colorize(utils::record_type_to_string(type), colors::CYAN) << "\n";

    // Performance Metrics Section
    std::cout << "\n" << colorize("⏱\uFE0E Performance Metrics", colors::BOLD + colors::YELLOW) << "\n";
    std::cout << colorize("━━━━━━━━━━━━━━━━━━━━━━━", colors::YELLOW) << "\n";
    std::cout << colorize("→ Resolution Time: ", colors::GRAY)
              << colorize(std::to_string(result.resolution_time.count()) + " ms",
                          colors::YELLOW + colors::BOLD)
              << "\n";
    std::cout << colorize("→ Cache Status: ", colors::GRAY)
              << colorize(result.from_cache ? "HIT" : "MISS", result.from_cache
                                                                  ? colors::GREEN + colors::BOLD
                                                                  : colors::YELLOW + colors::BOLD)
              << "\n";
    std::cout << colorize("→ Records Found: ", colors::GRAY)
              << colorize(std::to_string(result.addresses.size()), colors::CYAN + colors::BOLD)
              << "\n";

    // Results Section Header
    std::cout << "\n" << colorize("◎ DNS Resolution Results", colors::BOLD + colors::GREEN) << "\n";
    std::cout << colorize("━━━━━━━━━━━━━━━━━━━━━━━━━━", colors::GREEN) << "\n";
  }

  // Print results with appropriate icons and colors
  for (size_t i = 0; i < result.addresses.size(); ++i) {
    std::string icon = "○";
    std::string color = colors::GREEN;
    std::string type_label = "";

    // Choose icon, color, and label based on record type and content
    if (type == RecordType::A) {
      icon = "◉";
      color = colors::GREEN;
      type_label = "IPv4";
    } else if (type == RecordType::AAAA) {
      icon = "◆";
      color = colors::BLUE;
      type_label = "IPv6";
    } else if (type == RecordType::TXT) {
      icon = "✎";
      color = colors::YELLOW;
      type_label = "Text";
    } else if (type == RecordType::MX) {
      icon = "✉";
      color = colors::MAGENTA;
      type_label = "Mail";
    } else if (type == RecordType::NS) {
      icon = "⚑";
      color = colors::CYAN;
      type_label = "NameServer";
    } else if (type == RecordType::CNAME) {
      icon = "⇄";
      color = colors::BLUE;
      type_label = "Alias";
    } else if (type == RecordType::SOA) {
      icon = "☗";
      color = colors::YELLOW;
      type_label = "Authority";
    } else if (type == RecordType::SRV) {
      icon = "⚙";
      color = colors::GREEN;
      type_label = "Service";
    } else if (type == RecordType::PTR) {
      icon = "↩";
      color = colors::CYAN;
      type_label = "Pointer";
    }

    if (verbose) {
      std::cout << colorize("  " + icon + " ", color);
      if (!type_label.empty()) {
        std::cout << colorize("[" + type_label + "] ", colors::GRAY);
      }
      std::cout << colorize(result.addresses[i], colors::WHITE + colors::BOLD) << "\n";
    } else {
      std::cout << result.addresses[i] << "\n";
    }
  }

  if (verbose) {
    if (!result.addresses.empty()) {
      std::cout << "\n" << colorize("✔ Resolution Status", colors::BOLD + colors::GREEN) << "\n";
      std::cout << colorize("━━━━━━━━━━━━━━━━━━━", colors::GREEN) << "\n";
      std::cout << colorize("✓ Successfully resolved ", colors::GREEN)
                << colorize(std::to_string(result.addresses.size()), colors::GREEN + colors::BOLD)
                << colorize(" record(s) for ", colors::GREEN)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    } else {
      std::cout << "\n" << colorize("⚠ No Records Found", colors::BOLD + colors::YELLOW) << "\n";
      std::cout << colorize("━━━━━━━━━━━━━━━━━━━━", colors::YELLOW) << "\n";
      std::cout << colorize("→ No ", colors::YELLOW)
                << colorize(utils::record_type_to_string(type), colors::CYAN)
                << colorize(" records found for ", colors::YELLOW)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    }
  }
}

int run_resolver(const CliOptions &options) {
  try {
    // Create resolver configuration
    ResolverConfig config;
    config.query_timeout = options.timeout;
    config.verbose = options.verbose;
    config.enable_caching = true;
    config.enable_ipv6 = true;

    // Apply environment variable overrides
    if (const char *env_timeout = std::getenv("DNS_RESOLVER_UDP_TIMEOUT")) {
      try {
        int timeout_val = std::stoi(env_timeout);
        if (timeout_val > 0 && timeout_val <= 300) {
          config.query_timeout = std::chrono::seconds(timeout_val);
        }
      } catch (...) {
        // Ignore invalid environment values
      }
    }

    config.verbose = config.verbose || config::get_env_bool(config::ENV_VERBOSE, false);

    // Create resolver
    Resolver resolver(config);

    // Show startup banner in verbose mode
    if (options.verbose) {
      std::cout << colorize("✦ Starting DNS resolution in verbose mode",
                            colors::BOLD + colors::GREEN)
                << "\n";
      std::cout << colorize(
                       "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                       "━━━━━━━━━",
                       colors::CYAN)
                << "\n";
      std::cout << colorize("➤ Target Domain: ", colors::GRAY)
                << colorize(options.domain, colors::YELLOW + colors::BOLD) << "\n";

      if (options.resolve_all) {
        std::cout << colorize("☰ Query Types: ", colors::GRAY)
                  << colorize("A + AAAA", colors::CYAN + colors::BOLD) << "\n";
      } else {
        std::cout << colorize("☰ Query Type: ", colors::GRAY)
                  << colorize(utils::record_type_to_string(options.query_type),
                              colors::CYAN + colors::BOLD)
                  << "\n";
      }

      std::cout << colorize("⧗ Timeout: ", colors::GRAY)
                << colorize(std::to_string(options.timeout.count()) + "s",
                            colors::YELLOW + colors::BOLD)
                << "\n";
      std::cout << colorize("⚙ Mode: ", colors::GRAY)
                << colorize("Recursive Resolution", colors::GREEN + colors::BOLD) << "\n";
    }

    // Check if resolver is healthy
    if (options.verbose) {
      std::cout << "\n" << colorize("✚ System Health Check", colors::BOLD + colors::BLUE) << "\n";
      std::cout << colorize("━━━━━━━━━━━━━━━━━━━━━", colors::BLUE) << "\n";
      std::cout << colorize("⇄ Checking connectivity to root servers...", colors::GRAY) << "\n";

      if (!resolver.is_healthy()) {
        std::cout << colorize("⚠ Status: ", colors::GRAY)
                  << colorize("LIMITED", colors::YELLOW + colors::BOLD) << "\n";
        std::cout << colorize("ℹ Note: ", colors::GRAY)
                  << colorize("Cannot reach all root servers. Resolution may be slower.",
                              colors::YELLOW)
                  << "\n";
      } else {
        std::cout << colorize("✔ Status: ", colors::GRAY)
                  << colorize("HEALTHY", colors::GREEN + colors::BOLD) << "\n";
        std::cout << colorize("ℹ Note: ", colors::GRAY)
                  << colorize("All systems operational.", colors::GREEN) << "\n";
      }
    }

    // Perform resolution
    if (options.resolve_all) {
      auto result = resolver.resolve_all(options.domain);
      print_resolution_result(result, options.domain, RecordType::A, options.verbose);
    } else if (options.query_type == RecordType::CNAME) {
      // For CNAME queries, try fallback to SOA then NS if no CNAME exists
      auto result = resolver.resolve(options.domain, RecordType::CNAME);
      if (result.success && !result.addresses.empty()) {
        print_resolution_result(result, options.domain, RecordType::CNAME, options.verbose);
      } else {
        std::cout << colorize("No CNAME record found. Trying SOA...\n", colors::YELLOW);
        auto soa_result = resolver.resolve(options.domain, RecordType::SOA);
        if (soa_result.success && !soa_result.addresses.empty()) {
          print_resolution_result(soa_result, options.domain, RecordType::SOA, options.verbose);
        } else {
          std::cout << colorize("No SOA record found. Trying NS...\n", colors::YELLOW);
          auto ns_result = resolver.resolve(options.domain, RecordType::NS);
          if (ns_result.success && !ns_result.addresses.empty()) {
            print_resolution_result(ns_result, options.domain, RecordType::NS, options.verbose);
          } else {
            std::cout << colorize("No CNAME, SOA, or NS records found for this domain.\n",
                                  colors::RED + colors::BOLD);
          }
        }
      }
    } else {
      auto result = resolver.resolve(options.domain, options.query_type);
      print_resolution_result(result, options.domain, options.query_type, options.verbose);
    }

    // Print cache statistics if verbose
    if (options.verbose) {
      auto stats = resolver.get_cache_stats();
      std::cout << "\n" << colorize("▣ Cache Performance", colors::BOLD + colors::MAGENTA) << "\n";
      std::cout << colorize("━━━━━━━━━━━━━━━━━━━━", colors::MAGENTA) << "\n";

      std::cout << colorize("⬚ Cache Entries: ", colors::GRAY)
                << colorize(std::to_string(stats.total_entries), colors::CYAN + colors::BOLD)
                << "\n";

      double hit_ratio_percent = stats.hit_ratio * 100.0;
      std::string hit_ratio_color = hit_ratio_percent > 70   ? colors::GREEN + colors::BOLD
                                    : hit_ratio_percent > 40 ? colors::YELLOW + colors::BOLD
                                                             : colors::RED + colors::BOLD;

      std::cout << colorize("➤ Hit Ratio: ", colors::GRAY)
                << colorize(std::to_string(static_cast<int>(hit_ratio_percent)) + "%",
                            hit_ratio_color);

      // Add performance indicator
      if (hit_ratio_percent > 70) {
        std::cout << colorize(" (Excellent)", colors::GREEN);
      } else if (hit_ratio_percent > 40) {
        std::cout << colorize(" (Good)", colors::YELLOW);
      } else if (stats.hit_count + stats.miss_count > 0) {
        std::cout << colorize(" (Poor)", colors::RED);
      }
      std::cout << "\n";

      std::cout << colorize("✔ Cache Hits: ", colors::GRAY)
                << colorize(std::to_string(stats.hit_count), colors::GREEN + colors::BOLD) << "\n";
      std::cout << colorize("✘ Cache Misses: ", colors::GRAY)
                << colorize(std::to_string(stats.miss_count), colors::RED + colors::BOLD) << "\n";

      // Add efficiency note
      if (stats.hit_count + stats.miss_count > 0) {
        std::cout << colorize("✧ Efficiency: ", colors::GRAY);
        if (hit_ratio_percent > 70) {
          std::cout << colorize("Cache is performing excellently", colors::GREEN) << "\n";
        } else if (hit_ratio_percent > 40) {
          std::cout << colorize("Cache is working well", colors::YELLOW) << "\n";
        } else {
          std::cout << colorize("Consider increasing cache size", colors::RED) << "\n";
        }
      }
    }

    return 0;
  } catch (const NetworkException &e) {
    std::cerr << "Network error: " << e.what() << "\n";
    return 4;
  } catch (const DnsException &e) {
    std::cerr << "DNS error: " << e.what() << "\n";
    return 3;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}

}  // namespace dns_resolver

int main(int argc, char *argv[]) {
  using namespace dns_resolver;

  auto options = parse_arguments(argc, argv);

  if (options.show_help) {
    print_usage(argv[0]);
    return 0;
  }

  if (options.show_version) {
    print_version();
    return 0;
  }

  if (options.domain.empty()) {
    std::cerr << "Error: Domain name is required\n";
    std::cerr << "Use '" << argv[0] << " --help' for usage information\n";
    return 2;
  }

  // Validate domain name
  if (!utils::is_valid_domain_name(options.domain)) {
    std::cerr << "Error: Invalid domain name: " << options.domain << "\n";
    return 2;
  }

  return run_resolver(options);
}
