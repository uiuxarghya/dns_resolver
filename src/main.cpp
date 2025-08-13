#include "resolver/resolver.h"
#include "resolver/utils.h"
#include "config/config.h"
#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>
#include <cstdlib>
#include <iomanip>
#include <unistd.h>

namespace dns_resolver
{

  // ANSI color codes
  namespace colors
  {
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
  }

  // Check if stdout supports colors
  bool supports_color()
  {
    return isatty(STDOUT_FILENO);
  }

  // Color wrapper function
  std::string colorize(const std::string &text, const std::string &color)
  {
    if (supports_color())
    {
      return color + text + colors::RESET;
    }
    return text;
  }

  struct CliOptions
  {
    std::string domain;
    RecordType query_type = RecordType::A;
    bool verbose = false;
    bool show_help = false;
    bool show_version = false;
    bool resolve_all = false;
    std::chrono::seconds timeout{5};
  };

  void print_usage(const char *program_name)
  {
    std::cout << colorize("Usage: ", colors::BOLD) << colorize(program_name, colors::CYAN)
              << " [OPTIONS] " << colorize("<domain>", colors::YELLOW) << "\n\n";

    std::cout << colorize("DNS Resolver", colors::BOLD + colors::BLUE)
              << " - A recursive DNS resolver\n";
    std::cout << colorize("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", colors::GRAY) << "\n\n";

    std::cout << colorize("Options:", colors::BOLD) << "\n";
    std::cout << "  " << colorize("-t, --type TYPE", colors::GREEN)
              << "     Query type (" << colorize("A, AAAA, TXT, MX, NS, CNAME, SOA, ANY", colors::YELLOW)
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
    std::cout << "Exit codes:\n";
    std::cout << "  0  Success\n";
    std::cout << "  1  General error\n";
    std::cout << "  2  Invalid arguments\n";
    std::cout << "  3  DNS resolution failed\n";
    std::cout << "  4  Network error\n";
  }

  void print_version()
  {
    std::cout << colorize("╭─────────────────────────────────────────────────────────────╮", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize(config::APPLICATION_NAME, colors::BOLD + colors::CYAN)
              << " " << colorize(config::APPLICATION_VERSION, colors::YELLOW) << std::string(35, ' ')
              << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize("Author: ", colors::GRAY)
              << colorize(config::APPLICATION_AUTHOR, colors::WHITE) << std::string(35, ' ')
              << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << std::string(61, ' ') << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize("🚀 A recursive DNS resolver", colors::GREEN)
              << std::string(14, ' ') << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize("⚡ Implemented in modern C++ (C++23)", colors::GREEN)
              << std::string(23, ' ') << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize("🌐 Supports A, AAAA, TXT, MX, NS, CNAME records", colors::GREEN)
              << std::string(8, ' ') << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("│", colors::BLUE) << "  " << colorize("🔧 Features EDNS(0), caching, and IPv4/IPv6", colors::GREEN)
              << std::string(12, ' ') << colorize("│", colors::BLUE) << "\n";
    std::cout << colorize("╰─────────────────────────────────────────────────────────────╯", colors::BLUE) << "\n";
  }

  CliOptions parse_arguments(int argc, char *argv[])
  {
    CliOptions options;

    static struct option long_options[] = {
        {"type", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"all", no_argument, 0, 'a'},
        {"timeout", required_argument, 0, 'T'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 1000},
        {0, 0, 0, 0}};

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "t:vaT:h", long_options, &option_index)) != -1)
    {
      switch (c)
      {
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
        try
        {
          int timeout_val = std::stoi(optarg);
          if (timeout_val <= 0 || timeout_val > 300)
          {
            std::cerr << "Error: Timeout must be between 1 and 300 seconds\n";
            exit(2);
          }
          options.timeout = std::chrono::seconds(timeout_val);
        }
        catch (...)
        {
          std::cerr << "Error: Invalid timeout value: " << optarg << "\n";
          exit(2);
        }
        break;
      case 'h':
        options.show_help = true;
        break;
      case 1000: // --version
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
    if (optind < argc)
    {
      options.domain = argv[optind];
    }

    return options;
  }

  void print_resolution_result(const ResolutionResult &result, const std::string &domain,
                               RecordType type, bool verbose)
  {
    if (!result.success)
    {
      std::cerr << colorize("❌ Resolution failed for ", colors::RED + colors::BOLD)
                << colorize(domain, colors::YELLOW);
      if (!result.error_message.empty())
      {
        std::cerr << colorize(": " + result.error_message, colors::RED);
      }
      std::cerr << "\n";
      return;
    }

    if (verbose)
    {
      std::cout << colorize("🔍 Resolution for ", colors::BLUE)
                << colorize(domain, colors::CYAN + colors::BOLD)
                << colorize(" (" + utils::record_type_to_string(type) + ")", colors::GRAY) << "\n";
      std::cout << colorize("⏱️  Time taken: ", colors::GRAY)
                << colorize(std::to_string(result.resolution_time.count()) + " ms", colors::YELLOW) << "\n";
      std::cout << colorize("💾 From cache: ", colors::GRAY)
                << colorize(result.from_cache ? "yes" : "no", result.from_cache ? colors::GREEN : colors::YELLOW) << "\n";
      std::cout << colorize("📊 Records found: ", colors::GRAY)
                << colorize(std::to_string(result.addresses.size()), colors::CYAN) << "\n\n";
    }

    // Print results with appropriate icons and colors
    for (size_t i = 0; i < result.addresses.size(); ++i)
    {
      std::string icon = "🌐";
      std::string color = colors::GREEN;

      // Choose icon and color based on record type and content
      if (type == RecordType::A)
      {
        icon = "🌍";
        color = colors::GREEN;
      }
      else if (type == RecordType::AAAA)
      {
        icon = "🌎";
        color = colors::BLUE;
      }
      else if (type == RecordType::TXT)
      {
        icon = "📝";
        color = colors::YELLOW;
      }
      else if (type == RecordType::MX)
      {
        icon = "📧";
        color = colors::MAGENTA;
      }
      else if (type == RecordType::NS)
      {
        icon = "🏛️";
        color = colors::CYAN;
      }
      else if (type == RecordType::CNAME)
      {
        icon = "🔗";
        color = colors::BLUE;
      }
      else if (type == RecordType::SOA)
      {
        icon = "👑";
        color = colors::YELLOW;
      }
      else if (type == RecordType::SRV)
      {
        icon = "⚙️";
        color = colors::GREEN;
      }
      else if (type == RecordType::PTR)
      {
        icon = "🔄";
        color = colors::CYAN;
      }

      if (verbose)
      {
        std::cout << colorize("  " + icon + " ", color)
                  << colorize(result.addresses[i], colors::WHITE + colors::BOLD) << "\n";
      }
      else
      {
        std::cout << result.addresses[i] << "\n";
      }
    }

    if (verbose && !result.addresses.empty())
    {
      std::cout << "\n"
                << colorize("✅ Resolution completed successfully!", colors::GREEN + colors::BOLD) << "\n";
    }
  }

  int run_resolver(const CliOptions &options)
  {
    try
    {
      // Create resolver configuration
      ResolverConfig config;
      config.query_timeout = options.timeout;
      config.verbose = options.verbose;
      config.enable_caching = true;
      config.enable_ipv6 = true;

      // Apply environment variable overrides
      if (const char *env_timeout = std::getenv("DNS_RESOLVER_UDP_TIMEOUT"))
      {
        try
        {
          int timeout_val = std::stoi(env_timeout);
          if (timeout_val > 0 && timeout_val <= 300)
          {
            config.query_timeout = std::chrono::seconds(timeout_val);
          }
        }
        catch (...)
        {
          // Ignore invalid environment values
        }
      }

      config.verbose = config.verbose ||
                       config::get_env_bool(config::ENV_VERBOSE, false);

      // Create resolver
      Resolver resolver(config);

      // Show startup banner in verbose mode
      if (options.verbose)
      {
        std::cout << colorize("🚀 DNS Resolver Starting", colors::BOLD + colors::CYAN) << "\n";
        std::cout << colorize("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", colors::GRAY) << "\n";
        std::cout << colorize("🔍 Target: ", colors::GRAY) << colorize(options.domain, colors::YELLOW + colors::BOLD) << "\n";
        std::cout << colorize("📋 Type: ", colors::GRAY) << colorize(utils::record_type_to_string(options.query_type), colors::CYAN) << "\n";
        std::cout << colorize("⏱️  Timeout: ", colors::GRAY) << colorize(std::to_string(options.timeout.count()) + "s", colors::YELLOW) << "\n\n";
      }

      // Check if resolver is healthy
      if (options.verbose)
      {
        std::cout << colorize("🏥 Checking resolver health...", colors::BLUE) << "\n";
        if (!resolver.is_healthy())
        {
          std::cerr << colorize("⚠️  Warning: Cannot reach root servers. Resolution may fail.", colors::YELLOW + colors::BOLD) << "\n";
        }
        else
        {
          std::cout << colorize("✅ Resolver is healthy.", colors::GREEN) << "\n";
        }
        std::cout << "\n";
      }

      // Perform resolution
      if (options.resolve_all)
      {
        auto result = resolver.resolve_all(options.domain);
        print_resolution_result(result, options.domain, RecordType::A, options.verbose);
      }
      else
      {
        auto result = resolver.resolve(options.domain, options.query_type);
        print_resolution_result(result, options.domain, options.query_type, options.verbose);
      }

      // Print cache statistics if verbose
      if (options.verbose)
      {
        auto stats = resolver.get_cache_stats();
        std::cout << "\n"
                  << colorize("📈 Cache Statistics", colors::BOLD + colors::BLUE) << "\n";
        std::cout << colorize("━━━━━━━━━━━━━━━━━━", colors::GRAY) << "\n";
        std::cout << colorize("📦 Total entries: ", colors::GRAY)
                  << colorize(std::to_string(stats.total_entries), colors::CYAN) << "\n";

        double hit_ratio_percent = stats.hit_ratio * 100.0;
        std::string hit_ratio_color = hit_ratio_percent > 50 ? colors::GREEN : hit_ratio_percent > 20 ? colors::YELLOW
                                                                                                      : colors::RED;
        std::cout << colorize("🎯 Hit ratio: ", colors::GRAY)
                  << colorize(std::to_string(static_cast<int>(hit_ratio_percent)) + "%", hit_ratio_color) << "\n";
        std::cout << colorize("✅ Hits: ", colors::GRAY)
                  << colorize(std::to_string(stats.hit_count), colors::GREEN)
                  << colorize(", ❌ Misses: ", colors::GRAY)
                  << colorize(std::to_string(stats.miss_count), colors::RED) << "\n";
      }

      return 0;
    }
    catch (const NetworkException &e)
    {
      std::cerr << "Network error: " << e.what() << "\n";
      return 4;
    }
    catch (const DnsException &e)
    {
      std::cerr << "DNS error: " << e.what() << "\n";
      return 3;
    }
    catch (const std::exception &e)
    {
      std::cerr << "Error: " << e.what() << "\n";
      return 1;
    }
  }

} // namespace dns_resolver

int main(int argc, char *argv[])
{
  using namespace dns_resolver;

  auto options = parse_arguments(argc, argv);

  if (options.show_help)
  {
    print_usage(argv[0]);
    return 0;
  }

  if (options.show_version)
  {
    print_version();
    return 0;
  }

  if (options.domain.empty())
  {
    std::cerr << "Error: Domain name is required\n";
    std::cerr << "Use '" << argv[0] << " --help' for usage information\n";
    return 2;
  }

  // Validate domain name
  if (!utils::is_valid_domain_name(options.domain))
  {
    std::cerr << "Error: Invalid domain name: " << options.domain << "\n";
    return 2;
  }

  return run_resolver(options);
}