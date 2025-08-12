#include "resolver/resolver.h"
#include "resolver/utils.h"
#include "config/config.h"
#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>
#include <cstdlib>

namespace dns_resolver
{

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
    std::cout << "Usage: " << program_name << " [OPTIONS] <domain>\n\n";
    std::cout << "DNS Resolver - A recursive DNS resolver written in modern C++ (C++23)\n\n";
    std::cout << "Options:\n";
    std::cout << "  -t, --type TYPE     Query type (A, AAAA, TXT, MX, NS, CNAME, SOA, ANY) [default: A]\n";
    std::cout << "  -v, --verbose       Show detailed resolution path\n";
    std::cout << "  -a, --all           Resolve both A and AAAA records\n";
    std::cout << "  -T, --timeout SEC   Query timeout in seconds [default: 5]\n";
    std::cout << "  -h, --help          Show this help message\n";
    std::cout << "      --version       Show version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " example.com\n";
    std::cout << "  " << program_name << " -v -t AAAA example.com\n";
    std::cout << "  " << program_name << " --all example.com\n\n";
    std::cout << "Exit codes:\n";
    std::cout << "  0  Success\n";
    std::cout << "  1  General error\n";
    std::cout << "  2  Invalid arguments\n";
    std::cout << "  3  DNS resolution failed\n";
    std::cout << "  4  Network error\n";
  }

  void print_version()
  {
    std::cout << config::APPLICATION_NAME << " " << config::APPLICATION_VERSION << "\n";
    std::cout << "Author: " << config::APPLICATION_AUTHOR << "\n";
    std::cout << "A recursive DNS resolver written in modern C++ (C++23)\n";
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
      std::cerr << "Resolution failed for " << domain;
      if (!result.error_message.empty())
      {
        std::cerr << ": " << result.error_message;
      }
      std::cerr << "\n";
      return;
    }

    if (verbose)
    {
      std::cout << "Resolution for " << domain << " (" << utils::record_type_to_string(type) << "):\n";
      std::cout << "Time taken: " << result.resolution_time.count() << " ms\n";
      std::cout << "From cache: " << (result.from_cache ? "yes" : "no") << "\n";
      std::cout << "Addresses found: " << result.addresses.size() << "\n\n";
    }

    for (const auto &address : result.addresses)
    {
      std::cout << address << "\n";
    }

    if (verbose && !result.addresses.empty())
    {
      std::cout << "\nResolution completed successfully.\n";
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

      // Check if resolver is healthy
      if (options.verbose)
      {
        std::cout << "Checking resolver health...\n";
        if (!resolver.is_healthy())
        {
          std::cerr << "Warning: Cannot reach root servers. Resolution may fail.\n";
        }
        else
        {
          std::cout << "Resolver is healthy.\n";
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
        std::cout << "\nCache Statistics:\n";
        std::cout << "Total entries: " << stats.total_entries << "\n";
        std::cout << "Hit ratio: " << (stats.hit_ratio * 100.0) << "%\n";
        std::cout << "Hits: " << stats.hit_count << ", Misses: " << stats.miss_count << "\n";
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
