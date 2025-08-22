#include "application.h"

#include <cstdlib>
#include <iostream>

#include "../config/config.h"
#include "../resolver/resolver.h"
#include "../resolver/utils.h"

namespace dns_resolver {

int Application::run_resolver(const CliOptions &options) {
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
      std::cout << OutputFormatter::colorize("✦ Starting DNS resolution in verbose mode",
                                             colors::BOLD + colors::GREEN)
                << "\n";
      std::cout << OutputFormatter::colorize(
                       "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                       "━━━━━━━━━",
                       colors::CYAN)
                << "\n";
      std::cout << OutputFormatter::colorize("➤ Target Domain: ", colors::GRAY)
                << OutputFormatter::colorize(options.domain, colors::YELLOW + colors::BOLD) << "\n";

      if (options.resolve_all) {
        std::cout << OutputFormatter::colorize("☰ Query Types: ", colors::GRAY)
                  << OutputFormatter::colorize("ALL", colors::CYAN + colors::BOLD) << "\n";
      } else {
        std::cout << OutputFormatter::colorize("☰ Query Type: ", colors::GRAY)
                  << OutputFormatter::colorize(utils::record_type_to_string(options.query_type),
                                               colors::CYAN + colors::BOLD)
                  << "\n";
      }

      std::cout << OutputFormatter::colorize("⧗ Timeout: ", colors::GRAY)
                << OutputFormatter::colorize(std::to_string(options.timeout.count()) + "s",
                                             colors::YELLOW + colors::BOLD)
                << "\n";
      std::cout << OutputFormatter::colorize("⚙ Mode: ", colors::GRAY)
                << OutputFormatter::colorize("Recursive Resolution", colors::GREEN + colors::BOLD)
                << "\n";
    }

    // Check if resolver is healthy
    if (options.verbose) {
      std::cout << "\n"
                << OutputFormatter::colorize("✚ System Health Check", colors::BOLD + colors::BLUE)
                << "\n";
      std::cout << OutputFormatter::colorize("━━━━━━━━━━━━━━━━━━━━━", colors::BLUE) << "\n";
      std::cout << OutputFormatter::colorize("⇄ Checking connectivity to root servers...",
                                             colors::GRAY)
                << "\n";

      if (!resolver.is_healthy()) {
        std::cout << OutputFormatter::colorize("⚠ Status: ", colors::GRAY)
                  << OutputFormatter::colorize("LIMITED", colors::YELLOW + colors::BOLD) << "\n";
        std::cout << OutputFormatter::colorize("ℹ Note: ", colors::GRAY)
                  << OutputFormatter::colorize(
                         "Cannot reach all root servers. Resolution may be slower.", colors::YELLOW)
                  << "\n";
      } else {
        std::cout << OutputFormatter::colorize("✔ Status: ", colors::GRAY)
                  << OutputFormatter::colorize("HEALTHY", colors::GREEN + colors::BOLD) << "\n";
        std::cout << OutputFormatter::colorize("ℹ Note: ", colors::GRAY)
                  << OutputFormatter::colorize("All systems operational.", colors::GREEN) << "\n";
      }
    }

    // Perform resolution
    if (options.resolve_all || options.query_type == RecordType::ANY) {
      std::vector<RecordType> all_types = {RecordType::A,   RecordType::AAAA,  RecordType::MX,
                                           RecordType::NS,  RecordType::CNAME, RecordType::TXT,
                                           RecordType::SOA, RecordType::SRV,   RecordType::PTR};
      CombinedResolutionResult combined_result;
      std::vector<std::string> type_labels;

      for (auto type : all_types) {
        auto result = resolver.resolve(options.domain, type);
        if (result.success && !result.addresses.empty()) {
          for (const auto &addr : result.addresses) {
            combined_result.records.push_back({addr, type});
          }
          type_labels.push_back(utils::record_type_to_string(type));
        }
      }

      combined_result.success = !combined_result.records.empty();
      combined_result.resolution_time = std::chrono::milliseconds(0);  // Could be improved

      std::string combined_type_label;
      for (size_t i = 0; i < type_labels.size(); ++i) {
        if (i > 0) combined_type_label += " + ";
        combined_type_label += type_labels[i];
      }

      OutputFormatter::print_combined_resolution_result(combined_result, options.domain,
                                                        options.verbose, combined_type_label);
    } else if (options.query_type == RecordType::CNAME) {
      // For CNAME queries, try fallback to SOA then NS if no CNAME exists
      auto result = resolver.resolve(options.domain, RecordType::CNAME);
      if (result.success && !result.addresses.empty()) {
        OutputFormatter::print_resolution_result(result, options.domain, RecordType::CNAME,
                                                 options.verbose);
      } else {
        std::cout << OutputFormatter::colorize("No CNAME record found. Trying SOA...\n",
                                               colors::YELLOW);
        auto soa_result = resolver.resolve(options.domain, RecordType::SOA);
        if (soa_result.success && !soa_result.addresses.empty()) {
          OutputFormatter::print_resolution_result(soa_result, options.domain, RecordType::SOA,
                                                   options.verbose);
        } else {
          std::cout << OutputFormatter::colorize("No SOA record found. Trying NS...\n",
                                                 colors::YELLOW);
          auto ns_result = resolver.resolve(options.domain, RecordType::NS);
          if (ns_result.success && !ns_result.addresses.empty()) {
            OutputFormatter::print_resolution_result(ns_result, options.domain, RecordType::NS,
                                                     options.verbose);
          } else {
            std::cout << OutputFormatter::colorize(
                "No CNAME, SOA, or NS records found for this domain.\n",
                colors::RED + colors::BOLD);
          }
        }
      }
    } else {
      auto result = resolver.resolve(options.domain, options.query_type);
      OutputFormatter::print_resolution_result(result, options.domain, options.query_type,
                                               options.verbose);
    }

    // Print cache statistics if verbose
    if (options.verbose) {
      auto stats = resolver.get_cache_stats();
      std::cout << "\n"
                << OutputFormatter::colorize("▣ Cache Performance", colors::BOLD + colors::MAGENTA)
                << "\n";
      std::cout << OutputFormatter::colorize("━━━━━━━━━━━━━━━━━━━━", colors::MAGENTA) << "\n";

      std::cout << OutputFormatter::colorize("⬚ Cache Entries: ", colors::GRAY)
                << OutputFormatter::colorize(std::to_string(stats.total_entries),
                                             colors::CYAN + colors::BOLD)
                << "\n";

      double hit_ratio_percent = stats.hit_ratio * 100.0;
      std::string hit_ratio_color = hit_ratio_percent > 70   ? colors::GREEN + colors::BOLD
                                    : hit_ratio_percent > 40 ? colors::YELLOW + colors::BOLD
                                                             : colors::RED + colors::BOLD;

      std::cout << OutputFormatter::colorize("➤ Hit Ratio: ", colors::GRAY)
                << OutputFormatter::colorize(
                       std::to_string(static_cast<int>(hit_ratio_percent)) + "%", hit_ratio_color);

      // Add performance indicator
      if (hit_ratio_percent > 70) {
        std::cout << OutputFormatter::colorize(" (Excellent)", colors::GREEN);
      } else if (hit_ratio_percent > 40) {
        std::cout << OutputFormatter::colorize(" (Good)", colors::YELLOW);
      } else if (stats.hit_count + stats.miss_count > 0) {
        std::cout << OutputFormatter::colorize(" (Poor)", colors::RED);
      }
      std::cout << "\n";

      std::cout << OutputFormatter::colorize("✔ Cache Hits: ", colors::GRAY)
                << OutputFormatter::colorize(std::to_string(stats.hit_count),
                                             colors::GREEN + colors::BOLD)
                << "\n";
      std::cout << OutputFormatter::colorize("✘ Cache Misses: ", colors::GRAY)
                << OutputFormatter::colorize(std::to_string(stats.miss_count),
                                             colors::RED + colors::BOLD)
                << "\n";

      // Add efficiency note
      if (stats.hit_count + stats.miss_count > 0) {
        std::cout << OutputFormatter::colorize("✧ Efficiency: ", colors::GRAY);
        if (hit_ratio_percent > 70) {
          std::cout << OutputFormatter::colorize("Cache is performing excellently", colors::GREEN)
                    << "\n";
        } else if (hit_ratio_percent > 40) {
          std::cout << OutputFormatter::colorize("Cache is working well", colors::YELLOW) << "\n";
        } else {
          std::cout << OutputFormatter::colorize("Consider increasing cache size", colors::RED)
                    << "\n";
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

CombinedResolutionResult Application::convert_to_combined_result(const ResolutionResult &result,
                                                                 RecordType type) {
  CombinedResolutionResult combined_result;
  combined_result.success = result.success;
  combined_result.resolution_time = result.resolution_time;
  combined_result.from_cache = result.from_cache;
  combined_result.error_message = result.error_message;

  for (const auto &addr : result.addresses) {
    combined_result.records.push_back({addr, type});
  }

  return combined_result;
}

std::string Application::get_type_label(RecordType type) {
  return utils::record_type_to_string(type);
}

bool Application::is_valid_domain(const std::string &domain) {
  return utils::is_valid_domain_name(domain);
}

}  // namespace dns_resolver
