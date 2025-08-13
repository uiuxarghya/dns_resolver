#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace dns_resolver {

/**
 * @brief Result of a DNS resolution
 */
struct ResolutionResult {
  std::vector<std::string> addresses;            // Resolved IP addresses
  bool from_cache{false};                        // True if result came from cache
  std::chrono::milliseconds resolution_time{0};  // Time taken to resolve
  std::string error_message;                     // Error message if resolution failed
  bool success{false};                           // True if resolution was successful

  ResolutionResult() = default;

  explicit ResolutionResult(const std::vector<std::string> &addrs)
      : addresses(addrs), success(!addrs.empty()) {}
};

/**
 * @brief Configuration for the DNS resolver
 */
struct ResolverConfig {
  std::chrono::seconds query_timeout{5};       // Timeout for individual queries
  size_t max_cache_size{10000};                // Maximum cache entries
  int max_recursion_depth{16};                 // Maximum recursion depth
  bool enable_ipv6{true};                      // Enable IPv6 queries
  bool enable_caching{true};                   // Enable DNS caching
  bool enable_tcp_fallback{true};              // Enable TCP fallback for truncated responses
  size_t max_retries{3};                       // Maximum retries per server
  std::chrono::milliseconds retry_delay{100};  // Delay between retries
  bool verbose{false};                         // Enable verbose logging
};

}  // namespace dns_resolver
