#pragma once

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include "../config/config.h"
#include "cache.h"
#include "packet_builder.h"
#include "packet_parser.h"
#include "types.h"
#include "utils.h"

namespace dns_resolver {

// Forward declarations
class UdpClient;
class TcpClient;
class QueryEngine;
class RecursionHandler;
class ResponseProcessor;

/**
 * @brief Recursive DNS resolver implementation
 *
 * This class implements a complete recursive DNS resolver that:
 * - Starts queries from root servers
 * - Follows referrals through the DNS hierarchy
 * - Handles CNAME following and alias resolution
 * - Implements intelligent caching with TTL management
 * - Supports both UDP and TCP transport
 * - Provides thread-safe concurrent resolution
 */
class Resolver {
public:
  /**
   * @brief Construct a new Resolver with default configuration
   */
  Resolver();

  /**
   * @brief Construct a new Resolver with custom configuration
   * @param config Resolver configuration
   */
  explicit Resolver(const ResolverConfig &config);

  /**
   * @brief Destructor
   */
  ~Resolver();

  // Disable copy constructor and assignment operator
  Resolver(const Resolver &) = delete;
  Resolver &operator=(const Resolver &) = delete;

  // Enable move constructor and assignment operator
  Resolver(Resolver &&) = default;
  Resolver &operator=(Resolver &&) = default;

  /**
   * @brief Resolve a domain name to IP addresses
   * @param domain Domain name to resolve
   * @param type Record type to query for (A or AAAA)
   * @return Resolution result containing IP addresses or error information
   */
  ResolutionResult resolve(const std::string &domain, RecordType type = RecordType::A);

  /**
   * @brief Resolve a domain name asynchronously
   * @param domain Domain name to resolve
   * @param type Record type to query for
   * @return Future containing the resolution result
   */
  std::future<ResolutionResult> resolve_async(const std::string &domain,
                                              RecordType type = RecordType::A);

  /**
   * @brief Resolve both A and AAAA records for a domain
   * @param domain Domain name to resolve
   * @return Resolution result containing both IPv4 and IPv6 addresses
   */
  ResolutionResult resolve_all(const std::string &domain);

  /**
   * @brief Clear the DNS cache
   */
  void clear_cache();

  /**
   * @brief Get cache statistics
   * @return Cache statistics
   */
  DnsCache::CacheStats get_cache_stats() const;

  /**
   * @brief Update resolver configuration
   * @param config New configuration
   */
  void update_config(const ResolverConfig &config);

  /**
   * @brief Get current resolver configuration
   * @return Current configuration
   */
  const ResolverConfig &get_config() const { return config_; }

  /**
   * @brief Check if the resolver is healthy (can reach root servers)
   * @return True if the resolver can reach at least one root server
   */
  bool is_healthy();

private:
  ResolverConfig config_;
  std::unique_ptr<DnsCache> cache_;
  std::unique_ptr<UdpClient> udp_client_;
  std::unique_ptr<TcpClient> tcp_client_;

  // Modular components
  std::shared_ptr<QueryEngine> query_engine_;
  std::shared_ptr<ResponseProcessor> response_processor_;
  std::shared_ptr<RecursionHandler> recursion_handler_;

  /**
   * @brief Check cache for a domain/type combination
   * @param domain Domain name
   * @param type Record type
   * @return Cached result if available, nullopt otherwise
   */
  std::optional<ResolutionResult> check_cache(const std::string &domain, RecordType type);

  /**
   * @brief Store result in cache
   * @param domain Domain name
   * @param type Record type
   * @param result Resolution result to cache
   * @param ttl TTL for the cache entry
   */
  void store_in_cache(const std::string &domain, RecordType type, const ResolutionResult &result,
                      int ttl);

  /**
   * @brief Log a message if verbose mode is enabled
   * @param message Message to log
   */
  void log_verbose(const std::string &message) const;
};

/**
 * @brief Convenience functions for common resolution tasks
 */
namespace resolver_utils {

/**
 * @brief Create a resolver with optimized settings for fast resolution
 * @return Resolver configured for speed
 */
std::unique_ptr<Resolver> create_fast_resolver();

/**
 * @brief Create a resolver with optimized settings for performance
 * @return Resolver configured for high performance
 */
std::unique_ptr<Resolver> create_performance_resolver();

/**
 * @brief Create a resolver with optimized settings for reliability
 * @return Resolver configured for maximum reliability
 */
std::unique_ptr<Resolver> create_reliable_resolver();

/**
 * @brief Resolve a domain name using a temporary resolver instance
 * @param domain Domain name to resolve
 * @param type Record type to query for
 * @return Resolution result
 */
ResolutionResult quick_resolve(const std::string &domain, RecordType type = RecordType::A);

/**
 * @brief Check if a domain name exists (returns any record type)
 * @param domain Domain name to check
 * @return True if the domain exists
 */
bool domain_exists(const std::string &domain);

}  // namespace resolver_utils

}  // namespace dns_resolver
