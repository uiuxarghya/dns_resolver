#pragma once

#include "utils.h"
#include "cache.h"
#include "packet_builder.h"
#include "packet_parser.h"
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <future>

namespace dns_resolver
{

  // Forward declarations
  class UdpClient;
  class TcpClient;

  /**
   * @brief Configuration for the DNS resolver
   */
  struct ResolverConfig
  {
    std::chrono::seconds query_timeout{5};      // Timeout for individual queries
    size_t max_cache_size{10000};               // Maximum cache entries
    int max_recursion_depth{16};                // Maximum recursion depth
    bool enable_ipv6{true};                     // Enable IPv6 queries
    bool enable_caching{true};                  // Enable DNS caching
    bool enable_tcp_fallback{true};             // Enable TCP fallback for truncated responses
    size_t max_retries{3};                      // Maximum retries per server
    std::chrono::milliseconds retry_delay{100}; // Delay between retries
    bool verbose{false};                        // Enable verbose logging
  };

  /**
   * @brief Result of a DNS resolution
   */
  struct ResolutionResult
  {
    std::vector<std::string> addresses;           // Resolved IP addresses
    bool from_cache{false};                       // True if result came from cache
    std::chrono::milliseconds resolution_time{0}; // Time taken to resolve
    std::string error_message;                    // Error message if resolution failed
    bool success{false};                          // True if resolution was successful

    ResolutionResult() = default;

    explicit ResolutionResult(const std::vector<std::string> &addrs)
        : addresses(addrs), success(!addrs.empty()) {}
  };

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
  class Resolver
  {
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

    /**
     * @brief Perform recursive resolution starting from root servers
     * @param domain Domain name to resolve
     * @param type Record type to query for
     * @param servers List of servers to query
     * @param depth Current recursion depth
     * @return Resolution result
     */
    ResolutionResult resolve_recursive(const std::string &domain, RecordType type,
                                       const std::vector<std::string> &servers, int depth = 0);

    /**
     * @brief Query a specific DNS server
     * @param server Server IP address
     * @param domain Domain name to query
     * @param type Record type to query for
     * @param use_tcp Force TCP usage
     * @return DNS response packet, or empty vector on failure
     */
    std::vector<uint8_t> query_server(const std::string &server, const std::string &domain,
                                      RecordType type, bool use_tcp = false);

    /**
     * @brief Process a DNS response and extract relevant information
     * @param response DNS response packet
     * @param domain Original domain queried
     * @param type Record type queried
     * @return Processing result with addresses, referrals, or CNAME targets
     */
    struct ProcessResult
    {
      std::vector<std::string> addresses;
      std::vector<std::string> referral_servers;
      std::string cname_target;
      bool is_authoritative{false};
      bool has_answer{false};
      ResponseCode rcode{ResponseCode::NO_ERROR};
    };

    ProcessResult process_response(const std::vector<uint8_t> &response,
                                   const std::string &domain, RecordType type);

    /**
     * @brief Follow CNAME records to find the final target
     * @param cname_target Initial CNAME target
     * @param type Record type to resolve for the final target
     * @param depth Current recursion depth
     * @return Resolution result for the final target
     */
    ResolutionResult follow_cname(const std::string &cname_target, RecordType type, int depth);

    /**
     * @brief Extract glue records (A/AAAA records in additional section)
     * @param response DNS response packet
     * @param ns_names List of name server names to find glue records for
     * @return List of IP addresses for the name servers
     */
    std::vector<std::string> extract_glue_records(const std::vector<uint8_t> &response,
                                                  const std::vector<std::string> &ns_names);

    /**
     * @brief Resolve name servers to IP addresses
     * @param ns_names List of name server domain names
     * @param depth Current recursion depth
     * @return List of IP addresses for the name servers
     */
    std::vector<std::string> resolve_name_servers(const std::vector<std::string> &ns_names,
                                                  int depth);

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
    void store_in_cache(const std::string &domain, RecordType type,
                        const ResolutionResult &result, uint32_t ttl);

    /**
     * @brief Generate a unique query ID
     * @return 16-bit query ID
     */
    uint16_t generate_query_id();

    /**
     * @brief Log a message if verbose mode is enabled
     * @param message Message to log
     */
    void log_verbose(const std::string &message) const;

    /**
     * @brief Validate domain name format
     * @param domain Domain name to validate
     * @return True if the domain name is valid
     */
    bool is_valid_domain(const std::string &domain) const;

    /**
     * @brief Select the best servers from a list (prefer IPv4, then IPv6)
     * @param servers List of server IP addresses
     * @param max_servers Maximum number of servers to return
     * @return Filtered and ordered list of servers
     */
    std::vector<std::string> select_best_servers(const std::vector<std::string> &servers,
                                                 size_t max_servers = 3);
  };

  /**
   * @brief Convenience functions for common resolution tasks
   */
  namespace resolver_utils
  {

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

  } // namespace resolver_utils

} // namespace dns_resolver
