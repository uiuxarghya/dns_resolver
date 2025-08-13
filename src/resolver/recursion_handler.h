#pragma once

#include <memory>
#include <string>
#include <vector>

#include "types.h"
#include "utils.h"

namespace dns_resolver {

// Forward declarations
class QueryEngine;
class ResponseProcessor;

/**
 * @brief Handles DNS recursive resolution logic
 *
 * This class is responsible for:
 * - Managing the recursive resolution process
 * - Following referrals through the DNS hierarchy
 * - Handling CNAME resolution
 * - Managing recursion depth limits
 * - Resolving name servers
 */
class RecursionHandler {
public:
  /**
   * @brief Construct a new Recursion Handler
   * @param config Resolver configuration
   * @param query_engine Query engine for network operations
   * @param response_processor Response processor for parsing
   */
  RecursionHandler(const ResolverConfig& config, std::shared_ptr<QueryEngine> query_engine,
                   std::shared_ptr<ResponseProcessor> response_processor);

  /**
   * @brief Perform recursive resolution starting from given servers
   * @param domain Domain name to resolve
   * @param type Record type to query for
   * @param servers List of servers to query
   * @param depth Current recursion depth
   * @return Resolution result
   */
  ResolutionResult resolve_recursive(const std::string& domain, RecordType type,
                                     const std::vector<std::string>& servers, int depth = 0);

  /**
   * @brief Follow a CNAME record to its target
   * @param cname_target Target domain from CNAME record
   * @param type Original record type being queried
   * @param depth Current recursion depth
   * @return Resolution result for the CNAME target
   */
  ResolutionResult follow_cname(const std::string& cname_target, RecordType type, int depth);

  /**
   * @brief Resolve name servers to IP addresses
   * @param ns_names List of name server domain names
   * @param depth Current recursion depth
   * @return List of IP addresses for the name servers
   */
  std::vector<std::string> resolve_name_servers(const std::vector<std::string>& ns_names,
                                                int depth);

  /**
   * @brief Extract TLD from a domain name
   * @param domain Full domain name
   * @return TLD portion (e.g., "com" from "example.com")
   */
  std::string extract_tld(const std::string& domain);

  /**
   * @brief Select best servers from a list for querying
   * @param servers Available servers
   * @param max_servers Maximum number of servers to select
   * @return Selected servers
   */
  std::vector<std::string> select_best_servers(const std::vector<std::string>& servers,
                                               size_t max_servers);

private:
  ResolverConfig config_;  // Store by value instead of reference
  std::shared_ptr<QueryEngine> query_engine_;
  std::shared_ptr<ResponseProcessor> response_processor_;

  /**
   * @brief Log verbose message if verbose mode is enabled
   * @param message Message to log
   */
  void log_verbose(const std::string& message) const;
};

}  // namespace dns_resolver
