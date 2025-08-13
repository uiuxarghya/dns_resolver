#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "types.h"
#include "utils.h"

namespace dns_resolver {

// Forward declarations
class UdpClient;
class TcpClient;

/**
 * @brief Handles DNS query execution and network communication
 *
 * This class is responsible for:
 * - Executing DNS queries against specific servers
 * - Managing UDP/TCP transport protocols
 * - Handling query timeouts and retries
 * - Generating query packets
 */
class QueryEngine {
public:
  /**
   * @brief Construct a new Query Engine
   * @param config Resolver configuration
   */
  explicit QueryEngine(const ResolverConfig& config);

  /**
   * @brief Destructor
   */
  ~QueryEngine();

  /**
   * @brief Query a DNS server for a specific domain and record type
   * @param server Server IP address to query
   * @param domain Domain name to query
   * @param type Record type to query for
   * @param use_tcp Whether to use TCP instead of UDP
   * @return Raw DNS response packet, empty if query failed
   */
  std::vector<uint8_t> query_server(const std::string& server, const std::string& domain,
                                    RecordType type, bool use_tcp = false);

  /**
   * @brief Update configuration
   * @param config New configuration
   */
  void update_config(const ResolverConfig& config);

  /**
   * @brief Generate a unique query ID
   * @return 16-bit query ID
   */
  uint16_t generate_query_id();

private:
  ResolverConfig config_;  // Store by value instead of reference
  std::unique_ptr<UdpClient> udp_client_;
  std::unique_ptr<TcpClient> tcp_client_;

  /**
   * @brief Log verbose message if verbose mode is enabled
   * @param message Message to log
   */
  void log_verbose(const std::string& message) const;
};

}  // namespace dns_resolver
