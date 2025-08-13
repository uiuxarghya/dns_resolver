#pragma once

#include <optional>
#include <string>
#include <vector>

#include "types.h"
#include "utils.h"

namespace dns_resolver {

/**
 * @brief Result of processing a DNS response
 */
struct ProcessResult {
  std::vector<std::string> addresses;
  std::vector<std::string> referral_servers;
  std::string cname_target;
  bool is_authoritative{false};
  bool has_answer{false};
  ResponseCode rcode{ResponseCode::NO_ERROR};
};

/**
 * @brief Handles DNS response processing and parsing
 *
 * This class is responsible for:
 * - Parsing DNS response packets
 * - Extracting IP addresses from answer sections
 * - Processing referrals and authority sections
 * - Handling CNAME records
 * - Extracting glue records
 */
class ResponseProcessor {
public:
  /**
   * @brief Construct a new Response Processor
   * @param config Resolver configuration
   */
  explicit ResponseProcessor(const ResolverConfig& config);

  /**
   * @brief Process a DNS response packet
   * @param response Raw DNS response packet
   * @param domain Original domain queried
   * @param type Record type queried
   * @param depth Current recursion depth
   * @return Processing result with addresses, referrals, or CNAME targets
   */
  ProcessResult process_response(const std::vector<uint8_t>& response, const std::string& domain,
                                 RecordType type, int depth);

  /**
   * @brief Extract domain name from RDATA field
   * @param rdata RDATA bytes
   * @param full_packet Complete DNS packet for compression resolution
   * @return Extracted domain name
   */
  std::string extract_domain_name_from_rdata(const std::vector<uint8_t>& rdata,
                                             const std::vector<uint8_t>& full_packet);

  /**
   * @brief Extract domain name from name field
   * @param name_field Name field bytes
   * @param full_packet Complete DNS packet for compression resolution
   * @return Extracted domain name
   */
  std::string extract_domain_name_from_name_field(const std::vector<uint8_t>& name_field,
                                                  const std::vector<uint8_t>& full_packet);

  /**
   * @brief Parse domain name with compression support
   * @param data Packet data
   * @param start_offset Starting offset in packet
   * @param full_packet Complete DNS packet for compression resolution
   * @return Parsed domain name
   */
  std::string parse_domain_name_with_compression(const std::vector<uint8_t>& data,
                                                 size_t start_offset,
                                                 const std::vector<uint8_t>& full_packet);

  /**
   * @brief Parse SOA record
   * @param rdata SOA record data
   * @param full_packet Complete DNS packet for compression resolution
   * @return Formatted SOA record string
   */
  std::string parse_soa_record(const std::vector<uint8_t>& rdata,
                               const std::vector<uint8_t>& full_packet);

  /**
   * @brief Parse SRV record
   * @param rdata SRV record data
   * @param full_packet Complete DNS packet for compression resolution
   * @return Formatted SRV record string
   */
  std::string parse_srv_record(const std::vector<uint8_t>& rdata,
                               const std::vector<uint8_t>& full_packet);

  /**
   * @brief Skip domain name in packet data
   * @param data Packet data
   * @param start_pos Starting position
   * @return Position after domain name
   */
  size_t skip_domain_name(const std::vector<uint8_t>& data, size_t start_pos);

private:
  ResolverConfig config_;  // Store by value instead of reference

  /**
   * @brief Log verbose message if verbose mode is enabled
   * @param message Message to log
   */
  void log_verbose(const std::string& message) const;
};

}  // namespace dns_resolver
