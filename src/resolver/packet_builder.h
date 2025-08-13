#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "utils.h"

namespace dns_resolver {

/**
 * @brief DNS packet builder for creating DNS query and response packets
 *
 * This class provides a fluent interface for building DNS packets according to RFC 1035.
 * It handles proper encoding of domain names, including compression, and ensures
 * correct byte ordering for network transmission.
 */
class PacketBuilder {
public:
  /**
   * @brief Construct a new PacketBuilder
   */
  PacketBuilder();

  /**
   * @brief Set the query ID in the DNS header
   * @param id 16-bit query identifier
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &set_id(uint16_t id);

  /**
   * @brief Set the flags field in the DNS header
   * @param flags 16-bit flags field
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &set_flags(uint16_t flags);

  /**
   * @brief Set individual flag bits in the DNS header
   * @param is_response True if this is a response packet
   * @param opcode Operation code (0 for standard query)
   * @param authoritative True if this is an authoritative answer
   * @param truncated True if the response was truncated
   * @param recursion_desired True if recursion is desired
   * @param recursion_available True if recursion is available
   * @param rcode Response code
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &set_flags(bool is_response, uint8_t opcode, bool authoritative, bool truncated,
                           bool recursion_desired, bool recursion_available, uint8_t rcode);

  /**
   * @brief Add a question to the DNS packet
   * @param name Domain name to query
   * @param type Record type to query for
   * @param cls Record class (usually IN for Internet)
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &add_question(const std::string &name, RecordType type, RecordClass cls);

  /**
   * @brief Add an answer resource record to the DNS packet
   * @param name Domain name
   * @param type Record type
   * @param cls Record class
   * @param ttl Time to live in seconds
   * @param rdata Resource data
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &add_answer(const std::string &name, RecordType type, RecordClass cls, uint32_t ttl,
                            const std::vector<uint8_t> &rdata);

  /**
   * @brief Add an authority resource record to the DNS packet
   * @param name Domain name
   * @param type Record type
   * @param cls Record class
   * @param ttl Time to live in seconds
   * @param rdata Resource data
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &add_authority(const std::string &name, RecordType type, RecordClass cls,
                               uint32_t ttl, const std::vector<uint8_t> &rdata);

  /**
   * @brief Add an additional resource record to the DNS packet
   * @param name Domain name
   * @param type Record type
   * @param cls Record class
   * @param ttl Time to live in seconds
   * @param rdata Resource data
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &add_additional(const std::string &name, RecordType type, RecordClass cls,
                                uint32_t ttl, const std::vector<uint8_t> &rdata);

  /**
   * @brief Add EDNS(0) OPT record for extended DNS capabilities
   * @param udp_payload_size Maximum UDP payload size client can handle
   * @param extended_rcode Extended response code (usually 0)
   * @param version EDNS version (should be 0)
   * @param flags EDNS flags (e.g., DO bit for DNSSEC)
   * @return Reference to this builder for method chaining
   */
  PacketBuilder &add_edns0_opt(uint16_t udp_payload_size = 4096, uint8_t extended_rcode = 0,
                               uint8_t version = 0, uint16_t flags = 0);

  /**
   * @brief Build the final DNS packet
   * @return Vector of bytes representing the complete DNS packet
   * @throws ProtocolException if the packet cannot be built
   */
  std::vector<uint8_t> build();

  /**
   * @brief Reset the builder to its initial state
   */
  void reset();

  /**
   * @brief Get the current packet size (useful for checking limits)
   * @return Current size of the packet being built
   */
  size_t get_current_size() const;

  /**
   * @brief Check if compression is enabled
   * @return True if name compression is enabled
   */
  bool is_compression_enabled() const { return compression_enabled_; }

  /**
   * @brief Enable or disable name compression
   * @param enabled True to enable compression, false to disable
   */
  void set_compression_enabled(bool enabled) { compression_enabled_ = enabled; }

private:
  DnsHeader header_;
  std::vector<DnsQuestion> questions_;
  std::vector<ResourceRecord> answers_;
  std::vector<ResourceRecord> authorities_;
  std::vector<ResourceRecord> additionals_;

  // Name compression support
  bool compression_enabled_;
  std::unordered_map<std::string, size_t> compression_map_;

  /**
   * @brief Encode a domain name with optional compression
   * @param name Domain name to encode
   * @param buffer Buffer to write encoded name to
   * @param allow_compression Whether to use compression for this name
   */
  void encode_name(const std::string &name, std::vector<uint8_t> &buffer,
                   bool allow_compression = true);

  /**
   * @brief Write a 16-bit value in network byte order
   * @param value Value to write
   * @param buffer Buffer to write to
   */
  void write_uint16(uint16_t value, std::vector<uint8_t> &buffer);

  /**
   * @brief Write a 32-bit value in network byte order
   * @param value Value to write
   * @param buffer Buffer to write to
   */
  void write_uint32(uint32_t value, std::vector<uint8_t> &buffer);

  /**
   * @brief Write a resource record to the buffer
   * @param rr Resource record to write
   * @param buffer Buffer to write to
   */
  void write_resource_record(const ResourceRecord &rr, std::vector<uint8_t> &buffer);

  /**
   * @brief Validate domain name according to RFC 1035 rules
   * @param name Domain name to validate
   * @throws ProtocolException if the name is invalid
   */
  void validate_domain_name(const std::string &name);

  /**
   * @brief Add a compression entry for a domain name
   * @param name Domain name
   * @param offset Offset in the packet where the name starts
   */
  void add_compression_entry(const std::string &name, size_t offset);

  /**
   * @brief Find a compression target for a domain name
   * @param name Domain name to find compression for
   * @param offset Output parameter for the compression offset
   * @return True if a compression target was found
   */
  bool find_compression_target(const std::string &name, size_t &offset);

  /**
   * @brief Split a domain name into labels
   * @param name Domain name to split
   * @return Vector of labels
   */
  std::vector<std::string> split_domain_name(const std::string &name);
};

/**
 * @brief Convenience functions for creating common DNS packets
 */
namespace packet_builders {

/**
 * @brief Create a standard DNS query packet
 * @param id Query ID
 * @param domain Domain name to query
 * @param type Record type to query for
 * @param recursion_desired Whether to request recursion
 * @return DNS query packet bytes
 */
std::vector<uint8_t> create_query(uint16_t id, const std::string &domain, RecordType type,
                                  bool recursion_desired = true);

/**
 * @brief Create a DNS response packet with a single A record
 * @param query_id Original query ID
 * @param domain Domain name
 * @param ipv4_address IPv4 address as a string
 * @param ttl Time to live
 * @param authoritative Whether this is an authoritative response
 * @return DNS response packet bytes
 */
std::vector<uint8_t> create_a_response(uint16_t query_id, const std::string &domain,
                                       const std::string &ipv4_address, uint32_t ttl,
                                       bool authoritative = true);

/**
 * @brief Create a DNS response packet with a single AAAA record
 * @param query_id Original query ID
 * @param domain Domain name
 * @param ipv6_address IPv6 address as a string
 * @param ttl Time to live
 * @param authoritative Whether this is an authoritative response
 * @return DNS response packet bytes
 */
std::vector<uint8_t> create_aaaa_response(uint16_t query_id, const std::string &domain,
                                          const std::string &ipv6_address, uint32_t ttl,
                                          bool authoritative = true);

/**
 * @brief Create a DNS error response
 * @param query_id Original query ID
 * @param rcode Response code indicating the error
 * @return DNS error response packet bytes
 */
std::vector<uint8_t> create_error_response(uint16_t query_id, ResponseCode rcode);

}  // namespace packet_builders

}  // namespace dns_resolver
