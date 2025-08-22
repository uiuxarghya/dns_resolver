#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "utils.h"

namespace dns_resolver {

/**
 * @brief DNS packet parser for parsing DNS query and response packets
 *
 * This class provides functionality to parse DNS packets according to RFC 1035.
 * It handles proper decoding of domain names, including decompression, and ensures
 * correct interpretation of network byte order data.
 */
class PacketParser {
public:
  /**
   * @brief Construct a new PacketParser
   * @param packet Raw packet bytes to parse
   */
  explicit PacketParser(const std::vector<uint8_t> &packet);

  /**
   * @brief Parse the complete DNS message
   * @return Parsed DNS message structure
   * @throws ParseException if the packet is malformed
   */
  DnsMessage parse();

  /**
   * @brief Parse only the DNS header
   * @return Parsed DNS header
   * @throws ParseException if the header is malformed
   */
  DnsHeader parse_header();

  /**
   * @brief Check if the packet is a valid DNS packet
   * @return True if the packet appears to be valid
   */
  bool is_valid_packet() const;

  /**
   * @brief Get the size of the packet being parsed
   * @return Size of the packet in bytes
   */
  size_t get_packet_size() const { return packet_.size(); }

  /**
   * @brief Check if there are more bytes to read
   * @return True if there are more bytes available
   */
  bool has_more_data() const { return offset_ < packet_.size(); }

  /**
   * @brief Get the current parsing offset
   * @return Current offset in the packet
   */
  size_t get_offset() const { return offset_; }

  /**
   * @brief Reset the parser to the beginning of the packet
   */
  void reset() { offset_ = 0; }

  /**
   * @brief Decode a domain name from the packet, handling compression
   * @return Decoded domain name
   * @throws ParseException if the name is malformed or contains loops
   */
  std::string decode_name();

private:
  const std::vector<uint8_t> &packet_;
  mutable size_t offset_;

  /**
   * @brief Read a 16-bit value from the packet in network byte order
   * @return 16-bit value in host byte order
   * @throws ParseException if there are insufficient bytes
   */
  uint16_t read_uint16();

  /**
   * @brief Read a 32-bit value from the packet in network byte order
   * @return 32-bit value in host byte order
   * @throws ParseException if there are insufficient bytes
   */
  uint32_t read_uint32();

  /**
   * @brief Read a single byte from the packet
   * @return Byte value
   * @throws ParseException if there are insufficient bytes
   */
  uint8_t read_uint8();

  /**
   * @brief Read a sequence of bytes from the packet
   * @param length Number of bytes to read
   * @return Vector of bytes
   * @throws ParseException if there are insufficient bytes
   */
  std::vector<uint8_t> read_bytes(size_t length);

  /**
   * @brief Decode a domain name starting at a specific offset (for compression)
   * @param start_offset Offset to start decoding from
   * @param visited Set of visited offsets to detect loops
   * @return Decoded domain name
   * @throws ParseException if the name is malformed or contains loops
   */
  std::string decode_name_at_offset(size_t start_offset, std::vector<size_t> &visited) const;

  /**
   * @brief Parse a DNS question from the packet
   * @return Parsed DNS question
   * @throws ParseException if the question is malformed
   */
  DnsQuestion parse_question();

  /**
   * @brief Parse a DNS resource record from the packet
   * @return Parsed resource record
   * @throws ParseException if the resource record is malformed
   */
  ResourceRecord parse_resource_record();

  /**
   * @brief Check if we have enough bytes remaining for a read operation
   * @param bytes_needed Number of bytes needed
   * @throws ParseException if there are insufficient bytes
   */
  void ensure_bytes_available(size_t bytes_needed) const;

  /**
   * @brief Validate that an offset is within packet bounds
   * @param offset Offset to validate
   * @throws ParseException if the offset is out of bounds
   */
  void validate_offset(size_t offset) const;

  /**
   * @brief Check for compression pointer loops
   * @param offset Current offset
   * @param visited Vector of previously visited offsets
   * @return True if this offset was already visited (indicating a loop)
   */
  bool is_compression_loop(size_t offset, const std::vector<size_t> &visited) const;
};

/**
 * @brief Utility functions for packet parsing
 */
namespace packet_parsers {

/**
 * @brief Quick check if a packet is a DNS response
 * @param packet Raw packet bytes
 * @return True if the packet appears to be a DNS response
 */
bool is_dns_response(const std::vector<uint8_t> &packet);

/**
 * @brief Extract the query ID from a DNS packet
 * @param packet Raw packet bytes
 * @return Query ID, or nullopt if the packet is too short
 */
std::optional<uint16_t> extract_query_id(const std::vector<uint8_t> &packet);

/**
 * @brief Extract the response code from a DNS packet
 * @param packet Raw packet bytes
 * @return Response code, or nullopt if the packet is too short
 */
std::optional<ResponseCode> extract_response_code(const std::vector<uint8_t> &packet);

/**
 * @brief Check if a DNS response is truncated (TC bit set)
 * @param packet Raw packet bytes
 * @return True if the response is truncated
 */
bool is_truncated_response(const std::vector<uint8_t> &packet);

/**
 * @brief Extract all A records from a DNS response
 * @param packet Raw packet bytes
 * @return Vector of IPv4 addresses as strings
 */
std::vector<std::string> extract_a_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract all AAAA records from a DNS response
 * @param packet Raw packet bytes
 * @return Vector of IPv6 addresses as strings
 */
std::vector<std::string> extract_aaaa_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract all CNAME records from a DNS response
 * @param packet Raw packet bytes
 * @return Vector of canonical names
 */
std::vector<std::string> extract_cname_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract all NS records from a DNS response
 * @param packet Raw packet bytes
 * @return Vector of name server names
 */
std::vector<std::string> extract_ns_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract NS records from the authority section (for referrals)
 * @param packet Raw packet bytes
 * @return Vector of name server names from authority section
 */
std::vector<std::string> extract_authority_ns_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract A records from the additional section (glue records)
 * @param packet Raw packet bytes
 * @return Vector of IPv4 addresses from additional section
 */
std::vector<std::string> extract_additional_a_records(const std::vector<uint8_t> &packet);

/**
 * @brief Extract AAAA records from the additional section (glue records)
 * @param packet Raw packet bytes
 * @return Vector of IPv6 addresses from additional section
 */
std::vector<std::string> extract_additional_aaaa_records(const std::vector<uint8_t> &packet);

/**
 * @brief Validate packet structure without full parsing
 * @param packet Raw packet bytes
 * @return True if the packet structure appears valid
 */
bool validate_packet_structure(const std::vector<uint8_t> &packet);

/**
 * @brief Get a human-readable description of a DNS packet
 * @param packet Raw packet bytes
 * @return String description of the packet contents
 */
std::string describe_packet(const std::vector<uint8_t> &packet);

}  // namespace packet_parsers

}  // namespace dns_resolver
