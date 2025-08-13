#include "utils.h"

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <random>
#include <regex>
#include <sstream>

namespace dns_resolver {

std::string ResourceRecord::get_a_record() const {
  if (type != RecordType::A || rdata.size() != 4) {
    return "";
  }
  return utils::ipv4_to_string(rdata);
}

std::string ResourceRecord::get_aaaa_record() const {
  if (type != RecordType::AAAA || rdata.size() != 16) {
    return "";
  }
  return utils::ipv6_to_string(rdata);
}

std::string ResourceRecord::get_cname_record() const {
  if (type != RecordType::CNAME) {
    return "";
  }
  // For CNAME records, rdata contains the encoded domain name
  // This would need to be decoded using the packet parser
  // For now, return empty string - this will be implemented in packet_parser.cpp
  return "";
}

std::string ResourceRecord::get_ns_record() const {
  if (type != RecordType::NS) {
    return "";
  }
  // Similar to CNAME, NS records contain encoded domain names
  return "";
}

std::string ResourceRecord::get_txt_record() const {
  if (type != RecordType::TXT) {
    return "";
  }
  // TXT records have a specific format with length prefixes
  std::string result;
  size_t offset = 0;
  while (offset < rdata.size()) {
    if (offset >= rdata.size()) break;
    uint8_t length = rdata[offset++];
    if (offset + length > rdata.size()) break;

    result.append(reinterpret_cast<const char *>(rdata.data() + offset), length);
    offset += length;
  }
  return result;
}

namespace utils {

std::string normalize_domain_name(const std::string &domain) {
  std::string normalized = domain;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);

  // Remove trailing dot if present
  if (!normalized.empty() && normalized.back() == '.') {
    normalized.pop_back();
  }

  return normalized;
}

bool is_valid_domain_name(const std::string &domain) {
  if (domain.empty() || domain.length() > 255) {
    return false;
  }
  // Allow '.' for root domain
  if (domain == ".") {
    return true;
  }
  // Check for valid characters and label length
  std::regex domain_regex(
      R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$)");
  return std::regex_match(domain, domain_regex);
}

std::string record_type_to_string(RecordType type) {
  switch (type) {
    case RecordType::A:
      return "A";
    case RecordType::NS:
      return "NS";
    case RecordType::CNAME:
      return "CNAME";
    case RecordType::SOA:
      return "SOA";
    case RecordType::PTR:
      return "PTR";
    case RecordType::MX:
      return "MX";
    case RecordType::TXT:
      return "TXT";
    case RecordType::AAAA:
      return "AAAA";
    case RecordType::SRV:
      return "SRV";
    case RecordType::ANY:
      return "ANY";
    default:
      return "UNKNOWN";
  }
}

RecordType string_to_record_type(const std::string &type_str) {
  std::string upper_type = type_str;
  std::transform(upper_type.begin(), upper_type.end(), upper_type.begin(), ::toupper);

  if (upper_type == "A") return RecordType::A;
  if (upper_type == "NS") return RecordType::NS;
  if (upper_type == "CNAME") return RecordType::CNAME;
  if (upper_type == "SOA") return RecordType::SOA;
  if (upper_type == "PTR") return RecordType::PTR;
  if (upper_type == "MX") return RecordType::MX;
  if (upper_type == "TXT") return RecordType::TXT;
  if (upper_type == "AAAA") return RecordType::AAAA;
  if (upper_type == "SRV") return RecordType::SRV;
  if (upper_type == "ANY") return RecordType::ANY;

  return RecordType::A;  // Default to A record
}

std::string ipv4_to_string(const std::vector<uint8_t> &bytes) {
  if (bytes.size() != 4) {
    return "";
  }

  std::ostringstream oss;
  oss << static_cast<int>(bytes[0]) << "." << static_cast<int>(bytes[1]) << "."
      << static_cast<int>(bytes[2]) << "." << static_cast<int>(bytes[3]);
  return oss.str();
}

std::string ipv6_to_string(const std::vector<uint8_t> &bytes) {
  if (bytes.size() != 16) {
    return "";
  }

  char str[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, bytes.data(), str, INET6_ADDRSTRLEN) == nullptr) {
    return "";
  }

  return std::string(str);
}

uint16_t generate_query_id() {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<uint16_t> dis(1, 65535);
  return dis(gen);
}

uint64_t get_current_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

uint16_t ntohs_safe(uint16_t value) { return ntohs(value); }

uint16_t htons_safe(uint16_t value) { return htons(value); }

uint32_t ntohl_safe(uint32_t value) { return ntohl(value); }

uint32_t htonl_safe(uint32_t value) { return htonl(value); }

}  // namespace utils

}  // namespace dns_resolver
