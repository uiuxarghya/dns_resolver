#include "packet_parser.h"

#include <algorithm>

namespace dns_resolver {

PacketParser::PacketParser(const std::vector<uint8_t> &packet) : packet_(packet), offset_(0) {}

DnsMessage PacketParser::parse() {
  offset_ = 0;
  DnsMessage message;

  // Parse header
  message.header = parse_header();

  // Parse questions
  for (uint16_t i = 0; i < message.header.qdcount; ++i) {
    message.questions.push_back(parse_question());
  }

  // Parse answer records
  for (uint16_t i = 0; i < message.header.ancount; ++i) {
    message.answers.push_back(parse_resource_record());
  }

  // Parse authority records
  for (uint16_t i = 0; i < message.header.nscount; ++i) {
    message.authorities.push_back(parse_resource_record());
  }

  // Parse additional records
  for (uint16_t i = 0; i < message.header.arcount; ++i) {
    message.additionals.push_back(parse_resource_record());
  }

  return message;
}

DnsHeader PacketParser::parse_header() {
  ensure_bytes_available(12);

  DnsHeader header;
  header.id = read_uint16();
  header.flags = read_uint16();
  header.qdcount = read_uint16();
  header.ancount = read_uint16();
  header.nscount = read_uint16();
  header.arcount = read_uint16();

  return header;
}

bool PacketParser::is_valid_packet() const {
  return packet_.size() >= 12;  // Minimum size for DNS header
}

uint16_t PacketParser::read_uint16() {
  ensure_bytes_available(2);
  uint16_t value = (static_cast<uint16_t>(packet_[offset_]) << 8) | packet_[offset_ + 1];
  offset_ += 2;
  return value;
}

uint32_t PacketParser::read_uint32() {
  ensure_bytes_available(4);
  uint32_t value = (static_cast<uint32_t>(packet_[offset_]) << 24) |
                   (static_cast<uint32_t>(packet_[offset_ + 1]) << 16) |
                   (static_cast<uint32_t>(packet_[offset_ + 2]) << 8) |
                   static_cast<uint32_t>(packet_[offset_ + 3]);
  offset_ += 4;
  return value;
}

uint8_t PacketParser::read_uint8() {
  ensure_bytes_available(1);
  return packet_[offset_++];
}

std::vector<uint8_t> PacketParser::read_bytes(size_t length) {
  ensure_bytes_available(length);
  std::vector<uint8_t> bytes(packet_.begin() + offset_, packet_.begin() + offset_ + length);
  offset_ += length;
  return bytes;
}

std::string PacketParser::decode_name() {
  std::vector<size_t> visited;
  return decode_name_at_offset(offset_, visited);
}

std::string PacketParser::decode_name_at_offset(size_t start_offset,
                                                std::vector<size_t> &visited) const {
  size_t current_offset = start_offset;
  std::string name;
  bool jumped = false;

  while (current_offset < packet_.size()) {
    uint8_t length = packet_[current_offset];

    if (length == 0) {
      // End of name
      if (!jumped) {
        const_cast<PacketParser *>(this)->offset_ = current_offset + 1;
      }
      break;
    }

    if ((length & 0xC0) == 0xC0) {
      // Compression pointer
      if (is_compression_loop(current_offset, visited)) {
        throw ParseException("Compression loop detected");
      }
      visited.push_back(current_offset);

      if (current_offset + 1 >= packet_.size()) {
        throw ParseException("Truncated compression pointer");
      }

      uint16_t pointer =
          ((static_cast<uint16_t>(length) & 0x3F) << 8) | packet_[current_offset + 1];
      validate_offset(pointer);

      if (!jumped) {
        const_cast<PacketParser *>(this)->offset_ = current_offset + 2;
        jumped = true;
      }
      current_offset = pointer;
      continue;
    }

    // Regular label
    if (length > 63) {
      throw ParseException("Invalid label length");
    }

    if (current_offset + 1 + length >= packet_.size()) {
      throw ParseException("Truncated label");
    }

    if (!name.empty()) {
      name += ".";
    }

    name.append(reinterpret_cast<const char *>(packet_.data() + current_offset + 1), length);
    current_offset += 1 + length;
  }

  return name;
}

DnsQuestion PacketParser::parse_question() {
  DnsQuestion question;
  question.qname = decode_name();
  question.qtype = static_cast<RecordType>(read_uint16());
  question.qclass = static_cast<RecordClass>(read_uint16());
  return question;
}

ResourceRecord PacketParser::parse_resource_record() {
  ResourceRecord rr;
  rr.name = decode_name();
  rr.type = static_cast<RecordType>(read_uint16());
  rr.rr_class = static_cast<RecordClass>(read_uint16());
  rr.ttl = read_uint32();

  uint16_t rdlength = read_uint16();
  rr.rdata = read_bytes(rdlength);

  return rr;
}

void PacketParser::ensure_bytes_available(size_t bytes_needed) const {
  if (offset_ + bytes_needed > packet_.size()) {
    throw ParseException("Insufficient bytes in packet");
  }
}

void PacketParser::validate_offset(size_t offset) const {
  if (offset >= packet_.size()) {
    throw ParseException("Invalid offset in packet");
  }
}

bool PacketParser::is_compression_loop(size_t offset, const std::vector<size_t> &visited) const {
  return std::find(visited.begin(), visited.end(), offset) != visited.end();
}

// Utility functions
namespace packet_parsers {

bool is_dns_response(const std::vector<uint8_t> &packet) {
  if (packet.size() < 2) return false;
  return (packet[2] & 0x80) != 0;  // QR bit
}

std::optional<uint16_t> extract_query_id(const std::vector<uint8_t> &packet) {
  if (packet.size() < 2) return std::nullopt;
  return (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
}

std::optional<ResponseCode> extract_response_code(const std::vector<uint8_t> &packet) {
  if (packet.size() < 4) return std::nullopt;
  return static_cast<ResponseCode>(packet[3] & 0x0F);
}

bool is_truncated_response(const std::vector<uint8_t> &packet) {
  if (packet.size() < 3) return false;
  return (packet[2] & 0x02) != 0;  // TC bit
}

std::vector<std::string> extract_a_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();

    std::vector<std::string> addresses;
    for (const auto &rr : message.answers) {
      if (rr.type == RecordType::A) {
        auto addr = rr.get_a_record();
        if (!addr.empty()) {
          addresses.push_back(addr);
        }
      }
    }
    return addresses;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_aaaa_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();

    std::vector<std::string> addresses;
    for (const auto &rr : message.answers) {
      if (rr.type == RecordType::AAAA) {
        auto addr = rr.get_aaaa_record();
        if (!addr.empty()) {
          addresses.push_back(addr);
        }
      }
    }
    return addresses;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_cname_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::vector<std::string> cnames;
    for (const auto &rr : message.answers) {
      if (rr.type == RecordType::CNAME) {
        // CNAME rdata is a domain name
        PacketParser name_parser(rr.rdata);
        cnames.push_back(name_parser.decode_name());
      }
    }
    return cnames;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_ns_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::vector<std::string> nss;
    for (const auto &rr : message.answers) {
      if (rr.type == RecordType::NS) {
        PacketParser name_parser(rr.rdata);
        nss.push_back(name_parser.decode_name());
      }
    }
    return nss;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_authority_ns_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::vector<std::string> nss;
    for (const auto &rr : message.authorities) {
      if (rr.type == RecordType::NS) {
        PacketParser name_parser(rr.rdata);
        nss.push_back(name_parser.decode_name());
      }
    }
    return nss;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_additional_a_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::vector<std::string> addresses;
    for (const auto &rr : message.additionals) {
      if (rr.type == RecordType::A) {
        auto addr = rr.get_a_record();
        if (!addr.empty()) {
          addresses.push_back(addr);
        }
      }
    }
    return addresses;
  } catch (...) {
    return {};
  }
}

std::vector<std::string> extract_additional_aaaa_records(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::vector<std::string> addresses;
    for (const auto &rr : message.additionals) {
      if (rr.type == RecordType::AAAA) {
        auto addr = rr.get_aaaa_record();
        if (!addr.empty()) {
          addresses.push_back(addr);
        }
      }
    }
    return addresses;
  } catch (...) {
    return {};
  }
}

bool validate_packet_structure(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    parser.parse();
    return true;
  } catch (...) {
    return false;
  }
}

std::string describe_packet(const std::vector<uint8_t> &packet) {
  try {
    PacketParser parser(packet);
    auto message = parser.parse();
    std::string desc = "ID: " + std::to_string(message.header.id) + ", ";
    desc += "Questions: " + std::to_string(message.header.qdcount) + ", ";
    desc += "Answers: " + std::to_string(message.header.ancount) + ", ";
    desc += "Authorities: " + std::to_string(message.header.nscount) + ", ";
    desc += "Additionals: " + std::to_string(message.header.arcount);
    return desc;
  } catch (...) {
    return "Invalid DNS packet";
  }
}

}  // namespace packet_parsers

}  // namespace dns_resolver
