#include "packet_builder.h"

#include <sstream>
#include <stdexcept>

namespace dns_resolver {

PacketBuilder::PacketBuilder() : compression_enabled_(true) { reset(); }

PacketBuilder &PacketBuilder::set_id(uint16_t id) {
  header_.id = id;
  return *this;
}

PacketBuilder &PacketBuilder::set_flags(uint16_t flags) {
  header_.flags = flags;
  return *this;
}

PacketBuilder &PacketBuilder::set_flags(bool is_response, uint8_t opcode, bool authoritative,
                                        bool truncated, bool recursion_desired,
                                        bool recursion_available, uint8_t rcode) {
  header_.flags = 0;
  if (is_response) header_.flags |= 0x8000;
  header_.flags |= (static_cast<uint16_t>(opcode & 0x0F) << 11);
  if (authoritative) header_.flags |= 0x0400;
  if (truncated) header_.flags |= 0x0200;
  if (recursion_desired) header_.flags |= 0x0100;
  if (recursion_available) header_.flags |= 0x0080;
  header_.flags |= (rcode & 0x0F);
  return *this;
}

PacketBuilder &PacketBuilder::add_question(const std::string &name, RecordType type,
                                           RecordClass cls) {
  validate_domain_name(name);
  questions_.emplace_back(name, type, cls);
  header_.qdcount = static_cast<uint16_t>(questions_.size());
  return *this;
}

PacketBuilder &PacketBuilder::add_answer(const std::string &name, RecordType type, RecordClass cls,
                                         uint32_t ttl, const std::vector<uint8_t> &rdata) {
  validate_domain_name(name);
  ResourceRecord rr(name, type, cls, ttl);
  rr.rdata = rdata;
  answers_.push_back(rr);
  header_.ancount = static_cast<uint16_t>(answers_.size());
  return *this;
}

PacketBuilder &PacketBuilder::add_authority(const std::string &name, RecordType type,
                                            RecordClass cls, uint32_t ttl,
                                            const std::vector<uint8_t> &rdata) {
  validate_domain_name(name);
  ResourceRecord rr(name, type, cls, ttl);
  rr.rdata = rdata;
  authorities_.push_back(rr);
  header_.nscount = static_cast<uint16_t>(authorities_.size());
  return *this;
}

PacketBuilder &PacketBuilder::add_additional(const std::string &name, RecordType type,
                                             RecordClass cls, uint32_t ttl,
                                             const std::vector<uint8_t> &rdata) {
  validate_domain_name(name);
  ResourceRecord rr(name, type, cls, ttl);
  rr.rdata = rdata;
  additionals_.push_back(rr);
  header_.arcount = static_cast<uint16_t>(additionals_.size());
  return *this;
}

PacketBuilder &PacketBuilder::add_edns0_opt(uint16_t udp_payload_size, uint8_t extended_rcode,
                                            uint8_t version, uint16_t flags) {
  // EDNS(0) OPT record format:
  // NAME: root domain (empty)
  // TYPE: OPT (41)
  // CLASS: UDP payload size
  // TTL: extended RCODE (8 bits) | version (8 bits) | flags (16 bits)
  // RDLENGTH: 0 (no options for basic EDNS(0))
  // RDATA: empty (no options)

  ResourceRecord opt_rr;
  opt_rr.name = "";  // Root domain for OPT record
  opt_rr.type = RecordType::OPT;
  opt_rr.rr_class =
      static_cast<RecordClass>(udp_payload_size);  // CLASS field holds UDP payload size

  // TTL field holds: extended_rcode (8) | version (8) | flags (16)
  opt_rr.ttl = (static_cast<uint32_t>(extended_rcode) << 24) |
               (static_cast<uint32_t>(version) << 16) | static_cast<uint32_t>(flags);

  opt_rr.rdata.clear();  // No options for basic EDNS(0)

  additionals_.push_back(opt_rr);
  header_.arcount = static_cast<uint16_t>(additionals_.size());
  return *this;
}

std::vector<uint8_t> PacketBuilder::build() {
  std::vector<uint8_t> packet;
  packet.reserve(512);  // Start with typical UDP packet size

  compression_map_.clear();

  // Write header
  write_uint16(header_.id, packet);
  write_uint16(header_.flags, packet);
  write_uint16(header_.qdcount, packet);
  write_uint16(header_.ancount, packet);
  write_uint16(header_.nscount, packet);
  write_uint16(header_.arcount, packet);

  // Write questions
  for (const auto &question : questions_) {
    encode_name(question.qname, packet);
    write_uint16(static_cast<uint16_t>(question.qtype), packet);
    write_uint16(static_cast<uint16_t>(question.qclass), packet);
  }

  // Write answer records
  for (const auto &rr : answers_) {
    write_resource_record(rr, packet);
  }

  // Write authority records
  for (const auto &rr : authorities_) {
    write_resource_record(rr, packet);
  }

  // Write additional records
  for (const auto &rr : additionals_) {
    write_resource_record(rr, packet);
  }

  return packet;
}

void PacketBuilder::reset() {
  header_ = {};
  questions_.clear();
  answers_.clear();
  authorities_.clear();
  additionals_.clear();
  compression_map_.clear();
}

size_t PacketBuilder::get_current_size() const {
  // Estimate current packet size
  size_t size = 12;  // Header size

  for (const auto &question : questions_) {
    size += question.qname.length() + 2 + 4;  // Name + null + type + class
  }

  for (const auto &rr : answers_) {
    size += rr.name.length() + 2 + 10 + rr.rdata.size();  // Name + null + fixed fields + rdata
  }

  for (const auto &rr : authorities_) {
    size += rr.name.length() + 2 + 10 + rr.rdata.size();
  }

  for (const auto &rr : additionals_) {
    size += rr.name.length() + 2 + 10 + rr.rdata.size();
  }

  return size;
}

void PacketBuilder::encode_name(const std::string &name, std::vector<uint8_t> &buffer,
                                bool allow_compression) {
  if (name.empty()) {
    buffer.push_back(0);  // Root domain
    return;
  }

  std::string normalized_name = utils::normalize_domain_name(name);

  // Check for compression opportunity
  if (compression_enabled_ && allow_compression) {
    size_t compression_offset;
    if (find_compression_target(normalized_name, compression_offset)) {
      // Write compression pointer
      uint16_t pointer = 0xC000 | static_cast<uint16_t>(compression_offset);
      write_uint16(pointer, buffer);
      return;
    }
  }

  // Record compression entry for this name
  if (compression_enabled_) {
    add_compression_entry(normalized_name, buffer.size());
  }

  // Split domain into labels and encode
  auto labels = split_domain_name(normalized_name);
  for (const auto &label : labels) {
    if (label.length() > 63) {
      throw ProtocolException("Label too long: " + label);
    }
    buffer.push_back(static_cast<uint8_t>(label.length()));
    buffer.insert(buffer.end(), label.begin(), label.end());
  }
  buffer.push_back(0);  // Null terminator
}

void PacketBuilder::write_uint16(uint16_t value, std::vector<uint8_t> &buffer) {
  // Write in network byte order (big endian)
  buffer.push_back(static_cast<uint8_t>(value >> 8));
  buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

void PacketBuilder::write_uint32(uint32_t value, std::vector<uint8_t> &buffer) {
  // Write in network byte order (big endian)
  buffer.push_back(static_cast<uint8_t>(value >> 24));
  buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

void PacketBuilder::write_resource_record(const ResourceRecord &rr, std::vector<uint8_t> &buffer) {
  encode_name(rr.name, buffer);
  write_uint16(static_cast<uint16_t>(rr.type), buffer);
  write_uint16(static_cast<uint16_t>(rr.rr_class), buffer);
  write_uint32(rr.ttl, buffer);
  write_uint16(static_cast<uint16_t>(rr.rdata.size()), buffer);
  buffer.insert(buffer.end(), rr.rdata.begin(), rr.rdata.end());
}

void PacketBuilder::validate_domain_name(const std::string &name) {
  if (!utils::is_valid_domain_name(name)) {
    throw ProtocolException("Invalid domain name: " + name);
  }
}

void PacketBuilder::add_compression_entry(const std::string &name, size_t offset) {
  compression_map_[name] = offset;
}

bool PacketBuilder::find_compression_target(const std::string &name, size_t &offset) {
  auto it = compression_map_.find(name);
  if (it != compression_map_.end()) {
    offset = it->second;
    return true;
  }
  return false;
}

std::vector<std::string> PacketBuilder::split_domain_name(const std::string &name) {
  std::vector<std::string> labels;

  if (name.empty() || name == ".") {
    return labels;  // Root domain
  }

  size_t start = 0;
  size_t pos = 0;

  while (pos < name.length()) {
    pos = name.find('.', start);
    if (pos == std::string::npos) {
      pos = name.length();
    }

    if (pos > start) {
      labels.push_back(name.substr(start, pos - start));
    }

    start = pos + 1;
  }

  return labels;
}

// Convenience functions
namespace packet_builders {

std::vector<uint8_t> create_query(uint16_t id, const std::string &domain, RecordType type,
                                  bool recursion_desired) {
  PacketBuilder builder;
  return builder.set_id(id)
      .set_flags(false, 0, false, false, recursion_desired, false, 0)
      .add_question(domain, type, RecordClass::IN)
      // Temporarily disable EDNS(0) to test basic functionality
      // .add_edns0_opt(4096)  // Add EDNS(0) with 4KB UDP buffer size
      .build();
}

std::vector<uint8_t> create_a_response(uint16_t query_id, const std::string &domain,
                                       const std::string &ipv4_address, uint32_t ttl,
                                       bool authoritative) {
  // Convert IPv4 address to bytes
  std::vector<uint8_t> addr_bytes(4);

  // Parse IPv4 address
  size_t pos = 0;
  for (int i = 0; i < 4; ++i) {
    size_t next_pos = ipv4_address.find('.', pos);
    if (next_pos == std::string::npos && i < 3) {
      return {};  // Invalid format
    }

    std::string octet = ipv4_address.substr(pos, next_pos - pos);
    int value = std::stoi(octet);
    if (value < 0 || value > 255) {
      return {};  // Invalid octet
    }

    addr_bytes[i] = static_cast<uint8_t>(value);
    pos = next_pos + 1;
  }

  PacketBuilder builder;
  return builder.set_id(query_id)
      .set_flags(true, 0, authoritative, false, true, true, 0)
      .add_question(domain, RecordType::A, RecordClass::IN)
      .add_answer(domain, RecordType::A, RecordClass::IN, ttl, addr_bytes)
      .build();
}

std::vector<uint8_t> create_aaaa_response(uint16_t query_id, const std::string &domain,
                                          const std::string &ipv6_address, uint32_t ttl,
                                          bool authoritative) {
  // Convert IPv6 address to bytes (simplified implementation)
  std::vector<uint8_t> addr_bytes(16, 0);

  // This is a simplified IPv6 parser - in production, use inet_pton
  // For now, return empty to indicate not implemented
  (void)query_id;
  (void)domain;
  (void)ipv6_address;
  (void)ttl;
  (void)authoritative;
  return {};
}

std::vector<uint8_t> create_error_response(uint16_t query_id, ResponseCode rcode) {
  PacketBuilder builder;
  return builder.set_id(query_id)
      .set_flags(true, 0, false, false, false, false, static_cast<uint8_t>(rcode))
      .build();
}

}  // namespace packet_builders

}  // namespace dns_resolver
