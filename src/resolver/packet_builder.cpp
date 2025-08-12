#include "packet_builder.h"
#include <stdexcept>
#include <sstream>

namespace dns_resolver
{

  PacketBuilder::PacketBuilder() : compression_enabled_(true)
  {
    reset();
  }

  PacketBuilder &PacketBuilder::set_id(uint16_t id)
  {
    header_.id = id;
    return *this;
  }

  PacketBuilder &PacketBuilder::set_flags(uint16_t flags)
  {
    header_.flags = flags;
    return *this;
  }

  PacketBuilder &PacketBuilder::set_flags(bool is_response, uint8_t opcode, bool authoritative,
                                          bool truncated, bool recursion_desired,
                                          bool recursion_available, uint8_t rcode)
  {
    header_.flags = 0;
    if (is_response)
      header_.flags |= 0x8000;
    header_.flags |= (static_cast<uint16_t>(opcode & 0x0F) << 11);
    if (authoritative)
      header_.flags |= 0x0400;
    if (truncated)
      header_.flags |= 0x0200;
    if (recursion_desired)
      header_.flags |= 0x0100;
    if (recursion_available)
      header_.flags |= 0x0080;
    header_.flags |= (rcode & 0x0F);
    return *this;
  }

  PacketBuilder &PacketBuilder::add_question(const std::string &name, RecordType type, RecordClass cls)
  {
    validate_domain_name(name);
    questions_.emplace_back(name, type, cls);
    header_.qdcount = static_cast<uint16_t>(questions_.size());
    return *this;
  }

  PacketBuilder &PacketBuilder::add_answer(const std::string &name, RecordType type, RecordClass cls,
                                           uint32_t ttl, const std::vector<uint8_t> &rdata)
  {
    validate_domain_name(name);
    ResourceRecord rr(name, type, cls, ttl);
    rr.rdata = rdata;
    answers_.push_back(rr);
    header_.ancount = static_cast<uint16_t>(answers_.size());
    return *this;
  }

  PacketBuilder &PacketBuilder::add_authority(const std::string &name, RecordType type, RecordClass cls,
                                              uint32_t ttl, const std::vector<uint8_t> &rdata)
  {
    validate_domain_name(name);
    ResourceRecord rr(name, type, cls, ttl);
    rr.rdata = rdata;
    authorities_.push_back(rr);
    header_.nscount = static_cast<uint16_t>(authorities_.size());
    return *this;
  }

  PacketBuilder &PacketBuilder::add_additional(const std::string &name, RecordType type, RecordClass cls,
                                               uint32_t ttl, const std::vector<uint8_t> &rdata)
  {
    validate_domain_name(name);
    ResourceRecord rr(name, type, cls, ttl);
    rr.rdata = rdata;
    additionals_.push_back(rr);
    header_.arcount = static_cast<uint16_t>(additionals_.size());
    return *this;
  }

  std::vector<uint8_t> PacketBuilder::build()
  {
    std::vector<uint8_t> packet;
    packet.reserve(512); // Start with typical UDP packet size

    compression_map_.clear();

    // Write header
    write_uint16(header_.id, packet);
    write_uint16(header_.flags, packet);
    write_uint16(header_.qdcount, packet);
    write_uint16(header_.ancount, packet);
    write_uint16(header_.nscount, packet);
    write_uint16(header_.arcount, packet);

    // Write questions
    for (const auto &question : questions_)
    {
      encode_name(question.qname, packet);
      write_uint16(static_cast<uint16_t>(question.qtype), packet);
      write_uint16(static_cast<uint16_t>(question.qclass), packet);
    }

    // Write answer records
    for (const auto &rr : answers_)
    {
      write_resource_record(rr, packet);
    }

    // Write authority records
    for (const auto &rr : authorities_)
    {
      write_resource_record(rr, packet);
    }

    // Write additional records
    for (const auto &rr : additionals_)
    {
      write_resource_record(rr, packet);
    }

    return packet;
  }

  void PacketBuilder::reset()
  {
    header_ = {};
    questions_.clear();
    answers_.clear();
    authorities_.clear();
    additionals_.clear();
    compression_map_.clear();
  }

  size_t PacketBuilder::get_current_size() const
  {
    // Estimate current packet size
    size_t size = 12; // Header size

    for (const auto &question : questions_)
    {
      size += question.qname.length() + 2 + 4; // Name + null + type + class
    }

    for (const auto &rr : answers_)
    {
      size += rr.name.length() + 2 + 10 + rr.rdata.size(); // Name + null + fixed fields + rdata
    }

    for (const auto &rr : authorities_)
    {
      size += rr.name.length() + 2 + 10 + rr.rdata.size();
    }

    for (const auto &rr : additionals_)
    {
      size += rr.name.length() + 2 + 10 + rr.rdata.size();
    }

    return size;
  }

  void PacketBuilder::encode_name(const std::string &name, std::vector<uint8_t> &buffer, bool allow_compression)
  {
    if (name.empty())
    {
      buffer.push_back(0); // Root domain
      return;
    }

    std::string normalized_name = utils::normalize_domain_name(name);

    // Check for compression opportunity
    if (compression_enabled_ && allow_compression)
    {
      size_t compression_offset;
      if (find_compression_target(normalized_name, compression_offset))
      {
        // Write compression pointer
        uint16_t pointer = 0xC000 | static_cast<uint16_t>(compression_offset);
        write_uint16(pointer, buffer);
        return;
      }
    }

    // Record compression entry for this name
    if (compression_enabled_)
    {
      add_compression_entry(normalized_name, buffer.size());
    }

    // Split domain into labels and encode
    auto labels = split_domain_name(normalized_name);
    for (const auto &label : labels)
    {
      if (label.length() > 63)
      {
        throw ProtocolException("Label too long: " + label);
      }
      buffer.push_back(static_cast<uint8_t>(label.length()));
      buffer.insert(buffer.end(), label.begin(), label.end());
    }
    buffer.push_back(0); // Null terminator
  }

  void PacketBuilder::write_uint16(uint16_t value, std::vector<uint8_t> &buffer)
  {
    uint16_t network_value = utils::htons_safe(value);
    buffer.push_back(static_cast<uint8_t>(network_value >> 8));
    buffer.push_back(static_cast<uint8_t>(network_value & 0xFF));
  }

  void PacketBuilder::write_uint32(uint32_t value, std::vector<uint8_t> &buffer)
  {
    uint32_t network_value = utils::htonl_safe(value);
    buffer.push_back(static_cast<uint8_t>(network_value >> 24));
    buffer.push_back(static_cast<uint8_t>((network_value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((network_value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(network_value & 0xFF));
  }

  void PacketBuilder::write_resource_record(const ResourceRecord &rr, std::vector<uint8_t> &buffer)
  {
    encode_name(rr.name, buffer);
    write_uint16(static_cast<uint16_t>(rr.type), buffer);
    write_uint16(static_cast<uint16_t>(rr.rr_class), buffer);
    write_uint32(rr.ttl, buffer);
    write_uint16(static_cast<uint16_t>(rr.rdata.size()), buffer);
    buffer.insert(buffer.end(), rr.rdata.begin(), rr.rdata.end());
  }

  void PacketBuilder::validate_domain_name(const std::string &name)
  {
    if (!utils::is_valid_domain_name(name))
    {
      throw ProtocolException("Invalid domain name: " + name);
    }
  }

  void PacketBuilder::add_compression_entry(const std::string &name, size_t offset)
  {
    compression_map_[name] = offset;
  }

  bool PacketBuilder::find_compression_target(const std::string &name, size_t &offset)
  {
    auto it = compression_map_.find(name);
    if (it != compression_map_.end())
    {
      offset = it->second;
      return true;
    }
    return false;
  }

  std::vector<std::string> PacketBuilder::split_domain_name(const std::string &name)
  {
    std::vector<std::string> labels;
    std::stringstream ss(name);
    std::string label;

    while (std::getline(ss, label, '.'))
    {
      if (!label.empty())
      {
        labels.push_back(label);
      }
    }

    return labels;
  }

  // Convenience functions
  namespace packet_builders
  {

    std::vector<uint8_t> create_query(uint16_t id, const std::string &domain,
                                      RecordType type, bool recursion_desired)
    {
      PacketBuilder builder;
      return builder
          .set_id(id)
          .set_flags(false, 0, false, false, recursion_desired, false, 0)
          .add_question(domain, type, RecordClass::IN)
          .build();
    }

    std::vector<uint8_t> create_a_response(uint16_t query_id, const std::string &domain,
                                           const std::string &ipv4_address, uint32_t ttl,
                                           bool authoritative)
    {
      // Convert IPv4 address to bytes
      std::vector<uint8_t> addr_bytes(4);
      // Simple IPv4 parsing (should use inet_pton in production)
      // This is a simplified implementation
      return {}; // TODO: Implement proper IPv4 parsing
    }

    std::vector<uint8_t> create_aaaa_response(uint16_t query_id, const std::string &domain,
                                              const std::string &ipv6_address, uint32_t ttl,
                                              bool authoritative)
    {
      // TODO: Implement IPv6 response creation
      return {};
    }

    std::vector<uint8_t> create_error_response(uint16_t query_id, ResponseCode rcode)
    {
      PacketBuilder builder;
      return builder
          .set_id(query_id)
          .set_flags(true, 0, false, false, false, false, static_cast<uint8_t>(rcode))
          .build();
    }

  } // namespace packet_builders

} // namespace dns_resolver
