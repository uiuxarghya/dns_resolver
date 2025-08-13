#include "response_processor.h"

#include <iostream>
#include <unordered_map>

#include "packet_parser.h"
#include "resolver.h"

namespace dns_resolver {

ResponseProcessor::ResponseProcessor(const ResolverConfig& config) : config_(config) {}

ProcessResult ResponseProcessor::process_response(const std::vector<uint8_t>& response,
                                                  const std::string& domain, RecordType type,
                                                  [[maybe_unused]] int depth) {
  ProcessResult result;
  (void)domain;  // Mark as unused - domain is used for logging/debugging in verbose mode

  try {
    PacketParser parser(response);
    auto message = parser.parse();

    result.rcode = static_cast<ResponseCode>(message.header.get_rcode());
    result.is_authoritative = message.header.is_authoritative();

    if (result.rcode != ResponseCode::NO_ERROR) {
      return result;
    }

    // Check for answers
    for (const auto& rr : message.answers) {
      if (rr.type == type) {
        result.has_answer = true;
        if (type == RecordType::A && rr.rdata.size() == 4) {
          auto addr = utils::ipv4_to_string(rr.rdata);
          if (!addr.empty()) result.addresses.push_back(addr);
        } else if (type == RecordType::AAAA && rr.rdata.size() == 16) {
          auto addr = utils::ipv6_to_string(rr.rdata);
          if (!addr.empty()) result.addresses.push_back(addr);
        } else if (type == RecordType::TXT) {
          auto txt = rr.get_txt_record();
          if (!txt.empty()) result.addresses.push_back(txt);
        } else if (type == RecordType::MX) {
          // MX records have priority (2 bytes) + domain name
          if (rr.rdata.size() >= 3) {
            uint16_t priority = (static_cast<uint16_t>(rr.rdata[0]) << 8) | rr.rdata[1];
            // Extract domain name starting from byte 2
            std::vector<uint8_t> domain_data(rr.rdata.begin() + 2, rr.rdata.end());
            std::string mx_domain = parse_domain_name_with_compression(domain_data, 0, response);
            if (!mx_domain.empty()) {
              result.addresses.push_back(std::to_string(priority) + " " + mx_domain);
            } else {
              result.addresses.push_back(std::to_string(priority) + " (failed to parse domain)");
            }
          }
        } else if (type == RecordType::NS) {
          // Extract NS name from rdata
          std::string ns_name = extract_domain_name_from_rdata(rr.rdata, response);
          if (!ns_name.empty()) {
            result.addresses.push_back(ns_name);
          } else {
            result.addresses.push_back("(Failed to parse NS name)");
          }
        } else if (type == RecordType::CNAME) {
          // Extract CNAME target from rdata
          std::string cname_target = extract_domain_name_from_rdata(rr.rdata, response);
          if (!cname_target.empty()) {
            result.cname_target = cname_target;
            result.addresses.push_back(cname_target);
          }
        } else if (type == RecordType::PTR) {
          // PTR records contain a domain name (for reverse DNS)
          std::string ptr_domain = extract_domain_name_from_rdata(rr.rdata, response);
          if (!ptr_domain.empty()) {
            result.addresses.push_back(ptr_domain);
          }
        } else if (type == RecordType::SOA) {
          // SOA records: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
          auto soa_record = parse_soa_record(rr.rdata, response);
          if (!soa_record.empty()) {
            result.addresses.push_back(soa_record);
          }
        } else if (type == RecordType::SRV) {
          // SRV records: priority weight port target
          auto srv_record = parse_srv_record(rr.rdata, response);
          if (!srv_record.empty()) {
            result.addresses.push_back(srv_record);
          }
        }
      } else if (rr.type == RecordType::CNAME) {
        // For now, skip CNAME processing - this would require parsing domain names from rdata
        // result.cname_target = extract_cname_target(rr.rdata);
      }
    }

    // If we have NS records in answer section, also check for glue records in additional section
    if (result.has_answer && type == RecordType::NS) {
      for (const auto& rr : message.additionals) {
        if (rr.type == RecordType::A && rr.rdata.size() == 4) {
          auto addr = utils::ipv4_to_string(rr.rdata);
          if (!addr.empty()) {
            result.referral_servers.push_back(addr);
            log_verbose("Found glue record (A): " + addr);
          }
        } else if (rr.type == RecordType::AAAA && rr.rdata.size() == 16) {
          auto addr = utils::ipv6_to_string(rr.rdata);
          if (!addr.empty()) {
            result.referral_servers.push_back(addr);
            log_verbose("Found glue record (AAAA): " + addr);
          }
        }
      }
    }

    // Check for referrals in authority section
    if (!result.has_answer) {
      std::vector<std::string> ns_names;

      // Extract NS names from authority section
      for (const auto& rr : message.authorities) {
        if (rr.type == RecordType::NS) {
          // Try to extract NS name from rdata (simplified domain name parsing)
          std::string ns_name = extract_domain_name_from_rdata(rr.rdata, response);
          if (!ns_name.empty()) {
            ns_names.push_back(ns_name);
            log_verbose("Found NS: " + ns_name);
          }
        }
      }

      // First, try to find glue records in additional section that match NS names
      std::unordered_map<std::string, std::vector<std::string>> glue_map;
      std::vector<std::pair<std::string, std::string>> all_glue_records;  // name, ip pairs

      for (const auto& rr : message.additionals) {
        if (rr.type == RecordType::A && rr.rdata.size() == 4) {
          auto addr = utils::ipv4_to_string(rr.rdata);
          if (!addr.empty()) {
            std::string glue_name = utils::normalize_domain_name(rr.name);
            all_glue_records.emplace_back(glue_name, addr);
            glue_map[glue_name].push_back(addr);
            log_verbose("Found glue record: " + glue_name + " -> " + addr);
          }
        } else if (rr.type == RecordType::AAAA && rr.rdata.size() == 16) {
          auto addr = utils::ipv6_to_string(rr.rdata);
          if (!addr.empty()) {
            std::string glue_name = utils::normalize_domain_name(rr.name);
            all_glue_records.emplace_back(glue_name, addr);
            glue_map[glue_name].push_back(addr);
            log_verbose("Found glue record: " + glue_name + " -> " + addr);
          }
        }
      }

      // Enhanced matching: exact match first, then fuzzy matching
      for (const auto& ns_name : ns_names) {
        std::string normalized_ns = utils::normalize_domain_name(ns_name);

        // Exact match
        auto it = glue_map.find(normalized_ns);
        if (it != glue_map.end()) {
          result.referral_servers.insert(result.referral_servers.end(), it->second.begin(),
                                         it->second.end());
          log_verbose("Exact match glue records for " + ns_name + ": " +
                      std::to_string(it->second.size()) + " addresses");
          continue;
        }

        // Fuzzy matching: check if any glue record contains the NS name or vice versa
        bool found_fuzzy = false;
        for (const auto& glue_pair : all_glue_records) {
          const std::string& glue_name = glue_pair.first;
          const std::string& glue_ip = glue_pair.second;

          // Check if glue name contains NS name or NS name contains glue name
          if (glue_name.find(normalized_ns) != std::string::npos ||
              normalized_ns.find(glue_name) != std::string::npos) {
            result.referral_servers.push_back(glue_ip);
            log_verbose("Fuzzy match glue record: " + ns_name + " matches " + glue_name + " -> " +
                        glue_ip);
            found_fuzzy = true;
          }
        }

        if (!found_fuzzy) {
          log_verbose("No glue record found for NS: " + ns_name);
        }
      }

      // If still no glue records found but we have some A records, use them as potential servers
      if (result.referral_servers.empty() && !all_glue_records.empty()) {
        log_verbose("No exact matches, using all available glue records as potential servers");
        for (const auto& glue_pair : all_glue_records) {
          result.referral_servers.push_back(glue_pair.second);
        }
      }

      // Note: NS resolution is handled by RecursionHandler
      // If no glue records found, the caller should resolve NS names to IP addresses
    }
  } catch (const std::exception& e) {
    log_verbose("Failed to process response: " + std::string(e.what()));
  }

  return result;
}

std::string ResponseProcessor::extract_domain_name_from_rdata(
    const std::vector<uint8_t>& rdata, const std::vector<uint8_t>& full_packet) {
  if (rdata.empty()) {
    return "";
  }

  try {
    return parse_domain_name_with_compression(rdata, 0, full_packet);
  } catch (const std::exception& e) {
    log_verbose("Error parsing domain name from rdata: " + std::string(e.what()));
    return "";
  }
}

std::string ResponseProcessor::extract_domain_name_from_name_field(
    const std::vector<uint8_t>& name_field, const std::vector<uint8_t>& full_packet) {
  if (name_field.empty()) {
    return "";
  }

  try {
    return parse_domain_name_with_compression(name_field, 0, full_packet);
  } catch (const std::exception& e) {
    log_verbose("Error parsing domain name from name field: " + std::string(e.what()));
    return "";
  }
}

std::string ResponseProcessor::parse_domain_name_with_compression(
    const std::vector<uint8_t>& data, size_t start_offset,
    const std::vector<uint8_t>& full_packet) {
  std::string domain_name;
  size_t pos = start_offset;
  size_t jump_count = 0;
  const size_t max_jumps = 10;  // Prevent infinite loops

  while (pos < data.size() && jump_count < max_jumps) {
    uint8_t length = data[pos];

    if (length == 0) {
      // End of domain name
      break;
    }

    if ((length & 0xC0) == 0xC0) {
      // Compression pointer
      if (pos + 1 >= data.size()) {
        break;  // Invalid pointer
      }

      uint16_t pointer = ((static_cast<uint16_t>(length & 0x3F) << 8) | data[pos + 1]);

      if (pointer >= full_packet.size()) {
        log_verbose("Invalid compression pointer: " + std::to_string(pointer));
        break;
      }

      // Follow the pointer in the full packet
      std::string compressed_part =
          parse_domain_name_with_compression(full_packet, pointer, full_packet);
      if (!compressed_part.empty()) {
        if (!domain_name.empty()) {
          domain_name += ".";
        }
        domain_name += compressed_part;
      }

      jump_count++;
      break;  // After following a pointer, we're done with this name
    }

    if (length > 63 || pos + length + 1 > data.size()) {
      // Invalid label length
      break;
    }

    if (!domain_name.empty()) {
      domain_name += ".";
    }

    domain_name += std::string(data.begin() + pos + 1, data.begin() + pos + 1 + length);
    pos += length + 1;
  }

  return domain_name;
}

std::string ResponseProcessor::parse_soa_record(const std::vector<uint8_t>& rdata,
                                                const std::vector<uint8_t>& full_packet) {
  if (rdata.size() < 20) {  // Minimum size for SOA record
    return "";
  }

  try {
    size_t pos = 0;

    // Parse MNAME (primary name server)
    std::string mname = parse_domain_name_with_compression(rdata, pos, full_packet);
    if (mname.empty()) return "";

    // Skip past the MNAME to find RNAME position
    pos = skip_domain_name(rdata, pos);
    if (pos >= rdata.size()) return "";

    // Parse RNAME (responsible person email)
    std::string rname = parse_domain_name_with_compression(rdata, pos, full_packet);
    if (rname.empty()) return "";

    // Skip past the RNAME to find the numeric fields
    pos = skip_domain_name(rdata, pos);
    if (pos + 20 > rdata.size()) return "";

    // Parse the 5 32-bit fields: SERIAL REFRESH RETRY EXPIRE MINIMUM
    uint32_t serial =
        (static_cast<uint32_t>(rdata[pos]) << 24) | (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
        (static_cast<uint32_t>(rdata[pos + 2]) << 8) | static_cast<uint32_t>(rdata[pos + 3]);
    pos += 4;

    uint32_t refresh =
        (static_cast<uint32_t>(rdata[pos]) << 24) | (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
        (static_cast<uint32_t>(rdata[pos + 2]) << 8) | static_cast<uint32_t>(rdata[pos + 3]);
    pos += 4;

    uint32_t retry =
        (static_cast<uint32_t>(rdata[pos]) << 24) | (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
        (static_cast<uint32_t>(rdata[pos + 2]) << 8) | static_cast<uint32_t>(rdata[pos + 3]);
    pos += 4;

    uint32_t expire =
        (static_cast<uint32_t>(rdata[pos]) << 24) | (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
        (static_cast<uint32_t>(rdata[pos + 2]) << 8) | static_cast<uint32_t>(rdata[pos + 3]);
    pos += 4;

    uint32_t minimum =
        (static_cast<uint32_t>(rdata[pos]) << 24) | (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
        (static_cast<uint32_t>(rdata[pos + 2]) << 8) | static_cast<uint32_t>(rdata[pos + 3]);

    // Format SOA record
    return mname + " " + rname + " " + std::to_string(serial) + " " + std::to_string(refresh) +
           " " + std::to_string(retry) + " " + std::to_string(expire) + " " +
           std::to_string(minimum);
  } catch (const std::exception& e) {
    log_verbose("Error parsing SOA record: " + std::string(e.what()));
    return "";
  }
}

std::string ResponseProcessor::parse_srv_record(const std::vector<uint8_t>& rdata,
                                                const std::vector<uint8_t>& full_packet) {
  if (rdata.size() < 7) {  // Minimum size: 2+2+2+1 (priority+weight+port+domain)
    return "";
  }

  try {
    // Parse priority (2 bytes)
    uint16_t priority = (static_cast<uint16_t>(rdata[0]) << 8) | rdata[1];

    // Parse weight (2 bytes)
    uint16_t weight = (static_cast<uint16_t>(rdata[2]) << 8) | rdata[3];

    // Parse port (2 bytes)
    uint16_t port = (static_cast<uint16_t>(rdata[4]) << 8) | rdata[5];

    // Parse target domain (starting from byte 6)
    std::vector<uint8_t> domain_data(rdata.begin() + 6, rdata.end());
    std::string target = parse_domain_name_with_compression(domain_data, 0, full_packet);

    if (target.empty()) {
      return std::to_string(priority) + " " + std::to_string(weight) + " " + std::to_string(port) +
             " (failed to parse target)";
    }

    return std::to_string(priority) + " " + std::to_string(weight) + " " + std::to_string(port) +
           " " + target;
  } catch (const std::exception& e) {
    log_verbose("Error parsing SRV record: " + std::string(e.what()));
    return "";
  }
}

size_t ResponseProcessor::skip_domain_name(const std::vector<uint8_t>& data, size_t start_pos) {
  size_t pos = start_pos;

  while (pos < data.size()) {
    uint8_t length = data[pos];

    if (length == 0) {
      // End of domain name
      return pos + 1;
    }

    if ((length & 0xC0) == 0xC0) {
      // Compression pointer - skip 2 bytes and we're done
      return pos + 2;
    }

    if (length > 63 || pos + length + 1 > data.size()) {
      // Invalid label length
      break;
    }

    pos += length + 1;
  }

  return data.size();  // Error case
}

void ResponseProcessor::log_verbose(const std::string& message) const {
  if (config_.verbose) {
    std::cout << "[VERBOSE] " << message << std::endl;
  }
}

}  // namespace dns_resolver
