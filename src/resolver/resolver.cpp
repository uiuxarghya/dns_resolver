#include "resolver.h"
#include "packet_builder.h"
#include "packet_parser.h"
#include "../net/udp_client.h"
#include "../net/tcp_client.h"
#include "../config/root_servers.h"
#include <iostream>
#include <thread>
#include <random>

namespace dns_resolver
{

  Resolver::Resolver() : Resolver(ResolverConfig{})
  {
  }

  Resolver::Resolver(const ResolverConfig &config)
      : config_(config),
        cache_(std::make_unique<DnsCache>(config.max_cache_size)),
        udp_client_(std::make_unique<UdpClient>(config.query_timeout)),
        tcp_client_(std::make_unique<TcpClient>(config.query_timeout))
  {
  }

  Resolver::~Resolver() = default;

  ResolutionResult Resolver::resolve(const std::string &domain, RecordType type)
  {
    auto start_time = std::chrono::steady_clock::now();

    if (!is_valid_domain(domain))
    {
      ResolutionResult result;
      result.error_message = "Invalid domain name: " + domain;
      return result;
    }

    // Check cache first
    if (config_.enable_caching)
    {
      auto cached_result = check_cache(domain, type);
      if (cached_result)
      {
        cached_result->from_cache = true;
        auto end_time = std::chrono::steady_clock::now();
        cached_result->resolution_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        return *cached_result;
      }
    }

    log_verbose("Starting recursive resolution for " + domain);

    // Start with root servers
    auto root_servers = config::get_ipv4_root_servers();
    if (config_.enable_ipv6)
    {
      auto ipv6_servers = config::get_ipv6_root_servers();
      root_servers.insert(root_servers.end(), ipv6_servers.begin(), ipv6_servers.end());
    }

    auto result = resolve_recursive(domain, type, root_servers, 0);

    // Note: No public DNS fallback - using pure recursive resolution only

    auto end_time = std::chrono::steady_clock::now();
    result.resolution_time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Cache the result if successful
    if (result.success && config_.enable_caching)
    {
      store_in_cache(domain, type, result, 300); // Default 5 minutes TTL
    }

    return result;
  }

  std::future<ResolutionResult> Resolver::resolve_async(const std::string &domain, RecordType type)
  {
    return std::async(std::launch::async, [this, domain, type]()
                      { return resolve(domain, type); });
  }

  ResolutionResult Resolver::resolve_all(const std::string &domain)
  {
    auto ipv4_future = resolve_async(domain, RecordType::A);
    auto ipv6_future = resolve_async(domain, RecordType::AAAA);

    auto ipv4_result = ipv4_future.get();
    auto ipv6_result = ipv6_future.get();

    ResolutionResult combined_result;
    combined_result.addresses.insert(combined_result.addresses.end(),
                                     ipv4_result.addresses.begin(), ipv4_result.addresses.end());
    combined_result.addresses.insert(combined_result.addresses.end(),
                                     ipv6_result.addresses.begin(), ipv6_result.addresses.end());

    combined_result.success = !combined_result.addresses.empty();
    combined_result.resolution_time = std::max(ipv4_result.resolution_time, ipv6_result.resolution_time);

    if (!combined_result.success)
    {
      combined_result.error_message = "No addresses found for " + domain;
    }

    return combined_result;
  }

  void Resolver::clear_cache()
  {
    if (cache_)
    {
      cache_->clear();
    }
  }

  DnsCache::CacheStats Resolver::get_cache_stats() const
  {
    if (cache_)
    {
      return cache_->get_stats();
    }
    return {};
  }

  void Resolver::update_config(const ResolverConfig &config)
  {
    config_ = config;
    if (cache_)
    {
      cache_->set_max_size(config.max_cache_size);
    }
    if (udp_client_)
    {
      udp_client_->set_timeout(config.query_timeout);
    }
    if (tcp_client_)
    {
      tcp_client_->set_timeout(config.query_timeout);
    }
  }

  bool Resolver::is_healthy()
  {
    try
    {
      auto root_servers = config::get_ipv4_root_servers();
      for (size_t i = 0; i < std::min(size_t(3), root_servers.size()); ++i)
      {
        auto packet = packet_builders::create_query(generate_query_id(), ".", RecordType::NS, false);
        auto response = udp_client_->query(root_servers[i], packet);
        if (!response.empty())
        {
          return true;
        }
      }
    }
    catch (...)
    {
      // Ignore exceptions for health check
    }
    return false;
  }

  ResolutionResult Resolver::resolve_recursive(const std::string &domain, RecordType type,
                                               const std::vector<std::string> &servers, int depth)
  {
    if (depth > config_.max_recursion_depth)
    {
      ResolutionResult result;
      result.error_message = "Maximum recursion depth exceeded";
      return result;
    }

    log_verbose("Querying servers at depth " + std::to_string(depth) + " for " + domain);

    auto selected_servers = select_best_servers(servers, 3);

    for (const auto &server : selected_servers)
    {
      log_verbose("Querying server: " + server);

      // For root and TLD servers, we need to query for NS records to get referrals
      // Only query for the actual record type when we reach authoritative servers
      RecordType query_type = type;
      std::string query_domain = domain;

      if (depth == 0 && type != RecordType::NS)
      {
        // At root level: query for TLD NS records (e.g., "com." for "google.com")
        query_type = RecordType::NS;
        query_domain = extract_tld(domain);
        log_verbose("Querying root servers for TLD: " + query_domain);
      }
      else if (depth == 1 && type != RecordType::NS)
      {
        // At TLD level: query for domain NS records
        query_type = RecordType::NS;
        log_verbose("Querying TLD servers for domain NS records");
      }

      auto response = query_server(server, query_domain, query_type);
      if (response.empty())
      {
        continue;
      }

      auto process_result = process_response(response, query_domain, query_type, depth);

      if (process_result.has_answer && !process_result.addresses.empty())
      {
        // If we queried for the actual record type and got an answer, we're done
        if (query_type == type)
        {
          ResolutionResult result(process_result.addresses);
          return result;
        }
        // If we queried for NS records and got an answer, these ARE the referral servers
        if (query_type == RecordType::NS)
        {
          log_verbose("Got NS records in answer section, extracting referral servers");

          // First, try to get glue records from the additional section
          std::vector<std::string> glue_ips;
          if (!process_result.referral_servers.empty())
          {
            glue_ips = process_result.referral_servers;
            log_verbose("Found " + std::to_string(glue_ips.size()) + " glue records");
          }

          // If we have glue records, use them directly
          if (!glue_ips.empty())
          {
            log_verbose("Using glue records, following referral to " + std::to_string(glue_ips.size()) + " servers");
            return resolve_recursive(domain, type, glue_ips, depth + 1);
          }

          // If no glue records, try to resolve NS names (but avoid infinite recursion)
          if (depth < 2)
          { // Only resolve NS names at shallow depths
            auto resolved_ips = resolve_name_servers(process_result.addresses, depth + 1);
            if (!resolved_ips.empty())
            {
              log_verbose("Resolved NS names, following referral to " + std::to_string(resolved_ips.size()) + " servers");
              return resolve_recursive(domain, type, resolved_ips, depth + 1);
            }
          }
          else
          {
            log_verbose("Maximum depth reached, cannot resolve NS names recursively");
          }
        }
      }

      if (!process_result.cname_target.empty())
      {
        // Follow CNAME
        log_verbose("Following CNAME to: " + process_result.cname_target);
        return follow_cname(process_result.cname_target, type, depth + 1);
      }

      if (!process_result.referral_servers.empty())
      {
        // Follow referral
        log_verbose("Following referral to " + std::to_string(process_result.referral_servers.size()) + " servers");
        return resolve_recursive(domain, type, process_result.referral_servers, depth + 1);
      }
    }

    ResolutionResult result;
    result.error_message = "No response from any server";
    return result;
  }

  std::vector<uint8_t> Resolver::query_server(const std::string &server, const std::string &domain,
                                              RecordType type, bool use_tcp)
  {
    try
    {
      auto packet = packet_builders::create_query(generate_query_id(), domain, type, true);

      if (use_tcp || !tcp_client_)
      {
        return tcp_client_->query(server, packet);
      }
      else
      {
        auto response = udp_client_->query(server, packet);

        // Check if response is truncated
        if (!response.empty() && packet_parsers::is_truncated_response(response))
        {
          log_verbose("Response truncated, retrying with TCP");
          return tcp_client_->query(server, packet);
        }

        return response;
      }
    }
    catch (const std::exception &e)
    {
      log_verbose("Query failed: " + std::string(e.what()));
      return {};
    }
  }

  Resolver::ProcessResult Resolver::process_response(const std::vector<uint8_t> &response,
                                                     const std::string &domain, RecordType type, int depth)
  {
    ProcessResult result;
    (void)domain; // Mark as unused - domain is used for logging/debugging in verbose mode

    try
    {
      PacketParser parser(response);
      auto message = parser.parse();

      result.rcode = static_cast<ResponseCode>(message.header.get_rcode());
      result.is_authoritative = message.header.is_authoritative();

      if (result.rcode != ResponseCode::NO_ERROR)
      {
        return result;
      }

      // Check for answers
      for (const auto &rr : message.answers)
      {
        if (rr.type == type)
        {
          result.has_answer = true;
          if (type == RecordType::A && rr.rdata.size() == 4)
          {
            auto addr = utils::ipv4_to_string(rr.rdata);
            if (!addr.empty())
              result.addresses.push_back(addr);
          }
          else if (type == RecordType::AAAA && rr.rdata.size() == 16)
          {
            auto addr = utils::ipv6_to_string(rr.rdata);
            if (!addr.empty())
              result.addresses.push_back(addr);
          }
          else if (type == RecordType::TXT)
          {
            auto txt = rr.get_txt_record();
            if (!txt.empty())
              result.addresses.push_back(txt);
          }
          else if (type == RecordType::MX)
          {
            // MX records have priority (2 bytes) + domain name
            if (rr.rdata.size() >= 3)
            {
              uint16_t priority = (static_cast<uint16_t>(rr.rdata[0]) << 8) | rr.rdata[1];
              // Extract domain name starting from byte 2
              std::vector<uint8_t> domain_data(rr.rdata.begin() + 2, rr.rdata.end());
              std::string mx_domain = parse_domain_name_with_compression(domain_data, 0, response);
              if (!mx_domain.empty())
              {
                result.addresses.push_back(std::to_string(priority) + " " + mx_domain);
              }
              else
              {
                result.addresses.push_back(std::to_string(priority) + " (failed to parse domain)");
              }
            }
          }
          else if (type == RecordType::NS)
          {
            // Extract NS name from rdata
            std::string ns_name = extract_domain_name_from_rdata(rr.rdata, response);
            if (!ns_name.empty())
            {
              result.addresses.push_back(ns_name);
            }
            else
            {
              result.addresses.push_back("(Failed to parse NS name)");
            }
          }
          else if (type == RecordType::CNAME)
          {
            // Extract CNAME target from rdata
            std::string cname_target = extract_domain_name_from_rdata(rr.rdata, response);
            if (!cname_target.empty())
            {
              result.cname_target = cname_target;
              result.addresses.push_back(cname_target);
            }
          }
          else if (type == RecordType::PTR)
          {
            // PTR records contain a domain name (for reverse DNS)
            std::string ptr_domain = extract_domain_name_from_rdata(rr.rdata, response);
            if (!ptr_domain.empty())
            {
              result.addresses.push_back(ptr_domain);
            }
          }
          else if (type == RecordType::SOA)
          {
            // SOA records: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
            auto soa_record = parse_soa_record(rr.rdata, response);
            if (!soa_record.empty())
            {
              result.addresses.push_back(soa_record);
            }
          }
          else if (type == RecordType::SRV)
          {
            // SRV records: priority weight port target
            auto srv_record = parse_srv_record(rr.rdata, response);
            if (!srv_record.empty())
            {
              result.addresses.push_back(srv_record);
            }
          }
        }
        else if (rr.type == RecordType::CNAME)
        {
          // For now, skip CNAME processing - this would require parsing domain names from rdata
          // result.cname_target = extract_cname_target(rr.rdata);
        }
      }

      // If we have NS records in answer section, also check for glue records in additional section
      if (result.has_answer && type == RecordType::NS)
      {
        for (const auto &rr : message.additionals)
        {
          if (rr.type == RecordType::A && rr.rdata.size() == 4)
          {
            auto addr = utils::ipv4_to_string(rr.rdata);
            if (!addr.empty())
            {
              result.referral_servers.push_back(addr);
              log_verbose("Found glue record (A): " + addr);
            }
          }
          else if (rr.type == RecordType::AAAA && rr.rdata.size() == 16)
          {
            auto addr = utils::ipv6_to_string(rr.rdata);
            if (!addr.empty())
            {
              result.referral_servers.push_back(addr);
              log_verbose("Found glue record (AAAA): " + addr);
            }
          }
        }
      }

      // Check for referrals in authority section
      if (!result.has_answer)
      {
        std::vector<std::string> ns_names;

        // Extract NS names from authority section
        for (const auto &rr : message.authorities)
        {
          if (rr.type == RecordType::NS)
          {
            // Try to extract NS name from rdata (simplified domain name parsing)
            std::string ns_name = extract_domain_name_from_rdata(rr.rdata, response);
            if (!ns_name.empty())
            {
              ns_names.push_back(ns_name);
              log_verbose("Found NS: " + ns_name);
            }
          }
        }

        // First, try to find glue records in additional section
        for (const auto &rr : message.additionals)
        {
          if (rr.type == RecordType::A && rr.rdata.size() == 4)
          {
            auto addr = utils::ipv4_to_string(rr.rdata);
            if (!addr.empty())
            {
              result.referral_servers.push_back(addr);
            }
          }
          else if (rr.type == RecordType::AAAA && rr.rdata.size() == 16)
          {
            auto addr = utils::ipv6_to_string(rr.rdata);
            if (!addr.empty())
            {
              result.referral_servers.push_back(addr);
            }
          }
        }

        // If no glue records found, resolve NS names to IP addresses
        if (result.referral_servers.empty() && !ns_names.empty())
        {
          log_verbose("No glue records found, resolving NS names");
          auto resolved_ips = resolve_name_servers(ns_names, depth + 1);
          result.referral_servers.insert(result.referral_servers.end(),
                                         resolved_ips.begin(), resolved_ips.end());
        }
      }
    }
    catch (const std::exception &e)
    {
      log_verbose("Failed to process response: " + std::string(e.what()));
    }

    return result;
  }

  ResolutionResult Resolver::follow_cname(const std::string &cname_target, RecordType type, int depth)
  {
    return resolve_recursive(cname_target, type, config::get_ipv4_root_servers(), depth);
  }

  std::vector<std::string> Resolver::extract_glue_records(const std::vector<uint8_t> &response,
                                                          const std::vector<std::string> &ns_names)
  {
    // This functionality is now handled in process_response
    (void)response; // Mark as unused
    (void)ns_names; // Mark as unused
    return {};
  }

  std::vector<std::string> Resolver::resolve_name_servers(const std::vector<std::string> &ns_names, int depth)
  {
    std::vector<std::string> ip_addresses;

    for (const auto &ns_name : ns_names)
    {
      if (depth < config_.max_recursion_depth)
      {
        auto result = resolve_recursive(ns_name, RecordType::A, config::get_ipv4_root_servers(), depth);
        ip_addresses.insert(ip_addresses.end(), result.addresses.begin(), result.addresses.end());
      }
    }

    return ip_addresses;
  }

  std::string Resolver::extract_domain_name_from_rdata(const std::vector<uint8_t> &rdata,
                                                       const std::vector<uint8_t> &full_packet)
  {
    if (rdata.empty())
    {
      return "";
    }

    try
    {
      return parse_domain_name_with_compression(rdata, 0, full_packet);
    }
    catch (const std::exception &e)
    {
      log_verbose("Error parsing domain name from rdata: " + std::string(e.what()));
      return "";
    }
  }

  std::string Resolver::parse_domain_name_with_compression(const std::vector<uint8_t> &data,
                                                           size_t start_offset,
                                                           const std::vector<uint8_t> &full_packet)
  {
    std::string domain_name;
    size_t pos = start_offset;
    bool jumped = false;
    size_t jump_count = 0;
    const size_t max_jumps = 10; // Prevent infinite loops

    while (pos < data.size() && jump_count < max_jumps)
    {
      uint8_t length = data[pos];

      if (length == 0)
      {
        // End of domain name
        break;
      }

      if ((length & 0xC0) == 0xC0)
      {
        // Compression pointer
        if (pos + 1 >= data.size())
        {
          break; // Invalid pointer
        }

        uint16_t pointer = ((static_cast<uint16_t>(length & 0x3F) << 8) | data[pos + 1]);

        if (pointer >= full_packet.size())
        {
          log_verbose("Invalid compression pointer: " + std::to_string(pointer));
          break;
        }

        // Follow the pointer in the full packet
        std::string compressed_part = parse_domain_name_with_compression(full_packet, pointer, full_packet);
        if (!compressed_part.empty())
        {
          if (!domain_name.empty())
          {
            domain_name += ".";
          }
          domain_name += compressed_part;
        }

        jumped = true;
        jump_count++;
        break; // After following a pointer, we're done with this name
      }

      if (length > 63 || pos + length + 1 > data.size())
      {
        // Invalid label length
        break;
      }

      if (!domain_name.empty())
      {
        domain_name += ".";
      }

      domain_name += std::string(data.begin() + pos + 1, data.begin() + pos + 1 + length);
      pos += length + 1;
    }

    return domain_name;
  }

  std::string Resolver::extract_tld(const std::string &domain)
  {
    // Extract TLD from domain (e.g., "google.com" -> "com")
    size_t last_dot = domain.find_last_of('.');
    if (last_dot != std::string::npos && last_dot < domain.length() - 1)
    {
      return domain.substr(last_dot + 1);
    }

    // If no dot found, assume it's already a TLD
    return domain;
  }

  std::string Resolver::parse_soa_record(const std::vector<uint8_t> &rdata,
                                         const std::vector<uint8_t> &full_packet)
  {
    if (rdata.size() < 20)
    { // Minimum size for SOA record
      return "";
    }

    try
    {
      size_t pos = 0;

      // Parse MNAME (primary name server)
      std::string mname = parse_domain_name_with_compression(rdata, pos, full_packet);
      if (mname.empty())
        return "";

      // Skip past the MNAME to find RNAME position
      pos = skip_domain_name(rdata, pos);
      if (pos >= rdata.size())
        return "";

      // Parse RNAME (responsible person email)
      std::string rname = parse_domain_name_with_compression(rdata, pos, full_packet);
      if (rname.empty())
        return "";

      // Skip past the RNAME to find the numeric fields
      pos = skip_domain_name(rdata, pos);
      if (pos + 20 > rdata.size())
        return "";

      // Parse the 5 32-bit fields: SERIAL REFRESH RETRY EXPIRE MINIMUM
      uint32_t serial = (static_cast<uint32_t>(rdata[pos]) << 24) |
                        (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
                        (static_cast<uint32_t>(rdata[pos + 2]) << 8) |
                        static_cast<uint32_t>(rdata[pos + 3]);
      pos += 4;

      uint32_t refresh = (static_cast<uint32_t>(rdata[pos]) << 24) |
                         (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
                         (static_cast<uint32_t>(rdata[pos + 2]) << 8) |
                         static_cast<uint32_t>(rdata[pos + 3]);
      pos += 4;

      uint32_t retry = (static_cast<uint32_t>(rdata[pos]) << 24) |
                       (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
                       (static_cast<uint32_t>(rdata[pos + 2]) << 8) |
                       static_cast<uint32_t>(rdata[pos + 3]);
      pos += 4;

      uint32_t expire = (static_cast<uint32_t>(rdata[pos]) << 24) |
                        (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
                        (static_cast<uint32_t>(rdata[pos + 2]) << 8) |
                        static_cast<uint32_t>(rdata[pos + 3]);
      pos += 4;

      uint32_t minimum = (static_cast<uint32_t>(rdata[pos]) << 24) |
                         (static_cast<uint32_t>(rdata[pos + 1]) << 16) |
                         (static_cast<uint32_t>(rdata[pos + 2]) << 8) |
                         static_cast<uint32_t>(rdata[pos + 3]);

      // Format SOA record
      return mname + " " + rname + " " + std::to_string(serial) + " " +
             std::to_string(refresh) + " " + std::to_string(retry) + " " +
             std::to_string(expire) + " " + std::to_string(minimum);
    }
    catch (const std::exception &e)
    {
      log_verbose("Error parsing SOA record: " + std::string(e.what()));
      return "";
    }
  }

  std::string Resolver::parse_srv_record(const std::vector<uint8_t> &rdata,
                                         const std::vector<uint8_t> &full_packet)
  {
    if (rdata.size() < 7)
    { // Minimum size: 2+2+2+1 (priority+weight+port+domain)
      return "";
    }

    try
    {
      // Parse priority (2 bytes)
      uint16_t priority = (static_cast<uint16_t>(rdata[0]) << 8) | rdata[1];

      // Parse weight (2 bytes)
      uint16_t weight = (static_cast<uint16_t>(rdata[2]) << 8) | rdata[3];

      // Parse port (2 bytes)
      uint16_t port = (static_cast<uint16_t>(rdata[4]) << 8) | rdata[5];

      // Parse target domain (starting from byte 6)
      std::vector<uint8_t> domain_data(rdata.begin() + 6, rdata.end());
      std::string target = parse_domain_name_with_compression(domain_data, 0, full_packet);

      if (target.empty())
      {
        return std::to_string(priority) + " " + std::to_string(weight) + " " +
               std::to_string(port) + " (failed to parse target)";
      }

      return std::to_string(priority) + " " + std::to_string(weight) + " " +
             std::to_string(port) + " " + target;
    }
    catch (const std::exception &e)
    {
      log_verbose("Error parsing SRV record: " + std::string(e.what()));
      return "";
    }
  }

  size_t Resolver::skip_domain_name(const std::vector<uint8_t> &data, size_t start_pos)
  {
    size_t pos = start_pos;

    while (pos < data.size())
    {
      uint8_t length = data[pos];

      if (length == 0)
      {
        // End of domain name
        return pos + 1;
      }

      if ((length & 0xC0) == 0xC0)
      {
        // Compression pointer - skip 2 bytes and we're done
        return pos + 2;
      }

      if (length > 63 || pos + length + 1 > data.size())
      {
        // Invalid label length
        break;
      }

      pos += length + 1;
    }

    return data.size(); // Error case
  }

  std::optional<ResolutionResult> Resolver::check_cache(const std::string &domain, RecordType type)
  {
    if (!cache_)
      return std::nullopt;

    auto key = cache_utils::generate_cache_key(domain, type, RecordClass::IN);
    auto entry = cache_->get(key);

    if (!entry)
      return std::nullopt;

    ResolutionResult result;
    if (entry->is_negative)
    {
      result.success = false;
      result.error_message = "Cached negative response";
    }
    else
    {
      result.addresses = entry->records;
      result.success = !result.addresses.empty();
    }

    return result;
  }

  void Resolver::store_in_cache(const std::string &domain, RecordType type,
                                const ResolutionResult &result, uint32_t ttl)
  {
    if (!cache_)
      return;

    auto key = cache_utils::generate_cache_key(domain, type, RecordClass::IN);
    CacheEntry entry(result.addresses, ttl, type, !result.success);
    cache_->put(key, entry);
  }

  uint16_t Resolver::generate_query_id()
  {
    return utils::generate_query_id();
  }

  void Resolver::log_verbose(const std::string &message) const
  {
    if (config_.verbose)
    {
      std::cout << "[VERBOSE] " << message << std::endl;
    }
  }

  bool Resolver::is_valid_domain(const std::string &domain) const
  {
    return utils::is_valid_domain_name(domain);
  }

  std::vector<std::string> Resolver::select_best_servers(const std::vector<std::string> &servers,
                                                         size_t max_servers)
  {
    std::vector<std::string> selected;
    selected.reserve(std::min(servers.size(), max_servers));

    // Simple selection: take first max_servers entries
    for (size_t i = 0; i < std::min(servers.size(), max_servers); ++i)
    {
      selected.push_back(servers[i]);
    }

    return selected;
  }

  // Utility functions
  namespace resolver_utils
  {

    std::unique_ptr<Resolver> create_performance_resolver()
    {
      ResolverConfig config;
      config.query_timeout = std::chrono::seconds(3);
      config.max_cache_size = 50000;
      config.max_retries = 2;
      return std::make_unique<Resolver>(config);
    }

    std::unique_ptr<Resolver> create_reliable_resolver()
    {
      ResolverConfig config;
      config.query_timeout = std::chrono::seconds(10);
      config.max_retries = 5;
      config.enable_tcp_fallback = true;
      return std::make_unique<Resolver>(config);
    }

    ResolutionResult quick_resolve(const std::string &domain, RecordType type)
    {
      Resolver resolver;
      return resolver.resolve(domain, type);
    }

    bool domain_exists(const std::string &domain)
    {
      auto result = quick_resolve(domain, RecordType::ANY);
      return result.success;
    }

  } // namespace resolver_utils

} // namespace dns_resolver
