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

      auto response = query_server(server, domain, type);
      if (response.empty())
      {
        continue;
      }

      auto process_result = process_response(response, domain, type);

      if (process_result.has_answer && !process_result.addresses.empty())
      {
        // Found answer
        ResolutionResult result(process_result.addresses);
        return result;
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
                                                     const std::string &domain, RecordType type)
  {
    ProcessResult result;

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
        }
        else if (rr.type == RecordType::CNAME)
        {
          // For now, skip CNAME processing - this would require parsing domain names from rdata
          // result.cname_target = extract_cname_target(rr.rdata);
        }
      }

      // Check for referrals in authority section
      if (!result.has_answer)
      {
        std::vector<std::string> ns_names;
        for (const auto &rr : message.authorities)
        {
          if (rr.type == RecordType::NS)
          {
            // For now, we'll extract glue records from additional section
            // NS name extraction from rdata would require domain name parsing
            ns_names.push_back(rr.name); // Use the domain being delegated
          }
        }

        // Extract glue records from additional section
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
