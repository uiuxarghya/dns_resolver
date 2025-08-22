#include "resolver.h"

#include <iostream>

#include "../config/root_servers.h"
#include "../net/tcp_client.h"
#include "../net/udp_client.h"
#include "packet_builder.h"
#include "query_engine.h"
#include "recursion_handler.h"
#include "response_processor.h"
#include "utils.h"

namespace dns_resolver {

Resolver::Resolver() : Resolver(ResolverConfig{}) {}

Resolver::Resolver(const ResolverConfig &config)
    : config_(config),
      cache_(std::make_unique<DnsCache>(config.max_cache_size, "./cache.txt")),
      udp_client_(std::make_unique<UdpClient>(config.query_timeout)),
      tcp_client_(std::make_unique<TcpClient>(config.query_timeout)),
      query_engine_(std::make_shared<QueryEngine>(config)),
      response_processor_(std::make_shared<ResponseProcessor>(config)),
      recursion_handler_(
          std::make_shared<RecursionHandler>(config, query_engine_, response_processor_)) {
  if (cache_) {
    cache_->load_from_file("./cache.txt");
  }
}

Resolver::~Resolver() = default;

ResolutionResult Resolver::resolve(const std::string &domain, RecordType type) {
  auto start_time = std::chrono::steady_clock::now();

  // For '.' domain, return root server IPs for A and AAAA queries
  if (domain == ".") {
    ResolutionResult result;
    if (type == RecordType::A) {
      auto ipv4_servers = config::get_ipv4_root_servers();
      result.addresses = ipv4_servers;
      result.success = !result.addresses.empty();
    } else if (type == RecordType::AAAA) {
      auto ipv6_servers = config::get_ipv6_root_servers();
      result.addresses = ipv6_servers;
      result.success = !result.addresses.empty();
    } else {
      result.error_message = "Root domain '.' is only used for root server connectivity checks.";
    }
    return result;
  }

  if (!utils::is_valid_domain_name(domain)) {
    ResolutionResult result;
    result.error_message = "Invalid domain name: " + domain;
    return result;
  }

  // Check cache first
  if (config_.enable_caching) {
    auto cached_result = check_cache(domain, type);
    if (cached_result) {
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
  if (config_.enable_ipv6) {
    auto ipv6_servers = config::get_ipv6_root_servers();
    root_servers.insert(root_servers.end(), ipv6_servers.begin(), ipv6_servers.end());
  }

  // Use the recursion handler for actual resolution
  auto result = recursion_handler_->resolve_recursive(domain, type, root_servers, 0);

  auto end_time = std::chrono::steady_clock::now();
  result.resolution_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

  // Cache the result if successful
  if (result.success && config_.enable_caching) {
    store_in_cache(domain, type, result, 300);  // Default 5 minutes TTL
  }

  return result;
}

std::future<ResolutionResult> Resolver::resolve_async(const std::string &domain, RecordType type) {
  return std::async(std::launch::async, [this, domain, type]() { return resolve(domain, type); });
}

ResolutionResult Resolver::resolve_all(const std::string &domain) {
  auto ipv4_future = resolve_async(domain, RecordType::A);
  auto ipv6_future = resolve_async(domain, RecordType::AAAA);

  auto ipv4_result = ipv4_future.get();
  auto ipv6_result = ipv6_future.get();

  ResolutionResult combined_result;
  combined_result.addresses.insert(combined_result.addresses.end(), ipv4_result.addresses.begin(),
                                   ipv4_result.addresses.end());
  combined_result.addresses.insert(combined_result.addresses.end(), ipv6_result.addresses.begin(),
                                   ipv6_result.addresses.end());

  combined_result.success = !combined_result.addresses.empty();
  combined_result.resolution_time =
      std::max(ipv4_result.resolution_time, ipv6_result.resolution_time);

  if (!combined_result.success) {
    combined_result.error_message = "No addresses found for " + domain;
  }

  return combined_result;
}

void Resolver::clear_cache() {
  if (cache_) {
    cache_->clear();
  }
}

DnsCache::CacheStats Resolver::get_cache_stats() const {
  if (cache_) {
    return cache_->get_stats();
  }
  return {};
}

void Resolver::update_config(const ResolverConfig &config) {
  config_ = config;
  if (cache_) {
    cache_->set_max_size(config.max_cache_size);
  }
  if (udp_client_) {
    udp_client_->set_timeout(config.query_timeout);
  }
  if (tcp_client_) {
    tcp_client_->set_timeout(config.query_timeout);
  }
  // Update module configurations
  if (query_engine_) {
    query_engine_->update_config(config);
  }
  // Note: response_processor_ and recursion_handler_ don't have update_config methods yet
}

bool Resolver::is_healthy() {
  bool any_success = false;
  log_verbose("Health check: Attempting to get root server list...");
  std::vector<std::string> root_servers;
  try {
    root_servers = config::get_ipv4_root_servers();
    log_verbose("Health check: Got " + std::to_string(root_servers.size()) + " root servers.");
  } catch (const std::exception &e) {
    log_verbose(std::string("Health check: Exception getting root server list: ") + e.what());
    return false;
  } catch (...) {
    log_verbose("Health check: Unknown exception getting root server list.");
    return false;
  }

  for (size_t i = 0; i < std::min(size_t(3), root_servers.size()); ++i) {
    auto packet =
        packet_builders::create_query(utils::generate_query_id(), ".", RecordType::NS, false);
    try {
      auto response = udp_client_->query(root_servers[i], packet);
      if (!response.empty()) {
        log_verbose("Health check: Successfully reached root server " + root_servers[i]);
        any_success = true;
      } else {
        log_verbose("Health check: No response from root server " + root_servers[i]);
      }
    } catch (const std::exception &e) {
      log_verbose("Health check: Exception querying root server " + root_servers[i] + ": " +
                  e.what());
    } catch (...) {
      log_verbose("Health check: Unknown exception querying root server " + root_servers[i]);
    }
  }
  return any_success;
}

// Cache-related private methods
std::optional<ResolutionResult> Resolver::check_cache(const std::string &domain, RecordType type) {
  if (!cache_) {
    return std::nullopt;
  }

  auto cache_key = domain + ":" + utils::record_type_to_string(type);
  auto cached_entry = cache_->get(cache_key);
  if (cached_entry) {
    log_verbose("Cache hit for " + cache_key);
    ResolutionResult result;
    result.addresses = cached_entry->records;  // CacheEntry uses 'records' field
    result.success = !result.addresses.empty();
    result.from_cache = true;
    return result;
  }

  log_verbose("Cache miss for " + cache_key);
  return std::nullopt;
}

void Resolver::store_in_cache(const std::string &domain, RecordType type,
                              const ResolutionResult &result, int ttl) {
  if (!cache_ || !result.success) {
    return;
  }

  auto cache_key = domain + ":" + utils::record_type_to_string(type);
  CacheEntry entry(result.addresses, ttl, type);  // Use CacheEntry constructor
  cache_->put(cache_key, entry);
  log_verbose("Cached result for " + cache_key + " (TTL: " + std::to_string(ttl) + "s)");
}

// Log a message if verbose mode is enabled
void Resolver::log_verbose(const std::string &message) const {
  if (config_.verbose) {
    std::cout << "[VERBOSE] " << message << std::endl;
  }
}

// Utility functions for creating specialized resolver instances
namespace resolver_utils {

std::unique_ptr<Resolver> create_fast_resolver() {
  ResolverConfig config;
  config.query_timeout = std::chrono::seconds(2);
  config.max_cache_size = 20000;
  config.max_retries = 1;
  return std::make_unique<Resolver>(config);
}

std::unique_ptr<Resolver> create_performance_resolver() {
  ResolverConfig config;
  config.query_timeout = std::chrono::seconds(3);
  config.max_cache_size = 50000;
  config.max_retries = 2;
  return std::make_unique<Resolver>(config);
}

std::unique_ptr<Resolver> create_reliable_resolver() {
  ResolverConfig config;
  config.query_timeout = std::chrono::seconds(10);
  config.max_cache_size = 10000;
  config.max_retries = 5;
  config.retry_delay = std::chrono::milliseconds(200);
  return std::make_unique<Resolver>(config);
}

ResolutionResult quick_resolve(const std::string &domain, RecordType type) {
  auto resolver = create_fast_resolver();
  return resolver->resolve(domain, type);
}

bool domain_exists(const std::string &domain) {
  auto result = quick_resolve(domain, RecordType::ANY);
  return result.success;
}

}  // namespace resolver_utils

}  // namespace dns_resolver
