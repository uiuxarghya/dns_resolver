#include "recursion_handler.h"

#include <algorithm>
#include <iostream>
#include <random>

#include "../config/root_servers.h"
#include "query_engine.h"
#include "resolver.h"
#include "response_processor.h"

namespace dns_resolver {

RecursionHandler::RecursionHandler(const ResolverConfig& config,
                                   std::shared_ptr<QueryEngine> query_engine,
                                   std::shared_ptr<ResponseProcessor> response_processor)
    : config_(config), query_engine_(query_engine), response_processor_(response_processor) {}

ResolutionResult RecursionHandler::resolve_recursive(const std::string& domain, RecordType type,
                                                     const std::vector<std::string>& servers,
                                                     int depth) {
  if (depth > config_.max_recursion_depth) {
    ResolutionResult result;
    result.error_message = "Maximum recursion depth exceeded";
    return result;
  }

  log_verbose("Querying servers at depth " + std::to_string(depth) + " for " + domain);

  auto selected_servers = select_best_servers(servers, 3);

  for (const auto& server : selected_servers) {
    log_verbose("Querying server: " + server);

    // For root and TLD servers, we need to query for NS records to get referrals
    // Only query for the actual record type when we reach authoritative servers
    RecordType query_type = type;
    std::string query_domain = domain;

    if (depth == 0 && type != RecordType::NS) {
      // At root level: query for TLD NS records (e.g., "com." for "example.com")
      query_type = RecordType::NS;
      query_domain = extract_tld(domain);
      log_verbose("Querying root servers for TLD: " + query_domain);
    } else if (depth == 1 && type != RecordType::NS) {
      // At TLD level: try querying for the actual record type first
      // Many modern hosting providers (Wix, AWS, etc.) return direct answers from TLD servers
      log_verbose("Querying TLD servers for direct answer first");
      auto direct_response = query_engine_->query_server(server, domain, type);
      if (!direct_response.empty()) {
        auto direct_result =
            response_processor_->process_response(direct_response, domain, type, depth);
        if (direct_result.has_answer && !direct_result.addresses.empty()) {
          log_verbose("Got direct answer from TLD server");
          ResolutionResult result(direct_result.addresses);
          return result;
        }
        if (!direct_result.cname_target.empty()) {
          log_verbose("Got CNAME from TLD server: " + direct_result.cname_target);
          return follow_cname(direct_result.cname_target, type, depth + 1);
        }
      }

      // If no direct answer, fall back to querying for NS records
      query_type = RecordType::NS;
      log_verbose("No direct answer, querying TLD servers for domain NS records");
    }

    auto response = query_engine_->query_server(server, query_domain, query_type);
    if (response.empty()) {
      continue;
    }

    auto process_result =
        response_processor_->process_response(response, query_domain, query_type, depth);

    if (process_result.rcode != ResponseCode::NO_ERROR) {
      log_verbose("Server returned error code: " +
                  std::to_string(static_cast<int>(process_result.rcode)));
      continue;
    }

    // Check for CNAME in the response
    if (!process_result.cname_target.empty()) {
      log_verbose("Following CNAME: " + process_result.cname_target);
      return follow_cname(process_result.cname_target, type, depth + 1);
    }

    // Check if we got the answer we were looking for
    // Only treat as final answer if we're querying for the original record type we wanted
    if (process_result.has_answer && !process_result.addresses.empty() && query_type == type) {
      log_verbose("Got answer with " + std::to_string(process_result.addresses.size()) +
                  " records");
      ResolutionResult result(process_result.addresses);
      return result;
    }

    // If we were querying for NS records as part of recursive resolution,
    // treat the NS records as referrals, not final answers
    if (query_type == RecordType::NS && process_result.has_answer &&
        !process_result.addresses.empty()) {
      // The NS names are in addresses, but we need their IPs as referral servers
      // Check if we have glue records
      if (!process_result.referral_servers.empty()) {
        log_verbose("Following referral to " +
                    std::to_string(process_result.referral_servers.size()) +
                    " servers (from glue records)");
        return resolve_recursive(domain, type, process_result.referral_servers, depth + 1);
      } else {
        // No glue records, need to resolve the NS names to IPs
        log_verbose("Resolving NS names to IPs: " +
                    std::to_string(process_result.addresses.size()) + " servers");
        auto ns_ips = resolve_name_servers(process_result.addresses, depth + 1);
        if (!ns_ips.empty()) {
          return resolve_recursive(domain, type, ns_ips, depth + 1);
        }
      }
    }

    // If no direct answer but we have referral servers, follow them
    if (!process_result.referral_servers.empty()) {
      // Follow referral
      log_verbose("Following referral to " +
                  std::to_string(process_result.referral_servers.size()) + " servers");
      return resolve_recursive(domain, type, process_result.referral_servers, depth + 1);
    }
  }

  ResolutionResult result;
  result.error_message = "No response from any server";
  return result;
}

ResolutionResult RecursionHandler::follow_cname(const std::string& cname_target, RecordType type,
                                                int depth) {
  return resolve_recursive(cname_target, type, config::get_ipv4_root_servers(), depth);
}

std::vector<std::string> RecursionHandler::resolve_name_servers(
    const std::vector<std::string>& ns_names, int depth) {
  std::vector<std::string> ip_addresses;

  for (const auto& ns_name : ns_names) {
    log_verbose("Attempting to resolve NS: " + ns_name);

    // For NS resolution, try a more targeted approach
    // Query multiple root servers to increase chances of getting glue records
    if (depth < config_.max_recursion_depth) {
      std::vector<std::string> root_servers = config::get_ipv4_root_servers();

      // Try each root server - some might have better glue records
      for (const auto& root_server : root_servers) {
        log_verbose("Querying root server " + root_server + " for NS: " + ns_name);

        try {
          auto response = query_engine_->query_server(root_server, ns_name, RecordType::A, false);
          if (!response.empty()) {
            auto processed =
                response_processor_->process_response(response, ns_name, RecordType::A, depth);

            // If we got direct answers, use them
            if (processed.has_answer && !processed.addresses.empty()) {
              log_verbose("Got direct answer for NS: " + ns_name);
              ip_addresses.insert(ip_addresses.end(), processed.addresses.begin(),
                                  processed.addresses.end());
              break;  // Found answer, no need to try more root servers
            }

            // If we got referrals with glue records, try them
            if (!processed.referral_servers.empty()) {
              log_verbose("Got " + std::to_string(processed.referral_servers.size()) +
                          " referral servers for NS: " + ns_name);

              // Try resolving using the referred servers
              for (const auto& referred_server : processed.referral_servers) {
                try {
                  auto referred_response =
                      query_engine_->query_server(referred_server, ns_name, RecordType::A, false);
                  if (!referred_response.empty()) {
                    auto referred_processed = response_processor_->process_response(
                        referred_response, ns_name, RecordType::A, depth + 1);
                    if (referred_processed.has_answer && !referred_processed.addresses.empty()) {
                      log_verbose("Resolved NS " + ns_name + " via referred server " +
                                  referred_server);
                      ip_addresses.insert(ip_addresses.end(), referred_processed.addresses.begin(),
                                          referred_processed.addresses.end());
                      goto next_ns;  // Successfully resolved this NS, move to next
                    }
                  }
                } catch (const std::exception& e) {
                  log_verbose("Failed to query referred server " + referred_server + ": " +
                              e.what());
                  continue;  // Try next referred server
                }
              }
            }
          }
        } catch (const std::exception& e) {
          log_verbose("Failed to query root server " + root_server + ": " + e.what());
          continue;  // Try next root server
        }
      }
    }

  next_ns:;
  }

  log_verbose("Resolved " + std::to_string(ip_addresses.size()) + " IP addresses for NS names");
  return ip_addresses;
}

std::string RecursionHandler::extract_tld(const std::string& domain) {
  // Extract TLD from domain (e.g., "example.com" -> "com")
  size_t last_dot = domain.find_last_of('.');
  if (last_dot != std::string::npos && last_dot < domain.length() - 1) {
    return domain.substr(last_dot + 1);
  }

  // If no dot found, assume it's already a TLD
  return domain;
}

std::vector<std::string> RecursionHandler::select_best_servers(
    const std::vector<std::string>& servers, size_t max_servers) {
  std::vector<std::string> selected;
  if (servers.empty()) {
    return selected;
  }

  // If we have fewer servers than requested, return all
  if (servers.size() <= max_servers) {
    return servers;
  }

  // Separate IPv4 and IPv6 servers
  std::vector<std::string> ipv4_servers;
  std::vector<std::string> ipv6_servers;

  for (const auto& server : servers) {
    if (server.find(':') != std::string::npos) {
      ipv6_servers.push_back(server);
    } else {
      ipv4_servers.push_back(server);
    }
  }

  // Prefer IPv4 servers if available, then add IPv6 servers
  // This ensures better compatibility in environments with limited IPv6 connectivity
  std::vector<std::string> prioritized_servers;
  prioritized_servers.insert(prioritized_servers.end(), ipv4_servers.begin(), ipv4_servers.end());
  prioritized_servers.insert(prioritized_servers.end(), ipv6_servers.begin(), ipv6_servers.end());

  // Randomly shuffle within each group to maintain load distribution
  std::random_device rd;
  std::mt19937 g(rd());

  if (!ipv4_servers.empty()) {
    std::shuffle(prioritized_servers.begin(), prioritized_servers.begin() + ipv4_servers.size(), g);
  }
  if (!ipv6_servers.empty()) {
    std::shuffle(prioritized_servers.begin() + ipv4_servers.size(), prioritized_servers.end(), g);
  }

  selected.assign(prioritized_servers.begin(),
                  prioritized_servers.begin() + std::min(max_servers, prioritized_servers.size()));
  return selected;
}

void RecursionHandler::log_verbose(const std::string& message) const {
  if (config_.verbose) {
    std::cout << "[VERBOSE] " << message << std::endl;
  }
}

}  // namespace dns_resolver
