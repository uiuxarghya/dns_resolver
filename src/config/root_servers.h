#pragma once

#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace dns_resolver {
namespace config {

/**
 * @brief Root DNS servers configuration
 *
 * This file contains the IP addresses of the 13 root DNS servers
 * that form the foundation of the DNS hierarchy. These servers
 * are operated by different organizations and provide the starting
 * point for all DNS resolution.
 */

/**
 * @brief IPv4 addresses of the 13 root DNS servers
 *
 * These addresses are stable and rarely change. They are maintained
 * by IANA and the root server operators.
 */
constexpr std::array<const char *, 13> ROOT_SERVERS_IPV4 = {
    "198.41.0.4",      // a.root-servers.net (VeriSign, Inc.)
    "199.9.14.201",    // b.root-servers.net (University of Southern California)
    "192.33.4.12",     // c.root-servers.net (Cogent Communications)
    "199.7.91.13",     // d.root-servers.net (University of Maryland)
    "192.203.230.10",  // e.root-servers.net (NASA Ames Research Center)
    "192.5.5.241",     // f.root-servers.net (Internet Systems Consortium, Inc.)
    "192.112.36.4",    // g.root-servers.net (US Department of Defense NIC)
    "198.97.190.53",   // h.root-servers.net (US Army Research Lab)
    "192.36.148.17",   // i.root-servers.net (Netnod)
    "192.58.128.30",   // j.root-servers.net (VeriSign, Inc.)
    "193.0.14.129",    // k.root-servers.net (RIPE NCC)
    "199.7.83.42",     // l.root-servers.net (ICANN)
    "202.12.27.33"     // m.root-servers.net (WIDE Project)
};

/**
 * @brief IPv6 addresses of the 13 root DNS servers
 *
 * Not all root servers support IPv6, so some entries may be empty.
 * IPv6 support is gradually being added to more root servers.
 */
constexpr std::array<const char *, 13> ROOT_SERVERS_IPV6 = {
    "2001:503:ba3e::2:30",  // a.root-servers.net
    "2001:500:200::b",      // b.root-servers.net
    "2001:500:2::c",        // c.root-servers.net
    "2001:500:2d::d",       // d.root-servers.net
    "2001:500:a8::e",       // e.root-servers.net
    "2001:500:2f::f",       // f.root-servers.net
    "2001:500:12::d0d",     // g.root-servers.net
    "2001:500:1::53",       // h.root-servers.net
    "2001:7fe::53",         // i.root-servers.net
    "2001:503:c27::2:30",   // j.root-servers.net
    "2001:7fd::1",          // k.root-servers.net
    "2001:500:9f::42",      // l.root-servers.net
    "2001:dc3::35"          // m.root-servers.net
};

/**
 * @brief Domain names of the 13 root DNS servers
 */
constexpr std::array<const char *, 13> ROOT_SERVERS_NAMES = {
    "a.root-servers.net", "b.root-servers.net", "c.root-servers.net", "d.root-servers.net",
    "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net",
    "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
    "m.root-servers.net"};

/**
 * @brief Get all IPv4 root server addresses
 * @return Vector of IPv4 addresses
 */
inline std::vector<std::string> get_ipv4_root_servers() {
  std::vector<std::string> servers;
  servers.reserve(ROOT_SERVERS_IPV4.size());
  for (const auto &server : ROOT_SERVERS_IPV4) {
    servers.emplace_back(server);
  }
  return servers;
}

/**
 * @brief Get all IPv6 root server addresses (excluding empty ones)
 * @return Vector of IPv6 addresses
 */
inline std::vector<std::string> get_ipv6_root_servers() {
  std::vector<std::string> servers;
  servers.reserve(ROOT_SERVERS_IPV6.size());
  for (const auto &server : ROOT_SERVERS_IPV6) {
    if (server && strlen(server) > 0) {
      servers.emplace_back(server);
    }
  }
  return servers;
}

/**
 * @brief Get all root server addresses (IPv4 and IPv6 combined)
 * @param prefer_ipv6 If true, IPv6 addresses come first
 * @return Vector of all root server addresses
 */
inline std::vector<std::string> get_all_root_servers(bool prefer_ipv6 = false) {
  std::vector<std::string> servers;

  if (prefer_ipv6) {
    auto ipv6_servers = get_ipv6_root_servers();
    auto ipv4_servers = get_ipv4_root_servers();
    servers.reserve(ipv6_servers.size() + ipv4_servers.size());
    servers.insert(servers.end(), ipv6_servers.begin(), ipv6_servers.end());
    servers.insert(servers.end(), ipv4_servers.begin(), ipv4_servers.end());
  } else {
    auto ipv4_servers = get_ipv4_root_servers();
    auto ipv6_servers = get_ipv6_root_servers();
    servers.reserve(ipv4_servers.size() + ipv6_servers.size());
    servers.insert(servers.end(), ipv4_servers.begin(), ipv4_servers.end());
    servers.insert(servers.end(), ipv6_servers.begin(), ipv6_servers.end());
  }

  return servers;
}

/**
 * @brief Get root server names
 * @return Vector of root server domain names
 */
inline std::vector<std::string> get_root_server_names() {
  std::vector<std::string> names;
  names.reserve(ROOT_SERVERS_NAMES.size());
  for (const auto &name : ROOT_SERVERS_NAMES) {
    names.emplace_back(name);
  }
  return names;
}

/**
 * @brief Get a specific root server's IPv4 address by index
 * @param index Root server index (0-12)
 * @return IPv4 address, or empty string if index is invalid
 */
inline std::string get_root_server_ipv4(size_t index) {
  if (index < ROOT_SERVERS_IPV4.size()) {
    return std::string(ROOT_SERVERS_IPV4[index]);
  }
  return "";
}

/**
 * @brief Get a specific root server's IPv6 address by index
 * @param index Root server index (0-12)
 * @return IPv6 address, or empty string if index is invalid or no IPv6 address
 */
inline std::string get_root_server_ipv6(size_t index) {
  if (index < ROOT_SERVERS_IPV6.size() && ROOT_SERVERS_IPV6[index] &&
      strlen(ROOT_SERVERS_IPV6[index]) > 0) {
    return std::string(ROOT_SERVERS_IPV6[index]);
  }
  return "";
}

/**
 * @brief Get a specific root server's name by index
 * @param index Root server index (0-12)
 * @return Root server name, or empty string if index is invalid
 */
inline std::string get_root_server_name(size_t index) {
  if (index < ROOT_SERVERS_NAMES.size()) {
    return std::string(ROOT_SERVERS_NAMES[index]);
  }
  return "";
}

/**
 * @brief Get the number of root servers
 * @return Number of root servers (always 13)
 */
constexpr size_t get_root_server_count() { return ROOT_SERVERS_IPV4.size(); }

}  // namespace config
}  // namespace dns_resolver
