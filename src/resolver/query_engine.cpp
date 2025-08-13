#include "query_engine.h"

#include <iostream>

#include "../net/tcp_client.h"
#include "../net/udp_client.h"
#include "packet_builder.h"
#include "resolver.h"

namespace dns_resolver {

QueryEngine::QueryEngine(const ResolverConfig& config)
    : config_(config),
      udp_client_(std::make_unique<UdpClient>(config.query_timeout)),
      tcp_client_(std::make_unique<TcpClient>(config.query_timeout)) {}

QueryEngine::~QueryEngine() = default;

std::vector<uint8_t> QueryEngine::query_server(const std::string& server, const std::string& domain,
                                               RecordType type, bool use_tcp) {
  try {
    auto packet = packet_builders::create_query(generate_query_id(), domain, type, true);

    if (use_tcp || packet.size() > 512) {
      log_verbose("Using TCP for query to " + server);
      return tcp_client_->query(server, packet);
    } else {
      log_verbose("Using UDP for query to " + server);
      auto response = udp_client_->query(server, packet);

      // Check if response is truncated and retry with TCP if enabled
      if (!response.empty() && response.size() >= 12) {
        uint16_t flags = (static_cast<uint16_t>(response[2]) << 8) | response[3];
        bool truncated = (flags & 0x0200) != 0;

        if (truncated && config_.enable_tcp_fallback) {
          log_verbose("Response truncated, retrying with TCP");
          return tcp_client_->query(server, packet);
        }
      }

      return response;
    }
  } catch (const std::exception& e) {
    log_verbose("Query failed: " + std::string(e.what()));
    return {};
  }
}

void QueryEngine::update_config(const ResolverConfig& config) {
  if (udp_client_) {
    udp_client_->set_timeout(config.query_timeout);
  }
  if (tcp_client_) {
    tcp_client_->set_timeout(config.query_timeout);
  }
}

uint16_t QueryEngine::generate_query_id() { return utils::generate_query_id(); }

void QueryEngine::log_verbose(const std::string& message) const {
  if (config_.verbose) {
    std::cout << "[VERBOSE] " << message << std::endl;
  }
}

}  // namespace dns_resolver
