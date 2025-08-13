#include "udp_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include "../resolver/utils.h"

namespace dns_resolver {

UdpClient::UdpClient(std::chrono::seconds timeout) : socket_fd_(-1), timeout_(timeout) {}

UdpClient::~UdpClient() { close_socket(); }

UdpClient::UdpClient(UdpClient &&other) noexcept
    : socket_fd_(other.socket_fd_), timeout_(other.timeout_) {
  other.socket_fd_ = -1;
}

UdpClient &UdpClient::operator=(UdpClient &&other) noexcept {
  if (this != &other) {
    close_socket();
    socket_fd_ = other.socket_fd_;
    timeout_ = other.timeout_;
    other.socket_fd_ = -1;
  }
  return *this;
}

std::vector<uint8_t> UdpClient::query(const std::string &server, uint16_t port,
                                      const std::vector<uint8_t> &packet) {
  if (packet.empty() || packet.size() > max_packet_size()) {
    throw NetworkException("Invalid packet size for UDP");
  }

  bool is_ipv6 = is_ipv6_address(server);
  int sock = create_socket(is_ipv6);
  if (sock == -1) {
    throw NetworkException("Failed to create UDP socket: " + std::string(strerror(errno)));
  }

  // Set socket timeout
  if (!set_socket_timeout(sock, timeout_)) {
    close(sock);
    throw NetworkException("Failed to set socket timeout");
  }

  try {
    // Convert server address
    struct sockaddr_storage addr;
    socklen_t addr_len;
    if (!string_to_sockaddr(server, port, addr, addr_len)) {
      close(sock);
      throw NetworkException("Invalid server address: " + server);
    }

    // Send query
    ssize_t sent = send_data(sock, packet, reinterpret_cast<struct sockaddr *>(&addr), addr_len);
    if (sent == -1 || static_cast<size_t>(sent) != packet.size()) {
      close(sock);
      throw NetworkException("Failed to send UDP packet");
    }

    // Wait for response
    if (!wait_for_readable(sock, timeout_)) {
      close(sock);
      throw TimeoutException("UDP query timeout");
    }

    // Receive response
    auto response = receive_data(sock, max_packet_size());
    close(sock);

    if (response.empty()) {
      throw NetworkException("Failed to receive UDP response");
    }

    return response;
  } catch (...) {
    close(sock);
    throw;
  }
}

void UdpClient::set_timeout(std::chrono::seconds timeout) { timeout_ = timeout; }

bool UdpClient::is_ready() const {
  return true;  // UDP client is always ready (stateless)
}

int UdpClient::create_socket(bool is_ipv6) {
  int sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    return -1;
  }

  // Enable dual-stack for IPv6 sockets
  if (is_ipv6) {
    int no = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
  }

  return sock;
}

void UdpClient::close_socket() {
  if (socket_fd_ != -1) {
    close(socket_fd_);
    socket_fd_ = -1;
  }
}

bool UdpClient::set_socket_timeout(int socket_fd, std::chrono::seconds timeout) {
  struct timeval tv;
  tv.tv_sec = timeout.count();
  tv.tv_usec = 0;

  if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    return false;
  }

  if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
    return false;
  }

  return true;
}

bool UdpClient::is_ipv6_address(const std::string &ip_address) {
  struct sockaddr_in6 sa6;
  return inet_pton(AF_INET6, ip_address.c_str(), &sa6.sin6_addr) == 1;
}

bool UdpClient::string_to_sockaddr(const std::string &ip_address, uint16_t port,
                                   struct sockaddr_storage &addr, socklen_t &addr_len) {
  memset(&addr, 0, sizeof(addr));

  if (is_ipv6_address(ip_address)) {
    struct sockaddr_in6 *addr6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    addr_len = sizeof(struct sockaddr_in6);
    return inet_pton(AF_INET6, ip_address.c_str(), &addr6->sin6_addr) == 1;
  } else {
    struct sockaddr_in *addr4 = reinterpret_cast<struct sockaddr_in *>(&addr);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    addr_len = sizeof(struct sockaddr_in);
    return inet_pton(AF_INET, ip_address.c_str(), &addr4->sin_addr) == 1;
  }
}

ssize_t UdpClient::send_data(int socket_fd, const std::vector<uint8_t> &data,
                             const struct sockaddr *addr, socklen_t addr_len) {
  return sendto(socket_fd, data.data(), data.size(), 0, addr, addr_len);
}

std::vector<uint8_t> UdpClient::receive_data(int socket_fd, size_t max_size) {
  std::vector<uint8_t> buffer(max_size);
  struct sockaddr_storage from_addr;
  socklen_t from_len = sizeof(from_addr);

  ssize_t received = recvfrom(socket_fd, buffer.data(), buffer.size(), 0,
                              reinterpret_cast<struct sockaddr *>(&from_addr), &from_len);

  if (received <= 0) {
    return {};
  }

  buffer.resize(static_cast<size_t>(received));
  return buffer;
}

bool UdpClient::wait_for_readable(int socket_fd, std::chrono::seconds timeout) {
  struct pollfd pfd;
  pfd.fd = socket_fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  int timeout_ms = static_cast<int>(timeout.count() * 1000);
  int result = poll(&pfd, 1, timeout_ms);

  return result > 0 && (pfd.revents & POLLIN);
}

}  // namespace dns_resolver
