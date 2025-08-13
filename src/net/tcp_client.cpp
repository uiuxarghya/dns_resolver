#include "tcp_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "../resolver/utils.h"

namespace dns_resolver {

TcpClient::TcpClient(std::chrono::seconds timeout) : timeout_(timeout) {}

TcpClient::~TcpClient() {
  // TCP client is stateless - no persistent connections
}

TcpClient::TcpClient(TcpClient &&other) noexcept : timeout_(other.timeout_) {}

TcpClient &TcpClient::operator=(TcpClient &&other) noexcept {
  if (this != &other) {
    timeout_ = other.timeout_;
  }
  return *this;
}

std::vector<uint8_t> TcpClient::query(const std::string &server, uint16_t port,
                                      const std::vector<uint8_t> &packet) {
  if (packet.empty() || packet.size() > max_packet_size()) {
    throw NetworkException("Invalid packet size for TCP");
  }

  bool is_ipv6 = is_ipv6_address(server);
  int sock = create_socket(is_ipv6);
  if (sock == -1) {
    throw NetworkException("Failed to create TCP socket");
  }

  try {
    // Set socket timeout
    if (!set_socket_timeout(sock, timeout_)) {
      close_socket(sock);
      throw NetworkException("Failed to set socket timeout");
    }

    // Connect to server
    if (!connect_to_server(sock, server, port)) {
      close_socket(sock);
      throw NetworkException("Failed to connect to server: " + server);
    }

    // Send query with length prefix
    if (!send_tcp_packet(sock, packet)) {
      close_socket(sock);
      throw NetworkException("Failed to send TCP packet");
    }

    // Give the server a moment to process the request
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Receive response
    auto response = receive_tcp_packet(sock);
    close_socket(sock);

    if (response.empty()) {
      throw NetworkException("Failed to receive TCP response");
    }

    return response;
  } catch (...) {
    close_socket(sock);
    throw;
  }
}

void TcpClient::set_timeout(std::chrono::seconds timeout) { timeout_ = timeout; }

bool TcpClient::is_ready() const {
  return true;  // TCP client is always ready (creates connections on demand)
}

int TcpClient::create_socket(bool is_ipv6) {
  int sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
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

bool TcpClient::set_socket_timeout(int socket_fd, std::chrono::seconds timeout) {
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

bool TcpClient::connect_to_server(int socket_fd, const std::string &server, uint16_t port) {
  struct sockaddr_storage addr;
  socklen_t addr_len;

  if (!string_to_sockaddr(server, port, addr, addr_len)) {
    return false;
  }

  return connect(socket_fd, reinterpret_cast<struct sockaddr *>(&addr), addr_len) == 0;
}

bool TcpClient::is_ipv6_address(const std::string &ip_address) {
  struct sockaddr_in6 sa6;
  return inet_pton(AF_INET6, ip_address.c_str(), &sa6.sin6_addr) == 1;
}

bool TcpClient::string_to_sockaddr(const std::string &ip_address, uint16_t port,
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

bool TcpClient::send_tcp_packet(int socket_fd, const std::vector<uint8_t> &packet) {
  // TCP DNS messages are prefixed with a 2-byte length field
  std::vector<uint8_t> tcp_packet;
  tcp_packet.reserve(packet.size() + 2);

  // DNS TCP length is in network byte order (big-endian)
  uint16_t length = static_cast<uint16_t>(packet.size());
  tcp_packet.push_back(static_cast<uint8_t>(length >> 8));    // High byte first
  tcp_packet.push_back(static_cast<uint8_t>(length & 0xFF));  // Low byte second
  tcp_packet.insert(tcp_packet.end(), packet.begin(), packet.end());

  return send_all(socket_fd, tcp_packet);
}

std::vector<uint8_t> TcpClient::receive_tcp_packet(int socket_fd) {
  // First, read the 2-byte length prefix
  auto length_bytes = receive_exact(socket_fd, 2);
  if (length_bytes.size() != 2) {
    return {};
  }

  uint16_t length = (static_cast<uint16_t>(length_bytes[0]) << 8) | length_bytes[1];

  if (length == 0) {
    // Server sent zero-length response
    return {};
  }

  if (length > max_packet_size()) {
    // Response too large
    return {};
  }

  // Then read the actual DNS packet
  auto packet = receive_exact(socket_fd, length);
  if (packet.size() != length) {
    // Couldn't read the full packet
    return {};
  }

  return packet;
}

bool TcpClient::send_all(int socket_fd, const std::vector<uint8_t> &data) {
  size_t total_sent = 0;
  while (total_sent < data.size()) {
    if (!wait_for_writable(socket_fd, timeout_)) {
      return false;
    }

    ssize_t sent =
        send(socket_fd, data.data() + total_sent, data.size() - total_sent, MSG_NOSIGNAL);
    if (sent <= 0) {
      return false;
    }

    total_sent += static_cast<size_t>(sent);
  }

  return true;
}

std::vector<uint8_t> TcpClient::receive_exact(int socket_fd, size_t size) {
  std::vector<uint8_t> buffer(size);
  size_t total_received = 0;

  while (total_received < size) {
    if (!wait_for_readable(socket_fd, timeout_)) {
      return {};
    }

    ssize_t received = recv(socket_fd, buffer.data() + total_received, size - total_received, 0);
    if (received <= 0) {
      return {};
    }

    total_received += static_cast<size_t>(received);
  }

  return buffer;
}

bool TcpClient::wait_for_readable(int socket_fd, std::chrono::seconds timeout) {
  struct pollfd pfd;
  pfd.fd = socket_fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  int timeout_ms = static_cast<int>(timeout.count() * 1000);
  int result = poll(&pfd, 1, timeout_ms);

  return result > 0 && (pfd.revents & POLLIN);
}

bool TcpClient::wait_for_writable(int socket_fd, std::chrono::seconds timeout) {
  struct pollfd pfd;
  pfd.fd = socket_fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;

  int timeout_ms = static_cast<int>(timeout.count() * 1000);
  int result = poll(&pfd, 1, timeout_ms);

  return result > 0 && (pfd.revents & POLLOUT);
}

void TcpClient::close_socket(int socket_fd) {
  if (socket_fd != -1) {
    close(socket_fd);
  }
}

}  // namespace dns_resolver