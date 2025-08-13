#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace dns_resolver {

/**
 * @brief TCP client for DNS queries
 *
 * This class provides TCP transport for DNS queries, which is used as a fallback
 * when UDP responses are truncated (TC bit set) or when larger responses are expected.
 * TCP allows for larger DNS responses and reliable delivery.
 */
class TcpClient {
public:
  /**
   * @brief Construct a new TCP client
   * @param timeout Timeout for TCP operations
   */
  explicit TcpClient(std::chrono::seconds timeout = std::chrono::seconds(10));

  /**
   * @brief Destructor - ensures proper socket cleanup
   */
  ~TcpClient();

  // Disable copy constructor and assignment operator
  TcpClient(const TcpClient &) = delete;
  TcpClient &operator=(const TcpClient &) = delete;

  // Enable move constructor and assignment operator
  TcpClient(TcpClient &&other) noexcept;
  TcpClient &operator=(TcpClient &&other) noexcept;

  /**
   * @brief Send a DNS query to a server and receive the response
   * @param server Server IP address (IPv4 or IPv6)
   * @param port Server port (usually 53)
   * @param packet DNS query packet bytes
   * @return DNS response packet bytes, or empty vector on failure
   * @throws NetworkException on network errors
   * @throws TimeoutException on timeout
   */
  std::vector<uint8_t> query(const std::string &server, uint16_t port,
                             const std::vector<uint8_t> &packet);

  /**
   * @brief Send a DNS query with default port 53
   * @param server Server IP address
   * @param packet DNS query packet bytes
   * @return DNS response packet bytes, or empty vector on failure
   */
  std::vector<uint8_t> query(const std::string &server, const std::vector<uint8_t> &packet) {
    return query(server, 53, packet);
  }

  /**
   * @brief Set the timeout for TCP operations
   * @param timeout New timeout value
   */
  void set_timeout(std::chrono::seconds timeout);

  /**
   * @brief Get the current timeout setting
   * @return Current timeout value
   */
  std::chrono::seconds get_timeout() const { return timeout_; }

  /**
   * @brief Check if the client is ready for operations
   * @return True if the client is properly initialized
   */
  bool is_ready() const;

  /**
   * @brief Get the maximum TCP packet size
   * @return Maximum packet size in bytes (64KB for TCP)
   */
  static constexpr size_t max_packet_size() { return 65535; }

private:
  std::chrono::seconds timeout_;

  /**
   * @brief Create and configure a TCP socket
   * @param is_ipv6 True to create an IPv6 socket, false for IPv4
   * @return Socket file descriptor, or -1 on failure
   */
  int create_socket(bool is_ipv6);

  /**
   * @brief Set socket timeout options
   * @param socket_fd Socket file descriptor
   * @param timeout Timeout value
   * @return True on success, false on failure
   */
  bool set_socket_timeout(int socket_fd, std::chrono::seconds timeout);

  /**
   * @brief Connect to a DNS server
   * @param socket_fd Socket file descriptor
   * @param server Server IP address
   * @param port Server port
   * @return True on successful connection, false on failure
   */
  bool connect_to_server(int socket_fd, const std::string &server, uint16_t port);

  /**
   * @brief Check if an IP address is IPv6
   * @param ip_address IP address string
   * @return True if the address is IPv6
   */
  bool is_ipv6_address(const std::string &ip_address);

  /**
   * @brief Convert IP address string to sockaddr structure
   * @param ip_address IP address string
   * @param port Port number
   * @param addr Output sockaddr structure
   * @param addr_len Output address length
   * @return True on success, false on failure
   */
  bool string_to_sockaddr(const std::string &ip_address, uint16_t port,
                          struct sockaddr_storage &addr, socklen_t &addr_len);

  /**
   * @brief Send DNS packet over TCP with length prefix
   * @param socket_fd Socket file descriptor
   * @param packet DNS packet to send
   * @return True on success, false on failure
   */
  bool send_tcp_packet(int socket_fd, const std::vector<uint8_t> &packet);

  /**
   * @brief Receive DNS packet over TCP with length prefix
   * @param socket_fd Socket file descriptor
   * @return Received DNS packet, or empty vector on failure
   */
  std::vector<uint8_t> receive_tcp_packet(int socket_fd);

  /**
   * @brief Send all data over TCP socket
   * @param socket_fd Socket file descriptor
   * @param data Data to send
   * @return True if all data was sent, false on error
   */
  bool send_all(int socket_fd, const std::vector<uint8_t> &data);

  /**
   * @brief Receive exact number of bytes from TCP socket
   * @param socket_fd Socket file descriptor
   * @param size Number of bytes to receive
   * @return Received data, or empty vector on error
   */
  std::vector<uint8_t> receive_exact(int socket_fd, size_t size);

  /**
   * @brief Wait for socket to become readable
   * @param socket_fd Socket file descriptor
   * @param timeout Timeout for the operation
   * @return True if socket is readable, false on timeout or error
   */
  bool wait_for_readable(int socket_fd, std::chrono::seconds timeout);

  /**
   * @brief Wait for socket to become writable
   * @param socket_fd Socket file descriptor
   * @param timeout Timeout for the operation
   * @return True if socket is writable, false on timeout or error
   */
  bool wait_for_writable(int socket_fd, std::chrono::seconds timeout);

  /**
   * @brief Close a socket safely
   * @param socket_fd Socket file descriptor to close
   */
  void close_socket(int socket_fd);
};

}  // namespace dns_resolver
