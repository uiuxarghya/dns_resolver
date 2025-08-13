#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace dns_resolver {

/**
 * @brief UDP client for DNS queries
 *
 * This class provides a simple interface for sending DNS queries over UDP.
 * It handles socket creation, timeout management, and proper cleanup.
 * UDP is the primary transport protocol for DNS queries.
 */
class UdpClient {
public:
  /**
   * @brief Construct a new UDP client
   * @param timeout Timeout for UDP operations
   */
  explicit UdpClient(std::chrono::seconds timeout = std::chrono::seconds(5));

  /**
   * @brief Destructor - ensures proper socket cleanup
   */
  ~UdpClient();

  // Disable copy constructor and assignment operator
  UdpClient(const UdpClient &) = delete;
  UdpClient &operator=(const UdpClient &) = delete;

  // Enable move constructor and assignment operator
  UdpClient(UdpClient &&other) noexcept;
  UdpClient &operator=(UdpClient &&other) noexcept;

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
   * @brief Set the timeout for UDP operations
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
   * @brief Get the maximum UDP packet size
   * @return Maximum packet size in bytes
   */
  static constexpr size_t max_packet_size() { return 512; }

private:
  int socket_fd_;
  std::chrono::seconds timeout_;

  /**
   * @brief Create and configure a UDP socket
   * @param is_ipv6 True to create an IPv6 socket, false for IPv4
   * @return Socket file descriptor, or -1 on failure
   */
  int create_socket(bool is_ipv6);

  /**
   * @brief Close the current socket if open
   */
  void close_socket();

  /**
   * @brief Set socket timeout options
   * @param socket_fd Socket file descriptor
   * @param timeout Timeout value
   * @return True on success, false on failure
   */
  bool set_socket_timeout(int socket_fd, std::chrono::seconds timeout);

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
   * @brief Send data over UDP socket
   * @param socket_fd Socket file descriptor
   * @param data Data to send
   * @param addr Destination address
   * @param addr_len Address length
   * @return Number of bytes sent, or -1 on error
   */
  ssize_t send_data(int socket_fd, const std::vector<uint8_t> &data, const struct sockaddr *addr,
                    socklen_t addr_len);

  /**
   * @brief Receive data from UDP socket
   * @param socket_fd Socket file descriptor
   * @param max_size Maximum bytes to receive
   * @return Received data, or empty vector on error/timeout
   */
  std::vector<uint8_t> receive_data(int socket_fd, size_t max_size);

  /**
   * @brief Wait for socket to become readable
   * @param socket_fd Socket file descriptor
   * @param timeout Timeout for the operation
   * @return True if socket is readable, false on timeout or error
   */
  bool wait_for_readable(int socket_fd, std::chrono::seconds timeout);
};

}  // namespace dns_resolver
