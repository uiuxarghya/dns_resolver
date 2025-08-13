#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace dns_resolver {
namespace config {

/**
 * @brief Default configuration values for DNS Resolver
 */

// Network timeouts
constexpr std::chrono::seconds DEFAULT_UDP_TIMEOUT{5};
constexpr std::chrono::seconds DEFAULT_TCP_TIMEOUT{10};
constexpr std::chrono::milliseconds DEFAULT_RETRY_DELAY{100};

// Cache settings
constexpr size_t DEFAULT_MAX_CACHE_SIZE = 10000;
constexpr std::chrono::seconds DEFAULT_MIN_TTL{1};
constexpr std::chrono::seconds DEFAULT_MAX_TTL{86400};     // 24 hours
constexpr std::chrono::seconds DEFAULT_NEGATIVE_TTL{300};  // 5 minutes

// Resolution limits
constexpr int DEFAULT_MAX_RECURSION_DEPTH = 16;
constexpr size_t DEFAULT_MAX_RETRIES = 3;
constexpr size_t DEFAULT_MAX_CNAME_CHAIN = 10;
constexpr size_t DEFAULT_MAX_SERVERS_PER_QUERY = 3;

// Packet sizes
constexpr size_t UDP_MAX_PACKET_SIZE = 512;
constexpr size_t TCP_MAX_PACKET_SIZE = 65535;
constexpr size_t MAX_DOMAIN_NAME_LENGTH = 255;
constexpr size_t MAX_LABEL_LENGTH = 63;

// DNS protocol constants
constexpr uint16_t DNS_PORT = 53;
constexpr uint16_t DNS_HEADER_SIZE = 12;
constexpr uint16_t DNS_QUESTION_MIN_SIZE = 5;  // 1 byte name + 2 bytes type + 2 bytes class
constexpr uint16_t DNS_RR_MIN_SIZE = 11;  // 1 byte name + 2+2+4+2 bytes for type/class/ttl/rdlength

// DNS flags
constexpr uint16_t DNS_FLAG_QR = 0x8000;  // Query/Response
constexpr uint16_t DNS_FLAG_AA = 0x0400;  // Authoritative Answer
constexpr uint16_t DNS_FLAG_TC = 0x0200;  // Truncated
constexpr uint16_t DNS_FLAG_RD = 0x0100;  // Recursion Desired
constexpr uint16_t DNS_FLAG_RA = 0x0080;  // Recursion Available

// Compression
constexpr uint8_t DNS_COMPRESSION_MASK = 0xC0;
constexpr uint8_t DNS_COMPRESSION_POINTER = 0xC0;

// Application settings
constexpr const char *APPLICATION_NAME = "DNS Resolver";
constexpr const char *APPLICATION_VERSION = "1.0.0";
constexpr const char *APPLICATION_AUTHOR = "Arghya Ghosh";

// Logging levels
enum class LogLevel : int { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3, FATAL = 4 };

constexpr LogLevel DEFAULT_LOG_LEVEL = LogLevel::INFO;

// Performance tuning
constexpr size_t DEFAULT_THREAD_POOL_SIZE = 4;
constexpr size_t DEFAULT_CONNECTION_POOL_SIZE = 10;
constexpr std::chrono::seconds DEFAULT_CONNECTION_IDLE_TIMEOUT{30};

// Error handling
constexpr size_t DEFAULT_MAX_ERROR_RETRIES = 3;
constexpr std::chrono::milliseconds DEFAULT_ERROR_BACKOFF{500};

/**
 * @brief Environment variable names for configuration
 */
constexpr const char *ENV_UDP_TIMEOUT = "DNS_RESOLVER_UDP_TIMEOUT";
constexpr const char *ENV_TCP_TIMEOUT = "DNS_RESOLVER_TCP_TIMEOUT";
constexpr const char *ENV_MAX_CACHE_SIZE = "DNS_RESOLVER_MAX_CACHE_SIZE";
constexpr const char *ENV_MAX_RECURSION_DEPTH = "DNS_RESOLVER_MAX_RECURSION_DEPTH";
constexpr const char *ENV_ENABLE_IPV6 = "DNS_RESOLVER_ENABLE_IPV6";
constexpr const char *ENV_VERBOSE = "DNS_RESOLVER_VERBOSE";
constexpr const char *ENV_LOG_LEVEL = "DNS_RESOLVER_LOG_LEVEL";

/**
 * @brief Configuration validation functions
 */

/**
 * @brief Validate timeout value
 * @param timeout Timeout to validate
 * @return True if timeout is valid (between 1 and 300 seconds)
 */
constexpr bool is_valid_timeout(std::chrono::seconds timeout) {
  return timeout.count() >= 1 && timeout.count() <= 300;
}

/**
 * @brief Validate cache size
 * @param size Cache size to validate
 * @return True if size is valid (0 for unlimited, or between 100 and 1000000)
 */
constexpr bool is_valid_cache_size(size_t size) {
  return size == 0 || (size >= 100 && size <= 1000000);
}

/**
 * @brief Validate recursion depth
 * @param depth Recursion depth to validate
 * @return True if depth is valid (between 1 and 50)
 */
constexpr bool is_valid_recursion_depth(int depth) { return depth >= 1 && depth <= 50; }

/**
 * @brief Validate retry count
 * @param retries Retry count to validate
 * @return True if retry count is valid (between 0 and 10)
 */
constexpr bool is_valid_retry_count(size_t retries) { return retries <= 10; }

/**
 * @brief Utility functions for configuration
 */

/**
 * @brief Get configuration value from environment variable
 * @param env_var Environment variable name
 * @param default_value Default value if environment variable is not set
 * @return Configuration value
 */
std::string get_env_string(const char *env_var, const std::string &default_value);

/**
 * @brief Get integer configuration value from environment variable
 * @param env_var Environment variable name
 * @param default_value Default value if environment variable is not set
 * @return Configuration value
 */
int get_env_int(const char *env_var, int default_value);

/**
 * @brief Get boolean configuration value from environment variable
 * @param env_var Environment variable name
 * @param default_value Default value if environment variable is not set
 * @return Configuration value
 */
bool get_env_bool(const char *env_var, bool default_value);

/**
 * @brief Convert log level string to enum
 * @param level_str Log level string (debug, info, warn, error, fatal)
 * @return Log level enum
 */
LogLevel string_to_log_level(const std::string &level_str);

/**
 * @brief Convert log level enum to string
 * @param level Log level enum
 * @return Log level string
 */
std::string log_level_to_string(LogLevel level);

}  // namespace config
}  // namespace dns_resolver
