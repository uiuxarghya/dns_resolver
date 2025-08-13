#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "../resolver/utils.h"

namespace dns_resolver {

// Forward declarations
struct ResolutionResult;

/**
 * @brief Typed address for multi-type queries
 */
struct TypedAddress {
  std::string address;
  RecordType type;
};

/**
 * @brief Combined resolution result for multi-type queries
 */
struct CombinedResolutionResult {
  std::vector<TypedAddress> records;
  bool success = false;
  std::chrono::milliseconds resolution_time{0};
  bool from_cache = false;
  std::string error_message;
};

/**
 * @brief Output formatter for DNS resolution results
 *
 * This class handles formatting and colorization of DNS resolution
 * results for console output.
 */
class OutputFormatter {
public:
  /**
   * @brief Print resolution result
   * @param result Resolution result to print
   * @param domain Domain that was queried
   * @param type Record type that was queried
   * @param verbose Whether to show verbose output
   * @param type_label_override Override for type label display
   */
  static void print_resolution_result(const ResolutionResult& result, const std::string& domain,
                                      RecordType type, bool verbose,
                                      const std::string& type_label_override = "");

  /**
   * @brief Print combined resolution result (for multi-type queries)
   * @param result Combined resolution result to print
   * @param domain Domain that was queried
   * @param verbose Whether to show verbose output
   * @param type_label_override Override for type label display
   */
  static void print_combined_resolution_result(const CombinedResolutionResult& result,
                                               const std::string& domain, bool verbose,
                                               const std::string& type_label_override = "");

  /**
   * @brief Check if stdout supports colors
   * @return True if colors are supported
   */
  static bool supports_color();

  /**
   * @brief Apply color to text if colors are supported
   * @param text Text to colorize
   * @param color Color code to apply
   * @return Colorized text or plain text if colors not supported
   */
  static std::string colorize(const std::string& text, const std::string& color);

private:
  /**
   * @brief Print performance metrics
   * @param resolution_time Time taken for resolution
   * @param from_cache Whether result came from cache
   */
  static void print_performance_metrics(std::chrono::milliseconds resolution_time, bool from_cache);

  /**
   * @brief Print DNS records
   * @param addresses List of addresses/records
   * @param type Record type
   */
  static void print_dns_records(const std::vector<std::string>& addresses, RecordType type);
};

/**
 * @brief ANSI color codes namespace
 */
namespace colors {
extern const std::string RESET;
extern const std::string BOLD;
extern const std::string RED;
extern const std::string GREEN;
extern const std::string YELLOW;
extern const std::string BLUE;
extern const std::string MAGENTA;
extern const std::string CYAN;
extern const std::string WHITE;
extern const std::string GRAY;
}  // namespace colors

}  // namespace dns_resolver
