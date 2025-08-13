#pragma once

#include "../resolver/resolver.h"
#include "cli_parser.h"
#include "output_formatter.h"

namespace dns_resolver {

/**
 * @brief Main application class
 *
 * This class contains the main application logic for the DNS resolver,
 * coordinating between CLI parsing, DNS resolution, and output formatting.
 */
class Application {
public:
  /**
   * @brief Run the DNS resolver application
   * @param options Parsed command-line options
   * @return Exit code (0 for success, non-zero for error)
   */
  static int run_resolver(const CliOptions& options);

  /**
   * @brief Validate domain name
   * @param domain Domain to validate
   * @return True if domain is valid
   */
  static bool is_valid_domain(const std::string& domain);

private:
  /**
   * @brief Convert ResolutionResult to CombinedResolutionResult
   * @param result Single resolution result
   * @param type Record type
   * @return Combined resolution result
   */
  static CombinedResolutionResult convert_to_combined_result(const ResolutionResult& result,
                                                             RecordType type);

  /**
   * @brief Get type label for display
   * @param type Record type
   * @return Human-readable type label
   */
  static std::string get_type_label(RecordType type);
};

}  // namespace dns_resolver
