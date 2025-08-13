#pragma once

#include <chrono>
#include <string>

#include "../resolver/utils.h"

namespace dns_resolver {

/**
 * @brief Command-line options structure
 */
struct CliOptions {
  std::string domain;
  RecordType query_type = RecordType::A;
  bool verbose = false;
  bool show_help = false;
  bool show_version = false;
  bool resolve_all = false;
  std::chrono::seconds timeout{5};
};

/**
 * @brief Command-line argument parser
 *
 * This class handles parsing of command-line arguments and provides
 * help and version information.
 */
class CliParser {
public:
  /**
   * @brief Parse command-line arguments
   * @param argc Argument count
   * @param argv Argument values
   * @return Parsed CLI options
   */
  static CliOptions parse_arguments(int argc, char* argv[]);

  /**
   * @brief Print usage information
   * @param program_name Name of the program
   */
  static void print_usage(const char* program_name);

  /**
   * @brief Print version information
   */
  static void print_version();

private:
  /**
   * @brief Parse record type from string
   * @param type_str String representation of record type
   * @return Parsed record type
   */
  static RecordType parse_record_type(const std::string& type_str);
};

}  // namespace dns_resolver
