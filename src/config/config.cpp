#include "config.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace dns_resolver {
namespace config {

std::string get_env_string(const char *env_var, const std::string &default_value) {
  const char *value = std::getenv(env_var);
  return value ? std::string(value) : default_value;
}

int get_env_int(const char *env_var, int default_value) {
  const char *value = std::getenv(env_var);
  if (!value) {
    return default_value;
  }

  try {
    return std::stoi(value);
  } catch (...) {
    return default_value;
  }
}

bool get_env_bool(const char *env_var, bool default_value) {
  const char *value = std::getenv(env_var);
  if (!value) {
    return default_value;
  }

  std::string str_value(value);
  std::transform(str_value.begin(), str_value.end(), str_value.begin(), ::tolower);

  return str_value == "true" || str_value == "1" || str_value == "yes" || str_value == "on";
}

LogLevel string_to_log_level(const std::string &level_str) {
  std::string lower_str = level_str;
  std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

  if (lower_str == "debug") return LogLevel::DEBUG;
  if (lower_str == "info") return LogLevel::INFO;
  if (lower_str == "warn" || lower_str == "warning") return LogLevel::WARN;
  if (lower_str == "error") return LogLevel::ERROR;
  if (lower_str == "fatal") return LogLevel::FATAL;

  return DEFAULT_LOG_LEVEL;
}

std::string log_level_to_string(LogLevel level) {
  switch (level) {
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::INFO:
      return "INFO";
    case LogLevel::WARN:
      return "WARN";
    case LogLevel::ERROR:
      return "ERROR";
    case LogLevel::FATAL:
      return "FATAL";
    default:
      return "INFO";
  }
}

}  // namespace config
}  // namespace dns_resolver
