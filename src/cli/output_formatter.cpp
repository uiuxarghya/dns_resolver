#include "output_formatter.h"

#include <unistd.h>

#include <iomanip>
#include <iostream>

#include "../resolver/resolver.h"

namespace dns_resolver {

// ANSI color codes
namespace colors {
const std::string RESET = "\033[0m";
const std::string BOLD = "\033[1m";
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string BLUE = "\033[34m";
const std::string MAGENTA = "\033[35m";
const std::string CYAN = "\033[36m";
const std::string WHITE = "\033[37m";
const std::string GRAY = "\033[90m";
}  // namespace colors

bool OutputFormatter::supports_color() { return isatty(STDOUT_FILENO); }

std::string OutputFormatter::colorize(const std::string &text, const std::string &color) {
  if (supports_color()) {
    return color + text + colors::RESET;
  }
  return text;
}

void OutputFormatter::print_combined_resolution_result(const CombinedResolutionResult &result,
                                                       const std::string &domain, bool verbose,
                                                       const std::string &type_label_override) {
  if (!result.success) {
    std::cerr << "\n" << colorize("✘ DNS Resolution Failed", colors::RED + colors::BOLD) << "\n";
    std::cerr << colorize("────────────────────────", colors::RED) << "\n";
    std::cerr << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::YELLOW + colors::BOLD) << "\n";
    std::cerr << colorize("→ Type: ", colors::GRAY) << colorize(type_label_override, colors::CYAN)
              << "\n";
    if (!result.error_message.empty()) {
      std::cerr << colorize("→ Error: ", colors::GRAY)
                << colorize(result.error_message, colors::RED) << "\n";
    }
    std::cerr << "\n";
    return;
  }

  if (verbose) {
    std::cout << "\n" << colorize("☰ Query Information", colors::BOLD + colors::BLUE) << "\n";
    std::cout << colorize("────────────────────", colors::BLUE) << "\n";
    std::cout << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    std::cout << colorize("→ Record Type: ", colors::GRAY)
              << colorize(type_label_override, colors::CYAN) << "\n";

    std::cout << "\n" << colorize("⏱︎ Performance Metrics", colors::BOLD + colors::YELLOW) << "\n";
    std::cout << colorize("────────────────────────", colors::YELLOW) << "\n";
    std::cout << colorize("→ Resolution Time: ", colors::GRAY)
              << colorize(std::to_string(result.resolution_time.count()) + " ms",
                          colors::YELLOW + colors::BOLD)
              << "\n";
    std::cout << colorize("→ Cache Status: ", colors::GRAY)
              << colorize(result.from_cache ? "HIT" : "MISS", result.from_cache
                                                                  ? colors::GREEN + colors::BOLD
                                                                  : colors::YELLOW + colors::BOLD)
              << "\n";
    std::cout << colorize("→ Records Found: ", colors::GRAY)
              << colorize(std::to_string(result.records.size()), colors::CYAN + colors::BOLD)
              << "\n";

    std::cout << "\n" << colorize("◎ DNS Resolution Results", colors::BOLD + colors::GREEN) << "\n";
    std::cout << colorize("──────────────────────────", colors::GREEN) << "\n";
  }

  // Print results with appropriate icons and labels
  for (const auto &rec : result.records) {
    std::string icon = "○";
    std::string color = colors::GREEN;
    std::string type_label = utils::record_type_to_string(rec.type);

    if (rec.type == RecordType::A) {
      icon = "◉";
      color = colors::GREEN;
      type_label = "IPv4";
    } else if (rec.type == RecordType::AAAA) {
      icon = "◆";
      color = colors::BLUE;
      type_label = "IPv6";
    } else if (rec.type == RecordType::TXT) {
      icon = "✎";
      color = colors::YELLOW;
      type_label = "Text";
    } else if (rec.type == RecordType::MX) {
      icon = "✉";
      color = colors::MAGENTA;
      type_label = "Mail";
    } else if (rec.type == RecordType::NS) {
      icon = "⚑";
      color = colors::CYAN;
      type_label = "NameServer";
    } else if (rec.type == RecordType::CNAME) {
      icon = "⇄";
      color = colors::BLUE;
      type_label = "Alias";
    } else if (rec.type == RecordType::SOA) {
      icon = "☗";
      color = colors::YELLOW;
      type_label = "Authority";
    } else if (rec.type == RecordType::SRV) {
      icon = "⚙";
      color = colors::GREEN;
      type_label = "Service";
    } else if (rec.type == RecordType::PTR) {
      icon = "↩";
      color = colors::CYAN;
      type_label = "Pointer";
    }

    if (verbose) {
      std::cout << colorize("  " + icon + " ", color);
      std::cout << colorize("[" + type_label + "] ", colors::GRAY);
      std::cout << colorize(rec.address, colors::WHITE + colors::BOLD) << "\n";
    } else {
      std::cout << rec.address << "\n";
    }
  }

  if (verbose) {
    if (!result.records.empty()) {
      std::cout << "\n" << colorize("✔ Resolution Status", colors::BOLD + colors::GREEN) << "\n";
      std::cout << colorize("───────────────────", colors::GREEN) << "\n";
      std::cout << colorize("✓ Successfully resolved ", colors::GREEN)
                << colorize(std::to_string(result.records.size()), colors::GREEN + colors::BOLD)
                << colorize(" record(s) for ", colors::GREEN)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    } else {
      std::cout << "\n" << colorize("⚠ No Records Found", colors::BOLD + colors::YELLOW) << "\n";
      std::cout << colorize("────────────────────", colors::YELLOW) << "\n";
      std::cout << colorize("→ No ", colors::YELLOW) << colorize(type_label_override, colors::CYAN)
                << colorize(" records found for ", colors::YELLOW)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    }
  }
}

void OutputFormatter::print_resolution_result(const ResolutionResult &result,
                                              const std::string &domain, RecordType type,
                                              bool verbose,
                                              const std::string &type_label_override) {
  if (!result.success) {
    // Error Section
    std::cerr << "\n" << colorize("✘ DNS Resolution Failed", colors::RED + colors::BOLD) << "\n";
    std::cerr << colorize("────────────────────────", colors::RED) << "\n";
    std::cerr << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::YELLOW + colors::BOLD) << "\n";
    std::cerr << colorize("→ Type: ", colors::GRAY)
              << colorize(utils::record_type_to_string(type), colors::CYAN) << "\n";
    if (!result.error_message.empty()) {
      std::cerr << colorize("→ Error: ", colors::GRAY)
                << colorize(result.error_message, colors::RED) << "\n";
    }
    std::cerr << "\n";
    return;
  }

  if (verbose) {
    // Query Information Section
    std::cout << "\n" << colorize("☰ Query Information", colors::BOLD + colors::BLUE) << "\n";
    std::cout << colorize("────────────────────", colors::BLUE) << "\n";
    std::cout << colorize("→ Domain: ", colors::GRAY)
              << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    // Show combined type for resolve_all or ANY
    if (!type_label_override.empty()) {
      std::cout << colorize("→ Record Type: ", colors::GRAY)
                << colorize(type_label_override, colors::CYAN) << "\n";
    } else {
      std::cout << colorize("→ Record Type: ", colors::GRAY)
                << colorize(utils::record_type_to_string(type), colors::CYAN) << "\n";
    }

    print_performance_metrics(result.resolution_time, result.from_cache);

    // Results Section Header
    std::cout << "\n" << colorize("◎ DNS Resolution Results", colors::BOLD + colors::GREEN) << "\n";
    std::cout << colorize("──────────────────────────", colors::GREEN) << "\n";
  }

  // Print results based on verbose mode
  if (verbose) {
    print_dns_records(result.addresses, type);
  } else {
    // Simple non-verbose output
    for (const auto &address : result.addresses) {
      std::cout << address << "\n";
    }
  }

  if (verbose) {
    if (!result.addresses.empty()) {
      std::cout << "\n" << colorize("✔ Resolution Status", colors::BOLD + colors::GREEN) << "\n";
      std::cout << colorize("────────────────────", colors::GREEN) << "\n";
      std::cout << colorize("✓ Successfully resolved ", colors::GREEN)
                << colorize(std::to_string(result.addresses.size()), colors::GREEN + colors::BOLD)
                << colorize(" record(s) for ", colors::GREEN)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    } else {
      std::cout << "\n" << colorize("⚠ No Records Found", colors::BOLD + colors::YELLOW) << "\n";
      std::cout << colorize("────────────────────", colors::YELLOW) << "\n";
      std::cout << colorize("→ No ", colors::YELLOW)
                << colorize(utils::record_type_to_string(type), colors::CYAN)
                << colorize(" records found for ", colors::YELLOW)
                << colorize(domain, colors::CYAN + colors::BOLD) << "\n";
    }
  }
}

void OutputFormatter::print_performance_metrics(std::chrono::milliseconds resolution_time,
                                                bool from_cache) {
  // Performance Metrics Section
  std::cout << "\n"
            << colorize("⏱\uFE0E Performance Metrics", colors::BOLD + colors::YELLOW) << "\n";
  std::cout << colorize("─────────────────────────", colors::YELLOW) << "\n";
  std::cout << colorize("→ Resolution Time: ", colors::GRAY)
            << colorize(std::to_string(resolution_time.count()) + " ms",
                        colors::YELLOW + colors::BOLD)
            << "\n";
  std::cout << colorize("→ Cache Status: ", colors::GRAY)
            << colorize(from_cache ? "HIT" : "MISS",
                        from_cache ? colors::GREEN + colors::BOLD : colors::YELLOW + colors::BOLD)
            << "\n";
}

void OutputFormatter::print_dns_records(const std::vector<std::string> &addresses,
                                        RecordType type) {
  // Print results with appropriate icons and colors
  for (size_t i = 0; i < addresses.size(); ++i) {
    std::string icon = "○";
    std::string color = colors::GREEN;
    std::string type_label = "";

    // Choose icon, color, and label based on record type and content
    if (type == RecordType::A) {
      icon = "◉";
      color = colors::GREEN;
      type_label = "IPv4";
    } else if (type == RecordType::AAAA) {
      icon = "◆";
      color = colors::BLUE;
      type_label = "IPv6";
    } else if (type == RecordType::TXT) {
      icon = "✎";
      color = colors::YELLOW;
      type_label = "Text";
    } else if (type == RecordType::MX) {
      icon = "✉";
      color = colors::MAGENTA;
      type_label = "Mail";
    } else if (type == RecordType::NS) {
      icon = "⚑";
      color = colors::CYAN;
      type_label = "NameServer";
    } else if (type == RecordType::CNAME) {
      icon = "⇄";
      color = colors::BLUE;
      type_label = "Alias";
    } else if (type == RecordType::SOA) {
      icon = "☗";
      color = colors::YELLOW;
      type_label = "Authority";
    } else if (type == RecordType::SRV) {
      icon = "⚙";
      color = colors::GREEN;
      type_label = "Service";
    } else if (type == RecordType::PTR) {
      icon = "↩";
      color = colors::CYAN;
      type_label = "Pointer";
    }

    std::cout << colorize("  " + icon + " ", color);
    if (!type_label.empty()) {
      std::cout << colorize("[" + type_label + "] ", colors::GRAY);
    }
    std::cout << colorize(addresses[i], colors::WHITE + colors::BOLD) << "\n";
  }
}

}  // namespace dns_resolver
