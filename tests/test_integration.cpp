#include <gtest/gtest.h>

#include <chrono>
#include <numeric>
#include <thread>

#include "../src/config/config.h"
#include "../src/config/root_servers.h"
#include "../src/resolver/resolver.h"

using namespace dns_resolver;

class IntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    ResolverConfig config;
    config.query_timeout = std::chrono::seconds(10);  // Longer timeout for real network
    config.max_retries = 3;
    config.verbose = false;  // Set to true for debugging
    resolver_ = std::make_unique<Resolver>(config);
  }

  std::unique_ptr<Resolver> resolver_;
};

// Note: These tests require internet connectivity and may fail in isolated environments
// They are designed to test against well-known, stable domains

TEST_F(IntegrationTest, DISABLED_ResolveWellKnownDomain) {
  // Test resolving a well-known domain
  auto result = resolver_->resolve("google.com", RecordType::A);

  if (result.success) {
    EXPECT_FALSE(result.addresses.empty());
    EXPECT_GT(result.resolution_time.count(), 0);

    // Verify IP address format
    for (const auto &addr : result.addresses) {
      EXPECT_FALSE(addr.empty());
      // Basic IPv4 format check (contains dots)
      EXPECT_NE(addr.find('.'), std::string::npos);
    }
  } else {
    // If resolution fails, it might be due to network issues
    std::cout << "Resolution failed (possibly no network): " << result.error_message << std::endl;
  }
}

TEST_F(IntegrationTest, DISABLED_ResolveIPv6) {
  auto result = resolver_->resolve("google.com", RecordType::AAAA);

  if (result.success) {
    EXPECT_FALSE(result.addresses.empty());

    // Verify IPv6 address format
    for (const auto &addr : result.addresses) {
      EXPECT_FALSE(addr.empty());
      // Basic IPv6 format check (contains colons)
      EXPECT_NE(addr.find(':'), std::string::npos);
    }
  }
}

TEST_F(IntegrationTest, DISABLED_ResolveMultipleTypes) {
  auto result = resolver_->resolve_all("cloudflare.com");

  if (result.success) {
    EXPECT_FALSE(result.addresses.empty());
    // Should have both IPv4 and IPv6 addresses for Cloudflare
  }
}

TEST_F(IntegrationTest, DISABLED_CacheEffectiveness) {
  // Clear cache first
  resolver_->clear_cache();

  // First resolution (should be from network)
  auto start1 = std::chrono::steady_clock::now();
  auto result1 = resolver_->resolve("example.com", RecordType::A);
  auto end1 = std::chrono::steady_clock::now();
  auto time1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);

  if (result1.success) {
    EXPECT_FALSE(result1.from_cache);

    // Second resolution (should be from cache)
    auto start2 = std::chrono::steady_clock::now();
    auto result2 = resolver_->resolve("example.com", RecordType::A);
    auto end2 = std::chrono::steady_clock::now();
    auto time2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);

    EXPECT_TRUE(result2.success);
    EXPECT_TRUE(result2.from_cache);
    EXPECT_EQ(result1.addresses, result2.addresses);

    // Cache hit should be much faster
    EXPECT_LT(time2.count(), time1.count() / 2);
  }
}

TEST_F(IntegrationTest, DISABLED_NonExistentDomain) {
  auto result =
      resolver_->resolve("this-domain-definitely-does-not-exist-12345.com", RecordType::A);

  EXPECT_FALSE(result.success);
  EXPECT_TRUE(result.addresses.empty());
  EXPECT_FALSE(result.error_message.empty());
}

TEST_F(IntegrationTest, DISABLED_ResolverHealth) {
  bool healthy = resolver_->is_healthy();

  // Should be able to reach at least one root server
  EXPECT_TRUE(healthy);
}

TEST_F(IntegrationTest, DISABLED_ConcurrentResolution) {
  const int num_threads = 5;
  const std::vector<std::string> domains = {"google.com", "github.com", "stackoverflow.com",
                                            "wikipedia.org", "cloudflare.com"};

  std::vector<std::thread> threads;
  std::vector<ResolutionResult> results(num_threads);

  // Launch concurrent resolutions
  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([this, &results, &domains, i]() {
      results[i] = resolver_->resolve(domains[i], RecordType::A);
    });
  }

  // Wait for all to complete
  for (auto &thread : threads) {
    thread.join();
  }

  // Check results
  int successful_resolutions = 0;
  for (const auto &result : results) {
    if (result.success) {
      successful_resolutions++;
      EXPECT_FALSE(result.addresses.empty());
    }
  }

  // At least some should succeed (depending on network connectivity)
  EXPECT_GT(successful_resolutions, 0);
}

TEST_F(IntegrationTest, DISABLED_AsyncResolution) {
  auto future1 = resolver_->resolve_async("google.com", RecordType::A);
  auto future2 = resolver_->resolve_async("github.com", RecordType::A);

  auto result1 = future1.get();
  auto result2 = future2.get();

  // Both should complete (success depends on network)
  EXPECT_GE(result1.resolution_time.count(), 0);
  EXPECT_GE(result2.resolution_time.count(), 0);
}

// Test root server configuration
TEST(RootServersTest, RootServerConfiguration) {
  auto ipv4_servers = config::get_ipv4_root_servers();
  auto ipv6_servers = config::get_ipv6_root_servers();
  auto all_servers = config::get_all_root_servers();
  auto names = config::get_root_server_names();

  EXPECT_EQ(ipv4_servers.size(), 13u);
  EXPECT_GT(ipv6_servers.size(), 0u);  // At least some IPv6 servers
  EXPECT_EQ(names.size(), 13u);
  EXPECT_EQ(all_servers.size(), ipv4_servers.size() + ipv6_servers.size());

  // Check specific root servers
  EXPECT_EQ(config::get_root_server_name(0), "a.root-servers.net");
  EXPECT_EQ(config::get_root_server_ipv4(0), "198.41.0.4");

  // Check count
  EXPECT_EQ(config::get_root_server_count(), 13u);
}

TEST(RootServersTest, RootServerValidation) {
  auto ipv4_servers = config::get_ipv4_root_servers();

  for (const auto &server : ipv4_servers) {
    EXPECT_FALSE(server.empty());
    // Basic IPv4 format validation
    EXPECT_NE(server.find('.'), std::string::npos);

    // Should not contain invalid characters
    for (char c : server) {
      EXPECT_TRUE(std::isdigit(c) || c == '.');
    }
  }
}

// Test configuration loading
TEST(ConfigTest, EnvironmentVariables) {
  // Test default values
  EXPECT_EQ(config::DEFAULT_UDP_TIMEOUT, std::chrono::seconds(5));
  EXPECT_EQ(config::DEFAULT_MAX_CACHE_SIZE, 10000u);
  EXPECT_EQ(config::DEFAULT_MAX_RECURSION_DEPTH, 16);

  // Test validation functions
  EXPECT_TRUE(config::is_valid_timeout(std::chrono::seconds(5)));
  EXPECT_FALSE(config::is_valid_timeout(std::chrono::seconds(0)));
  EXPECT_FALSE(config::is_valid_timeout(std::chrono::seconds(500)));

  EXPECT_TRUE(config::is_valid_cache_size(1000));
  EXPECT_TRUE(config::is_valid_cache_size(0));    // Unlimited
  EXPECT_FALSE(config::is_valid_cache_size(50));  // Too small

  EXPECT_TRUE(config::is_valid_recursion_depth(10));
  EXPECT_FALSE(config::is_valid_recursion_depth(0));
  EXPECT_FALSE(config::is_valid_recursion_depth(100));
}

TEST(ConfigTest, LogLevelConversion) {
  EXPECT_EQ(config::string_to_log_level("debug"), config::LogLevel::DEBUG);
  EXPECT_EQ(config::string_to_log_level("INFO"), config::LogLevel::INFO);
  EXPECT_EQ(config::string_to_log_level("Warning"), config::LogLevel::WARN);
  EXPECT_EQ(config::string_to_log_level("error"), config::LogLevel::ERROR);
  EXPECT_EQ(config::string_to_log_level("invalid"), config::DEFAULT_LOG_LEVEL);

  EXPECT_EQ(config::log_level_to_string(config::LogLevel::DEBUG), "DEBUG");
  EXPECT_EQ(config::log_level_to_string(config::LogLevel::INFO), "INFO");
  EXPECT_EQ(config::log_level_to_string(config::LogLevel::WARN), "WARN");
  EXPECT_EQ(config::log_level_to_string(config::LogLevel::ERROR), "ERROR");
}

// Performance tests
TEST(PerformanceTest, DISABLED_ResolutionLatency) {
  Resolver resolver;
  const std::string domain = "google.com";
  const int num_iterations = 10;

  std::vector<std::chrono::milliseconds> times;
  times.reserve(num_iterations);

  for (int i = 0; i < num_iterations; ++i) {
    auto start = std::chrono::steady_clock::now();
    auto result = resolver.resolve(domain, RecordType::A);
    auto end = std::chrono::steady_clock::now();

    if (result.success) {
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      times.push_back(duration);
    }
  }

  if (!times.empty()) {
    auto total_time = std::accumulate(times.begin(), times.end(), std::chrono::milliseconds(0));
    auto avg_time = total_time / times.size();

    std::cout << "Average resolution time: " << avg_time.count() << " ms" << std::endl;

    // Most resolutions should complete within reasonable time
    EXPECT_LT(avg_time.count(), 5000);  // 5 seconds
  }
}
