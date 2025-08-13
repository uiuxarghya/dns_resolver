#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../src/resolver/resolver.h"
#include "../src/resolver/utils.h"

using namespace dns_resolver;

class ResolverTest : public ::testing::Test {
protected:
  void SetUp() override {
    ResolverConfig config;
    config.query_timeout = std::chrono::seconds(2);
    config.max_cache_size = 1000;
    config.verbose = false;
    resolver_ = std::make_unique<Resolver>(config);
  }

  std::unique_ptr<Resolver> resolver_;
};

TEST_F(ResolverTest, ValidDomainNames) {
  EXPECT_TRUE(utils::is_valid_domain_name("example.com"));
  EXPECT_TRUE(utils::is_valid_domain_name("www.google.com"));
  EXPECT_TRUE(utils::is_valid_domain_name("sub.domain.example.org"));
  EXPECT_TRUE(utils::is_valid_domain_name("test-domain.com"));
  EXPECT_TRUE(utils::is_valid_domain_name("a.b.c.d.e.f.g"));
}

TEST_F(ResolverTest, InvalidDomainNames) {
  EXPECT_FALSE(utils::is_valid_domain_name(""));
  // '.' is valid for root domain queries, so do not test as invalid
  EXPECT_FALSE(utils::is_valid_domain_name(".."));
  EXPECT_FALSE(utils::is_valid_domain_name("domain..com"));
  EXPECT_FALSE(utils::is_valid_domain_name("-invalid.com"));
  EXPECT_FALSE(utils::is_valid_domain_name("invalid-.com"));

  // Test very long domain name (>255 characters)
  std::string long_domain(250, 'a');
  long_domain += ".com";
  EXPECT_FALSE(utils::is_valid_domain_name(long_domain));
}

TEST_F(ResolverTest, DomainNameNormalization) {
  EXPECT_EQ(utils::normalize_domain_name("Example.COM"), "example.com");
  EXPECT_EQ(utils::normalize_domain_name("WWW.GOOGLE.COM"), "www.google.com");
  EXPECT_EQ(utils::normalize_domain_name("test.com."), "test.com");
  EXPECT_EQ(utils::normalize_domain_name("Test.Com."), "test.com");
}

TEST_F(ResolverTest, RecordTypeConversion) {
  EXPECT_EQ(utils::record_type_to_string(RecordType::A), "A");
  EXPECT_EQ(utils::record_type_to_string(RecordType::AAAA), "AAAA");
  EXPECT_EQ(utils::record_type_to_string(RecordType::CNAME), "CNAME");
  EXPECT_EQ(utils::record_type_to_string(RecordType::NS), "NS");

  EXPECT_EQ(utils::string_to_record_type("A"), RecordType::A);
  EXPECT_EQ(utils::string_to_record_type("aaaa"), RecordType::AAAA);
  EXPECT_EQ(utils::string_to_record_type("CnAmE"), RecordType::CNAME);
}

TEST_F(ResolverTest, IPv4AddressConversion) {
  std::vector<uint8_t> ipv4_bytes = {192, 168, 1, 1};
  EXPECT_EQ(utils::ipv4_to_string(ipv4_bytes), "192.168.1.1");

  std::vector<uint8_t> invalid_ipv4 = {192, 168, 1};  // Too short
  EXPECT_EQ(utils::ipv4_to_string(invalid_ipv4), "");
}

TEST_F(ResolverTest, IPv6AddressConversion) {
  std::vector<uint8_t> ipv6_bytes = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
                                     0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34};

  std::string ipv6_str = utils::ipv6_to_string(ipv6_bytes);
  EXPECT_FALSE(ipv6_str.empty());

  std::vector<uint8_t> invalid_ipv6 = {0x20, 0x01};  // Too short
  EXPECT_EQ(utils::ipv6_to_string(invalid_ipv6), "");
}

TEST_F(ResolverTest, QueryIdGeneration) {
  uint16_t id1 = utils::generate_query_id();
  uint16_t id2 = utils::generate_query_id();

  EXPECT_NE(id1, 0);
  EXPECT_NE(id2, 0);
  // IDs should be different (with high probability)
  EXPECT_NE(id1, id2);
}

TEST_F(ResolverTest, NetworkByteOrderConversion) {
  uint16_t host_value = 0x1234;
  uint16_t network_value = utils::htons_safe(host_value);
  uint16_t back_to_host = utils::ntohs_safe(network_value);

  EXPECT_EQ(back_to_host, host_value);

  uint32_t host_value32 = 0x12345678;
  uint32_t network_value32 = utils::htonl_safe(host_value32);
  uint32_t back_to_host32 = utils::ntohl_safe(network_value32);

  EXPECT_EQ(back_to_host32, host_value32);
}

TEST_F(ResolverTest, ResolverConfiguration) {
  ResolverConfig config;
  config.query_timeout = std::chrono::seconds(10);
  config.max_cache_size = 5000;
  config.verbose = true;

  resolver_->update_config(config);

  auto current_config = resolver_->get_config();
  EXPECT_EQ(current_config.query_timeout, std::chrono::seconds(10));
  EXPECT_EQ(current_config.max_cache_size, 5000u);
  EXPECT_TRUE(current_config.verbose);
}

TEST_F(ResolverTest, CacheOperations) {
  // Clear cache
  resolver_->clear_cache();

  auto stats = resolver_->get_cache_stats();
  EXPECT_EQ(stats.total_entries, 0u);
  EXPECT_EQ(stats.hit_count, 0u);
  EXPECT_EQ(stats.miss_count, 0u);
}

TEST_F(ResolverTest, InvalidDomainResolution) {
  auto result = resolver_->resolve("", RecordType::A);
  EXPECT_FALSE(result.success);
  EXPECT_FALSE(result.error_message.empty());

  auto result2 = resolver_->resolve("invalid..domain", RecordType::A);
  EXPECT_FALSE(result2.success);
}

// Mock tests for network operations would require more complex setup
// These tests focus on the logic that doesn't require actual network calls

TEST_F(ResolverTest, ResolutionResultStructure) {
  ResolutionResult result;
  EXPECT_FALSE(result.success);
  EXPECT_TRUE(result.addresses.empty());
  EXPECT_FALSE(result.from_cache);
  EXPECT_EQ(result.resolution_time.count(), 0);

  ResolutionResult result_with_addresses({"1.2.3.4", "5.6.7.8"});
  EXPECT_TRUE(result_with_addresses.success);
  EXPECT_EQ(result_with_addresses.addresses.size(), 2u);
}

TEST_F(ResolverTest, AsyncResolution) {
  // Test async interface (will fail due to no network, but tests the interface)
  auto future = resolver_->resolve_async("example.com", RecordType::A);
  EXPECT_TRUE(future.valid());

  // Get result (will likely fail due to no network connectivity in test environment)
  auto result = future.get();
  // We can't assert success here since we don't have real network access
  EXPECT_GE(result.resolution_time.count(), 0);
}

// Test utility functions
TEST(ResolverUtilsTest, CreatePerformanceResolver) {
  auto resolver = resolver_utils::create_performance_resolver();
  EXPECT_NE(resolver, nullptr);

  auto config = resolver->get_config();
  EXPECT_LE(config.query_timeout, std::chrono::seconds(5));
  EXPECT_GE(config.max_cache_size, 10000u);
}

TEST(ResolverUtilsTest, CreateReliableResolver) {
  auto resolver = resolver_utils::create_reliable_resolver();
  EXPECT_NE(resolver, nullptr);

  auto config = resolver->get_config();
  EXPECT_GE(config.query_timeout, std::chrono::seconds(5));
  EXPECT_GE(config.max_retries, 3u);
  EXPECT_TRUE(config.enable_tcp_fallback);
}

// Test ResourceRecord methods
TEST(ResourceRecordTest, ARecordExtraction) {
  ResourceRecord rr("test.com", RecordType::A, RecordClass::IN, 300);
  rr.rdata = {192, 168, 1, 100};

  EXPECT_EQ(rr.get_a_record(), "192.168.1.100");

  // Test with wrong type
  ResourceRecord wrong_type("test.com", RecordType::AAAA, RecordClass::IN, 300);
  wrong_type.rdata = {192, 168, 1, 100};
  EXPECT_EQ(wrong_type.get_a_record(), "");

  // Test with wrong size
  ResourceRecord wrong_size("test.com", RecordType::A, RecordClass::IN, 300);
  wrong_size.rdata = {192, 168, 1};  // Too short
  EXPECT_EQ(wrong_size.get_a_record(), "");
}

TEST(ResourceRecordTest, AAAARecordExtraction) {
  ResourceRecord rr("test.com", RecordType::AAAA, RecordClass::IN, 300);
  rr.rdata = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
              0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34};

  std::string ipv6 = rr.get_aaaa_record();
  EXPECT_FALSE(ipv6.empty());

  // Test with wrong type
  ResourceRecord wrong_type("test.com", RecordType::A, RecordClass::IN, 300);
  wrong_type.rdata = rr.rdata;
  EXPECT_EQ(wrong_type.get_aaaa_record(), "");
}

TEST(ResourceRecordTest, TXTRecordExtraction) {
  ResourceRecord rr("test.com", RecordType::TXT, RecordClass::IN, 300);

  // TXT record format: length-prefixed strings
  std::string text = "Hello World";
  rr.rdata.push_back(static_cast<uint8_t>(text.length()));
  rr.rdata.insert(rr.rdata.end(), text.begin(), text.end());

  EXPECT_EQ(rr.get_txt_record(), "Hello World");

  // Test with wrong type
  ResourceRecord wrong_type("test.com", RecordType::A, RecordClass::IN, 300);
  wrong_type.rdata = rr.rdata;
  EXPECT_EQ(wrong_type.get_txt_record(), "");
}
