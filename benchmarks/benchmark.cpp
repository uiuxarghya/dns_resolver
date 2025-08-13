#include <benchmark/benchmark.h>

#include <iostream>
#include <random>
#include <string>

#include "../src/resolver/cache.h"
#include "../src/resolver/packet_builder.h"
#include "../src/resolver/packet_parser.h"
#include "../src/resolver/resolver.h"
#include "../src/resolver/utils.h"

using namespace dns_resolver;

// Benchmark DNS packet building
static void BM_PacketBuilder_SimpleQuery(benchmark::State &state) {
  PacketBuilder builder;

  for (auto _ : state) {
    auto packet = builder.set_id(12345)
                      .set_flags(false, 0, false, false, true, false, 0)
                      .add_question("example.com", RecordType::A, RecordClass::IN)
                      .build();
    builder.reset();
    benchmark::DoNotOptimize(packet);
  }
}
BENCHMARK(BM_PacketBuilder_SimpleQuery);

static void BM_PacketBuilder_ComplexQuery(benchmark::State &state) {
  PacketBuilder builder;
  std::vector<uint8_t> rdata = {192, 168, 1, 1};

  for (auto _ : state) {
    auto packet = builder.set_id(12345)
                      .set_flags(true, 0, true, false, true, true, 0)
                      .add_question("example.com", RecordType::A, RecordClass::IN)
                      .add_answer("example.com", RecordType::A, RecordClass::IN, 300, rdata)
                      .add_answer("www.example.com", RecordType::A, RecordClass::IN, 300, rdata)
                      .build();
    builder.reset();
    benchmark::DoNotOptimize(packet);
  }
}
BENCHMARK(BM_PacketBuilder_ComplexQuery);

// Benchmark DNS packet parsing
static void BM_PacketParser_SimpleResponse(benchmark::State &state) {
  // Pre-built DNS response packet
  std::vector<uint8_t> response = {
      0x12, 0x34,  // ID
      0x81, 0x80,  // Flags
      0x00, 0x01,  // QDCOUNT
      0x00, 0x01,  // ANCOUNT
      0x00, 0x00,  // NSCOUNT
      0x00, 0x00,  // ARCOUNT
      // Question
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
      // Answer
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216, 34};

  for (auto _ : state) {
    PacketParser parser(response);
    auto message = parser.parse();
    benchmark::DoNotOptimize(message);
  }
}
BENCHMARK(BM_PacketParser_SimpleResponse);

// Benchmark cache operations
static void BM_Cache_Put(benchmark::State &state) {
  DnsCache cache(10000);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(1, 1000000);

  for (auto _ : state) {
    std::string key = "domain" + std::to_string(dis(gen)) + ".com:1:1";
    CacheEntry entry({"1.2.3.4"}, 300, RecordType::A);
    cache.put(key, entry);
  }
}
BENCHMARK(BM_Cache_Put);

static void BM_Cache_Get_Hit(benchmark::State &state) {
  DnsCache cache(10000);

  // Pre-populate cache
  for (int i = 0; i < 1000; ++i) {
    std::string key = "domain" + std::to_string(i) + ".com:1:1";
    CacheEntry entry({"1.2.3." + std::to_string(i)}, 3600, RecordType::A);
    cache.put(key, entry);
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 999);

  for (auto _ : state) {
    std::string key = "domain" + std::to_string(dis(gen)) + ".com:1:1";
    auto result = cache.get(key);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_Cache_Get_Hit);

static void BM_Cache_Get_Miss(benchmark::State &state) {
  DnsCache cache(10000);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(1, 1000000);

  for (auto _ : state) {
    std::string key = "nonexistent" + std::to_string(dis(gen)) + ".com:1:1";
    auto result = cache.get(key);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_Cache_Get_Miss);

// Benchmark utility functions
static void BM_Utils_DomainValidation(benchmark::State &state) {
  std::vector<std::string> domains = {"example.com",
                                      "www.google.com",
                                      "sub.domain.test.org",
                                      "invalid..domain",
                                      "toolong" + std::string(250, 'a') + ".com",
                                      "valid-domain.net",
                                      "123.456.789.012"};

  size_t index = 0;
  for (auto _ : state) {
    bool valid = utils::is_valid_domain_name(domains[index % domains.size()]);
    benchmark::DoNotOptimize(valid);
    ++index;
  }
}
BENCHMARK(BM_Utils_DomainValidation);

static void BM_Utils_DomainNormalization(benchmark::State &state) {
  std::vector<std::string> domains = {"Example.COM", "WWW.GOOGLE.COM", "Test.Domain.ORG",
                                      "UPPERCASE.DOMAIN.NET", "MiXeD.cAsE.CoM"};

  size_t index = 0;
  for (auto _ : state) {
    auto normalized = utils::normalize_domain_name(domains[index % domains.size()]);
    benchmark::DoNotOptimize(normalized);
    ++index;
  }
}
BENCHMARK(BM_Utils_DomainNormalization);

static void BM_Utils_IPv4ToString(benchmark::State &state) {
  std::vector<uint8_t> ipv4 = {192, 168, 1, 100};

  for (auto _ : state) {
    auto str = utils::ipv4_to_string(ipv4);
    benchmark::DoNotOptimize(str);
  }
}
BENCHMARK(BM_Utils_IPv4ToString);

static void BM_Utils_QueryIdGeneration(benchmark::State &state) {
  for (auto _ : state) {
    auto id = utils::generate_query_id();
    benchmark::DoNotOptimize(id);
  }
}
BENCHMARK(BM_Utils_QueryIdGeneration);

// Benchmark cache key generation
static void BM_CacheUtils_KeyGeneration(benchmark::State &state) {
  std::vector<std::string> domains = {"example.com", "google.com", "github.com",
                                      "stackoverflow.com"};

  size_t index = 0;
  for (auto _ : state) {
    auto key = cache_utils::generate_cache_key(domains[index % domains.size()], RecordType::A,
                                               RecordClass::IN);
    benchmark::DoNotOptimize(key);
    ++index;
  }
}
BENCHMARK(BM_CacheUtils_KeyGeneration);

// Concurrent cache operations
static void BM_Cache_Concurrent_Put(benchmark::State &state) {
  static DnsCache cache(50000);
  std::random_device rd;
  thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(1, 1000000);

  for (auto _ : state) {
    std::string key = "concurrent" + std::to_string(dis(gen)) + ".com:1:1";
    CacheEntry entry({"1.2.3.4"}, 300, RecordType::A);
    cache.put(key, entry);
  }
}
BENCHMARK(BM_Cache_Concurrent_Put)->Threads(4);

static void BM_Cache_Concurrent_Get(benchmark::State &state) {
  static DnsCache cache(50000);
  static bool initialized = false;

  if (!initialized) {
    // Pre-populate cache
    for (int i = 0; i < 10000; ++i) {
      std::string key = "concurrent" + std::to_string(i) + ".com:1:1";
      CacheEntry entry({"1.2.3." + std::to_string(i % 256)}, 3600, RecordType::A);
      cache.put(key, entry);
    }
    initialized = true;
  }

  std::random_device rd;
  thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 9999);

  for (auto _ : state) {
    std::string key = "concurrent" + std::to_string(dis(gen)) + ".com:1:1";
    auto result = cache.get(key);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_Cache_Concurrent_Get)->Threads(8);

// Memory usage benchmarks
static void BM_Cache_MemoryUsage(benchmark::State &state) {
  const int cache_size = state.range(0);

  for (auto _ : state) {
    DnsCache cache(cache_size);

    // Fill cache to capacity
    for (int i = 0; i < cache_size; ++i) {
      std::string key = "memory" + std::to_string(i) + ".com:1:1";
      CacheEntry entry({"1.2.3." + std::to_string(i % 256)}, 3600, RecordType::A);
      cache.put(key, entry);
    }

    benchmark::DoNotOptimize(cache);
  }
}
BENCHMARK(BM_Cache_MemoryUsage)->Range(100, 10000);

// Packet size benchmarks
static void BM_PacketSize_Scaling(benchmark::State &state) {
  const int num_questions = state.range(0);
  PacketBuilder builder;

  for (auto _ : state) {
    builder.set_id(12345);

    for (int i = 0; i < num_questions; ++i) {
      std::string domain = "domain" + std::to_string(i) + ".example.com";
      builder.add_question(domain, RecordType::A, RecordClass::IN);
    }

    auto packet = builder.build();
    builder.reset();
    benchmark::DoNotOptimize(packet);
  }
}
BENCHMARK(BM_PacketSize_Scaling)->Range(1, 100);

// Custom main function to add additional reporting
int main(int argc, char **argv) {
  benchmark::Initialize(&argc, argv);

  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }

  std::cout << "DNS Resolver Performance Benchmarks\n";
  std::cout << "=================================\n\n";

  benchmark::RunSpecifiedBenchmarks();

  std::cout << "\nBenchmark completed. Results saved to benchmark_results.json\n";
  return 0;
}
