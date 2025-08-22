#pragma once

#include <atomic>
#include <chrono>
#include <fstream>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "utils.h"

namespace dns_resolver {

/**
 * @brief Cache entry for DNS records
 */
struct CacheEntry {
  std::vector<std::string> records;                   // IP addresses or other record data
  std::chrono::system_clock::time_point expiry_time;  // When this entry expires
  uint32_t original_ttl;                              // Original TTL value
  bool is_negative;                                   // True for NXDOMAIN/NODATA responses
  RecordType record_type;                             // Type of records stored

  CacheEntry() = default;

  CacheEntry(const std::vector<std::string> &recs, uint32_t ttl, RecordType type,
             bool negative = false)
      : records(recs),
        expiry_time(std::chrono::system_clock::now() + std::chrono::seconds(ttl)),
        original_ttl(ttl),
        is_negative(negative),
        record_type(type) {}

  /**
   * @brief Check if this cache entry has expired
   * @return True if the entry has expired
   */
  bool is_expired() const { return std::chrono::system_clock::now() >= expiry_time; }

  /**
   * @brief Get the remaining TTL in seconds
   * @return Remaining TTL, or 0 if expired
   */
  uint32_t get_remaining_ttl() const {
    auto now = std::chrono::system_clock::now();
    if (now >= expiry_time) {
      return 0;
    }
    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(expiry_time - now);
    return static_cast<uint32_t>(remaining.count());
  }
  // Simple text serialization
  std::string serialize(const std::string &key) const {
    std::string line = key + "|";
    line += std::to_string(
                std::chrono::duration_cast<std::chrono::seconds>(expiry_time.time_since_epoch())
                    .count()) +
            "|";
    line += std::to_string(original_ttl) + "|";
    line += std::to_string(is_negative ? 1 : 0) + "|";
    line += std::to_string(static_cast<int>(record_type)) + "|";
    for (size_t i = 0; i < records.size(); ++i) {
      line += records[i];
      if (i + 1 < records.size()) line += ",";
    }
    return line;
  }
  static CacheEntry deserialize(const std::string &line, std::string &key_out) {
    CacheEntry entry;
    size_t pos = 0, next = 0;
    std::vector<std::string> fields;
    while ((next = line.find('|', pos)) != std::string::npos) {
      fields.push_back(line.substr(pos, next - pos));
      pos = next + 1;
    }
    fields.push_back(line.substr(pos));
    if (fields.size() < 6) return entry;
    key_out = fields[0];
    auto expiry_secs = std::stoll(fields[1]);
    entry.expiry_time = std::chrono::system_clock::time_point(std::chrono::seconds(expiry_secs));
    entry.original_ttl = static_cast<uint32_t>(std::stoul(fields[2]));
    entry.is_negative = (fields[3] == "1");
    entry.record_type = static_cast<RecordType>(std::stoi(fields[4]));
    entry.records.clear();
    std::string recs = fields[5];
    size_t rpos = 0, rnext = 0;
    while ((rnext = recs.find(',', rpos)) != std::string::npos) {
      entry.records.push_back(recs.substr(rpos, rnext - rpos));
      rpos = rnext + 1;
    }
    if (rpos < recs.size()) entry.records.push_back(recs.substr(rpos));
    return entry;
  }
};

/**
 * @brief Thread-safe DNS cache with LRU eviction and TTL management
 *
 * This cache implementation provides:
 * - Thread-safe concurrent access using shared_mutex
 * - LRU (Least Recently Used) eviction policy
 * - Automatic TTL expiration
 * - Support for both positive and negative caching
 * - Configurable maximum size
 */
class DnsCache {
public:
  /**
   * @brief Construct a new DNS cache
   * @param max_size Maximum number of entries to store (0 for unlimited)
   */
  // If cache_file is empty, persistence is disabled (no save/load to disk).
  explicit DnsCache(size_t max_size = 10000, const std::string &cache_file = "");

  // Persistent cache support
  void load_from_file(const std::string &filename);
  void save_to_file(const std::string &filename);

  /**
   * @brief Destructor
   */
  ~DnsCache() = default;

  // Disable copy constructor and assignment operator
  DnsCache(const DnsCache &) = delete;
  DnsCache &operator=(const DnsCache &) = delete;

  // Disable move constructor and assignment operator (due to std::shared_mutex)
  DnsCache(DnsCache &&) = delete;
  DnsCache &operator=(DnsCache &&) = delete;

  /**
   * @brief Get a cache entry by key
   * @param key Cache key (domain:type:class format)
   * @return Cache entry if found and not expired, nullopt otherwise
   */
  std::optional<CacheEntry> get(const std::string &key);

  /**
   * @brief Put a cache entry
   * @param key Cache key
   * @param entry Cache entry to store
   */
  void put(const std::string &key, const CacheEntry &entry);

  /**
   * @brief Remove a specific cache entry
   * @param key Cache key to remove
   * @return True if the entry was found and removed
   */
  bool remove(const std::string &key);

  /**
   * @brief Clear all cache entries
   */
  void clear();

  /**
   * @brief Remove all expired entries
   * @return Number of entries removed
   */
  size_t cleanup_expired();

  /**
   * @brief Get the current number of cache entries
   * @return Number of entries in the cache
   */
  size_t size() const;

  /**
   * @brief Get the maximum cache size
   * @return Maximum number of entries
   */
  size_t max_size() const { return max_size_; }

  /**
   * @brief Check if the cache is empty
   * @return True if the cache is empty
   */
  bool empty() const;

  /**
   * @brief Get cache statistics
   * @return Cache statistics structure
   */
  struct CacheStats {
    size_t total_entries;
    size_t expired_entries;
    uint64_t hit_count;
    uint64_t miss_count;
    uint64_t eviction_count;
    double hit_ratio;
  };

  CacheStats get_stats() const;

  /**
   * @brief Reset cache statistics
   */
  void reset_stats();

  /**
   * @brief Set the maximum cache size
   * @param new_max_size New maximum size (0 for unlimited)
   */
  void set_max_size(size_t new_max_size);

private:
  mutable std::shared_mutex cache_mutex_;
  std::unordered_map<std::string, CacheEntry> cache_;
  std::list<std::string> lru_list_;
  std::unordered_map<std::string, std::list<std::string>::iterator> lru_map_;
  size_t max_size_;

  // Empty means persistence disabled
  std::string cache_file_ = "";

  // Statistics (atomic for thread safety)
  mutable std::atomic<uint64_t> hit_count_{0};
  mutable std::atomic<uint64_t> miss_count_{0};
  mutable std::atomic<uint64_t> eviction_count_{0};

  /**
   * @brief Move an entry to the front of the LRU list (most recently used)
   * @param key Cache key to move
   */
  void move_to_front(const std::string &key);

  /**
   * @brief Add a new entry to the front of the LRU list
   * @param key Cache key to add
   */
  void add_to_front(const std::string &key);

  /**
   * @brief Remove an entry from the LRU list
   * @param key Cache key to remove
   */
  void remove_from_lru(const std::string &key);

  /**
   * @brief Evict the least recently used entry
   * @return True if an entry was evicted
   */
  bool evict_lru();

  /**
   * @brief Ensure cache size is within limits by evicting entries if necessary
   */
  void enforce_size_limit();
};

/**
 * @brief Utility functions for cache key generation and management
 */
namespace cache_utils {

/**
 * @brief Generate a cache key for a DNS query
 * @param domain Domain name (will be normalized)
 * @param type Record type
 * @param cls Record class
 * @return Cache key string
 */
std::string generate_cache_key(const std::string &domain, RecordType type, RecordClass cls);

/**
 * @brief Parse a cache key back into its components
 * @param key Cache key string
 * @param domain Output parameter for domain name
 * @param type Output parameter for record type
 * @param cls Output parameter for record class
 * @return True if the key was successfully parsed
 */
bool parse_cache_key(const std::string &key, std::string &domain, RecordType &type,
                     RecordClass &cls);

/**
 * @brief Create a cache entry from DNS resource records
 * @param records Vector of resource records
 * @param record_type Type of records
 * @return Cache entry
 */
CacheEntry create_cache_entry_from_records(const std::vector<ResourceRecord> &records,
                                           RecordType record_type);

/**
 * @brief Create a negative cache entry (for NXDOMAIN/NODATA)
 * @param ttl TTL for the negative entry
 * @param record_type Type of record that was queried
 * @return Negative cache entry
 */
CacheEntry create_negative_cache_entry(uint32_t ttl, RecordType record_type);

/**
 * @brief Extract IP addresses from A/AAAA resource records
 * @param records Vector of resource records
 * @return Vector of IP address strings
 */
std::vector<std::string> extract_ip_addresses(const std::vector<ResourceRecord> &records);

/**
 * @brief Extract domain names from CNAME/NS resource records
 * @param records Vector of resource records
 * @return Vector of domain name strings
 */
std::vector<std::string> extract_domain_names(const std::vector<ResourceRecord> &records);

/**
 * @brief Calculate the minimum TTL from a set of resource records
 * @param records Vector of resource records
 * @return Minimum TTL value
 */
uint32_t calculate_min_ttl(const std::vector<ResourceRecord> &records);

}  // namespace cache_utils

}  // namespace dns_resolver
