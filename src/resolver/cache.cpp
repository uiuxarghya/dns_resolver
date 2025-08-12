#include "cache.h"
#include <algorithm>

namespace dns_resolver
{

  DnsCache::DnsCache(size_t max_size) : max_size_(max_size)
  {
  }

  std::optional<CacheEntry> DnsCache::get(const std::string &key)
  {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end())
    {
      miss_count_++;
      return std::nullopt;
    }

    // Check if entry has expired
    if (it->second.is_expired())
    {
      lock.unlock();
      std::unique_lock<std::shared_mutex> write_lock(cache_mutex_);
      cache_.erase(it);
      remove_from_lru(key);
      miss_count_++;
      return std::nullopt;
    }

    // Move to front of LRU list
    lock.unlock();
    std::unique_lock<std::shared_mutex> write_lock(cache_mutex_);
    move_to_front(key);
    hit_count_++;

    return it->second;
  }

  void DnsCache::put(const std::string &key, const CacheEntry &entry)
  {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it != cache_.end())
    {
      // Update existing entry
      it->second = entry;
      move_to_front(key);
    }
    else
    {
      // Add new entry
      cache_[key] = entry;
      add_to_front(key);
      enforce_size_limit();
    }
  }

  bool DnsCache::remove(const std::string &key)
  {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end())
    {
      return false;
    }

    cache_.erase(it);
    remove_from_lru(key);
    return true;
  }

  void DnsCache::clear()
  {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    cache_.clear();
    lru_list_.clear();
    lru_map_.clear();
  }

  size_t DnsCache::cleanup_expired()
  {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    size_t removed_count = 0;
    auto it = cache_.begin();
    while (it != cache_.end())
    {
      if (it->second.is_expired())
      {
        remove_from_lru(it->first);
        it = cache_.erase(it);
        removed_count++;
      }
      else
      {
        ++it;
      }
    }

    return removed_count;
  }

  size_t DnsCache::size() const
  {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    return cache_.size();
  }

  bool DnsCache::empty() const
  {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    return cache_.empty();
  }

  DnsCache::CacheStats DnsCache::get_stats() const
  {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);

    CacheStats stats;
    stats.total_entries = cache_.size();
    stats.hit_count = hit_count_.load();
    stats.miss_count = miss_count_.load();
    stats.eviction_count = eviction_count_.load();

    uint64_t total_requests = stats.hit_count + stats.miss_count;
    stats.hit_ratio = total_requests > 0 ? static_cast<double>(stats.hit_count) / total_requests : 0.0;

    // Count expired entries
    stats.expired_entries = 0;
    for (const auto &pair : cache_)
    {
      if (pair.second.is_expired())
      {
        stats.expired_entries++;
      }
    }

    return stats;
  }

  void DnsCache::reset_stats()
  {
    hit_count_ = 0;
    miss_count_ = 0;
    eviction_count_ = 0;
  }

  void DnsCache::set_max_size(size_t new_max_size)
  {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    max_size_ = new_max_size;
    enforce_size_limit();
  }

  void DnsCache::move_to_front(const std::string &key)
  {
    auto lru_it = lru_map_.find(key);
    if (lru_it != lru_map_.end())
    {
      lru_list_.erase(lru_it->second);
      lru_list_.push_front(key);
      lru_map_[key] = lru_list_.begin();
    }
  }

  void DnsCache::add_to_front(const std::string &key)
  {
    lru_list_.push_front(key);
    lru_map_[key] = lru_list_.begin();
  }

  void DnsCache::remove_from_lru(const std::string &key)
  {
    auto lru_it = lru_map_.find(key);
    if (lru_it != lru_map_.end())
    {
      lru_list_.erase(lru_it->second);
      lru_map_.erase(lru_it);
    }
  }

  bool DnsCache::evict_lru()
  {
    if (lru_list_.empty())
    {
      return false;
    }

    std::string key = lru_list_.back();
    lru_list_.pop_back();
    lru_map_.erase(key);
    cache_.erase(key);
    eviction_count_++;

    return true;
  }

  void DnsCache::enforce_size_limit()
  {
    if (max_size_ == 0)
      return; // Unlimited size

    while (cache_.size() > max_size_)
    {
      if (!evict_lru())
      {
        break; // Should not happen, but safety check
      }
    }
  }

  // Cache utility functions
  namespace cache_utils
  {

    std::string generate_cache_key(const std::string &domain, RecordType type, RecordClass cls)
    {
      std::string normalized_domain = utils::normalize_domain_name(domain);
      return normalized_domain + ":" +
             std::to_string(static_cast<uint16_t>(type)) + ":" +
             std::to_string(static_cast<uint16_t>(cls));
    }

    bool parse_cache_key(const std::string &key, std::string &domain,
                         RecordType &type, RecordClass &cls)
    {
      size_t first_colon = key.find(':');
      size_t second_colon = key.find(':', first_colon + 1);

      if (first_colon == std::string::npos || second_colon == std::string::npos)
      {
        return false;
      }

      domain = key.substr(0, first_colon);

      try
      {
        uint16_t type_val = std::stoul(key.substr(first_colon + 1, second_colon - first_colon - 1));
        uint16_t cls_val = std::stoul(key.substr(second_colon + 1));

        type = static_cast<RecordType>(type_val);
        cls = static_cast<RecordClass>(cls_val);
        return true;
      }
      catch (...)
      {
        return false;
      }
    }

    CacheEntry create_cache_entry_from_records(const std::vector<ResourceRecord> &records,
                                               RecordType record_type)
    {
      if (records.empty())
      {
        return create_negative_cache_entry(300, record_type); // 5 minutes default
      }

      std::vector<std::string> data;
      uint32_t min_ttl = UINT32_MAX;

      for (const auto &rr : records)
      {
        if (rr.type == record_type)
        {
          min_ttl = std::min(min_ttl, rr.ttl);

          if (record_type == RecordType::A)
          {
            auto addr = rr.get_a_record();
            if (!addr.empty())
              data.push_back(addr);
          }
          else if (record_type == RecordType::AAAA)
          {
            auto addr = rr.get_aaaa_record();
            if (!addr.empty())
              data.push_back(addr);
          }
          // Add other record types as needed
        }
      }

      if (min_ttl == UINT32_MAX)
      {
        min_ttl = 300; // Default TTL
      }

      return CacheEntry(data, min_ttl, record_type, data.empty());
    }

    CacheEntry create_negative_cache_entry(uint32_t ttl, RecordType record_type)
    {
      return CacheEntry({}, ttl, record_type, true);
    }

    std::vector<std::string> extract_ip_addresses(const std::vector<ResourceRecord> &records)
    {
      std::vector<std::string> addresses;
      for (const auto &rr : records)
      {
        if (rr.type == RecordType::A)
        {
          auto addr = rr.get_a_record();
          if (!addr.empty())
            addresses.push_back(addr);
        }
        else if (rr.type == RecordType::AAAA)
        {
          auto addr = rr.get_aaaa_record();
          if (!addr.empty())
            addresses.push_back(addr);
        }
      }
      return addresses;
    }

    std::vector<std::string> extract_domain_names(const std::vector<ResourceRecord> &records)
    {
      std::vector<std::string> names;
      for (const auto &rr : records)
      {
        if (rr.type == RecordType::CNAME || rr.type == RecordType::NS)
        {
          // TODO: Implement domain name extraction from RDATA
          // This requires proper parsing of the encoded domain names
        }
      }
      return names;
    }

    uint32_t calculate_min_ttl(const std::vector<ResourceRecord> &records)
    {
      if (records.empty())
        return 300; // Default 5 minutes

      uint32_t min_ttl = UINT32_MAX;
      for (const auto &rr : records)
      {
        min_ttl = std::min(min_ttl, rr.ttl);
      }

      return min_ttl == UINT32_MAX ? 300 : min_ttl;
    }

  } // namespace cache_utils

} // namespace dns_resolver
