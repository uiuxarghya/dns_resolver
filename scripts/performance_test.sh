#!/bin/bash

# DNS Resolver Performance Testing Script
# Comprehensive performance testing and monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DNS_RESOLVER_BINARY="./build/dns_resolver"
RESULTS_DIR="performance_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$RESULTS_DIR/performance_report_$TIMESTAMP.md"

# Test domains for different scenarios
COMMON_DOMAINS=("google.com" "github.com" "stackoverflow.com" "wikipedia.org" "cloudflare.com")
LARGE_DOMAINS=("amazon.com" "microsoft.com" "facebook.com" "twitter.com" "linkedin.com")
INTERNATIONAL_DOMAINS=("baidu.com" "yandex.ru" "naver.com" "qq.com" "taobao.com")

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [ ! -f "$DNS_RESOLVER_BINARY" ]; then
        log_error "DNS Resolver binary not found at $DNS_RESOLVER_BINARY"
        log_info "Please build the project first: cd build && make"
        exit 1
    fi

    if ! command -v time &> /dev/null; then
        log_error "time command not available"
        exit 1
    fi

    if ! command -v bc &> /dev/null; then
        log_warning "bc not available, some calculations may be limited"
    fi

    log_success "Prerequisites check passed"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results will be saved to: $RESULTS_DIR"
}

# Test single domain resolution
test_domain_resolution() {
    local domain=$1
    local record_type=${2:-"A"}
    local iterations=${3:-5}

    log_info "Testing $domain ($record_type) - $iterations iterations"

    local total_time=0
    local successful_queries=0
    local failed_queries=0

    for ((i=1; i<=iterations; i++)); do
        local start_time=$(date +%s.%N)

        if timeout 30 "$DNS_RESOLVER_BINARY" -t "$record_type" "$domain" > /dev/null 2>&1; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
            total_time=$(echo "$total_time + $duration" | bc -l 2>/dev/null || echo "$total_time")
            ((successful_queries++))
        else
            ((failed_queries++))
        fi
    done

    if [ $successful_queries -gt 0 ]; then
        local avg_time=$(echo "scale=3; $total_time / $successful_queries" | bc -l 2>/dev/null || echo "N/A")
        echo "$domain,$record_type,$successful_queries,$failed_queries,$avg_time" >> "$RESULTS_DIR/raw_results_$TIMESTAMP.csv"
        log_success "$domain: $successful_queries/$iterations successful (avg: ${avg_time}s)"
    else
        log_error "$domain: All queries failed"
        echo "$domain,$record_type,0,$failed_queries,N/A" >> "$RESULTS_DIR/raw_results_$TIMESTAMP.csv"
    fi
}

# Test concurrent queries
test_concurrent_queries() {
    local domain=$1
    local concurrent_count=${2:-10}

    log_info "Testing concurrent queries for $domain ($concurrent_count concurrent)"

    local start_time=$(date +%s.%N)
    local pids=()

    # Start concurrent queries
    for ((i=1; i<=concurrent_count; i++)); do
        timeout 30 "$DNS_RESOLVER_BINARY" "$domain" > /dev/null 2>&1 &
        pids+=($!)
    done

    # Wait for all to complete
    local successful=0
    for pid in "${pids[@]}"; do
        if wait $pid; then
            ((successful++))
        fi
    done

    local end_time=$(date +%s.%N)
    local total_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")

    log_success "Concurrent test: $successful/$concurrent_count successful in ${total_time}s"
    echo "concurrent,$domain,$successful,$concurrent_count,$total_time" >> "$RESULTS_DIR/concurrent_results_$TIMESTAMP.csv"
}

# Memory usage test
test_memory_usage() {
    log_info "Testing memory usage..."

    # Start DNS Resolver with a long-running query and monitor memory
    local domain="google.com"

    # Use /usr/bin/time for detailed memory statistics
    if command -v /usr/bin/time &> /dev/null; then
        /usr/bin/time -v "$DNS_RESOLVER_BINARY" "$domain" 2> "$RESULTS_DIR/memory_usage_$TIMESTAMP.txt" > /dev/null

        local max_memory=$(grep "Maximum resident set size" "$RESULTS_DIR/memory_usage_$TIMESTAMP.txt" | awk '{print $6}')
        log_success "Maximum memory usage: ${max_memory} KB"
    else
        log_warning "Detailed memory monitoring not available"
    fi
}

# Cache performance test
test_cache_performance() {
    log_info "Testing cache performance..."

    local domain="example.com"

    # First query (cache miss)
    local start_time=$(date +%s.%N)
    "$DNS_RESOLVER_BINARY" "$domain" > /dev/null 2>&1
    local end_time=$(date +%s.%N)
    local first_query_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")

    # Second query (cache hit)
    start_time=$(date +%s.%N)
    "$DNS_RESOLVER_BINARY" "$domain" > /dev/null 2>&1
    end_time=$(date +%s.%N)
    local second_query_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")

    log_success "Cache test - First: ${first_query_time}s, Second: ${second_query_time}s"
    echo "cache,$domain,$first_query_time,$second_query_time" >> "$RESULTS_DIR/cache_results_$TIMESTAMP.csv"
}

# Generate performance report
generate_report() {
    log_info "Generating performance report..."

    cat > "$REPORT_FILE" << EOF
# DNS Resolver Performance Report

**Generated:** $(date)
**Test Duration:** Performance testing session

## Test Environment

- **OS:** $(uname -s) $(uname -r)
- **Architecture:** $(uname -m)
- **CPU:** $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
- **Memory:** $(free -h | grep "Mem:" | awk '{print $2}')
- **DNS Resolver Version:** $(cd build && ./dns_resolver --version 2>/dev/null || echo "Unknown")

## Test Results Summary

### Domain Resolution Tests

EOF

    # Add raw results if available
    if [ -f "$RESULTS_DIR/raw_results_$TIMESTAMP.csv" ]; then
        echo "| Domain | Record Type | Successful | Failed | Avg Time (s) |" >> "$REPORT_FILE"
        echo "|--------|-------------|------------|--------|--------------|" >> "$REPORT_FILE"

        while IFS=',' read -r domain record_type successful failed avg_time; do
            echo "| $domain | $record_type | $successful | $failed | $avg_time |" >> "$REPORT_FILE"
        done < "$RESULTS_DIR/raw_results_$TIMESTAMP.csv"

        echo "" >> "$REPORT_FILE"
    fi

    # Add concurrent results
    if [ -f "$RESULTS_DIR/concurrent_results_$TIMESTAMP.csv" ]; then
        echo "### Concurrent Query Tests" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "| Domain | Successful | Total | Time (s) |" >> "$REPORT_FILE"
        echo "|--------|------------|-------|----------|" >> "$REPORT_FILE"

        while IFS=',' read -r test_type domain successful total time; do
            echo "| $domain | $successful | $total | $time |" >> "$REPORT_FILE"
        done < "$RESULTS_DIR/concurrent_results_$TIMESTAMP.csv"

        echo "" >> "$REPORT_FILE"
    fi

    # Add memory usage
    if [ -f "$RESULTS_DIR/memory_usage_$TIMESTAMP.txt" ]; then
        echo "### Memory Usage" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        grep -E "(Maximum resident set size|User time|System time)" "$RESULTS_DIR/memory_usage_$TIMESTAMP.txt" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    echo "## Recommendations" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "- Monitor query times for performance regressions" >> "$REPORT_FILE"
    echo "- Cache hit rates should be high for repeated queries" >> "$REPORT_FILE"
    echo "- Memory usage should remain stable under load" >> "$REPORT_FILE"
    echo "- Concurrent queries should scale well" >> "$REPORT_FILE"

    log_success "Performance report generated: $REPORT_FILE"
}

# Main test execution
main() {
    echo "🚀 DNS Resolver Performance Testing"
    echo "================================"

    check_prerequisites
    setup_results_dir

    # Initialize CSV files
    echo "domain,record_type,successful,failed,avg_time" > "$RESULTS_DIR/raw_results_$TIMESTAMP.csv"
    echo "test_type,domain,successful,total,time" > "$RESULTS_DIR/concurrent_results_$TIMESTAMP.csv"
    echo "test_type,domain,first_query,second_query" > "$RESULTS_DIR/cache_results_$TIMESTAMP.csv"

    # Run tests
    log_info "Starting domain resolution tests..."
    for domain in "${COMMON_DOMAINS[@]}"; do
        test_domain_resolution "$domain" "A" 3
    done

    log_info "Testing different record types..."
    test_domain_resolution "google.com" "AAAA" 3
    test_domain_resolution "google.com" "MX" 3

    log_info "Testing concurrent queries..."
    test_concurrent_queries "google.com" 5
    test_concurrent_queries "github.com" 10

    log_info "Testing cache performance..."
    test_cache_performance

    log_info "Testing memory usage..."
    test_memory_usage

    generate_report

    echo ""
    log_success "Performance testing completed!"
    log_info "Results saved in: $RESULTS_DIR"
    log_info "Report available at: $REPORT_FILE"
}

# Run main function
main "$@"
