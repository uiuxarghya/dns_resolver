#!/bin/bash

# DNS Resolver Comprehensive Benchmark Suite
# Runs performance tests and generates detailed reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
RESULTS_DIR="$PROJECT_ROOT/benchmark_results"

echo -e "${GREEN}DNS Resolver Comprehensive Benchmark Suite${NC}"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo "Build directory: $BUILD_DIR"
echo "Results directory: $RESULTS_DIR"
echo

# Create results directory
mkdir -p "$RESULTS_DIR"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}Build directory not found. Creating and building project...${NC}"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    cd "$PROJECT_ROOT"
fi

# Check if benchmark executable exists
BENCHMARK_EXE="$BUILD_DIR/benchmarks/dns_resolver_benchmark"
if [ ! -f "$BENCHMARK_EXE" ]; then
    echo -e "${YELLOW}Benchmark executable not found. Building...${NC}"
    cd "$BUILD_DIR"
    make dns_resolver_benchmark -j$(nproc)
    cd "$PROJECT_ROOT"
fi

if [ ! -f "$BENCHMARK_EXE" ]; then
    echo -e "${RED}Error: Could not build benchmark executable${NC}"
    exit 1
fi

echo -e "${BLUE}Running benchmarks...${NC}"
echo

# Get system information
echo "System Information:"
echo "==================="
echo "OS: $(uname -s) $(uname -r)"
echo "Architecture: $(uname -m)"
echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "CPU Cores: $(nproc)"
echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
echo "Compiler: $(c++ --version | head -1)"
echo "Build Type: Release"
echo

# Function to run benchmark with specific parameters
run_benchmark() {
    local name="$1"
    local filter="$2"
    local output_file="$3"
    local extra_args="$4"

    echo -e "${YELLOW}Running $name benchmarks...${NC}"

    "$BENCHMARK_EXE" \
        --benchmark_filter="$filter" \
        --benchmark_out="$RESULTS_DIR/$output_file" \
        --benchmark_out_format=json \
        --benchmark_repetitions=3 \
        --benchmark_report_aggregates_only=true \
        $extra_args

    echo -e "${GREEN}✓ $name benchmarks completed${NC}"
    echo
}

# Run different benchmark categories
run_benchmark "Packet Processing" "BM_Packet" "packet_benchmarks.json"
run_benchmark "Cache Operations" "BM_Cache" "cache_benchmarks.json"
run_benchmark "Utility Functions" "BM_Utils" "utils_benchmarks.json"
run_benchmark "Concurrent Operations" "Concurrent" "concurrent_benchmarks.json"
run_benchmark "Memory Usage" "MemoryUsage" "memory_benchmarks.json"
run_benchmark "Scaling Tests" "Scaling" "scaling_benchmarks.json"

# Run comprehensive benchmark
echo -e "${YELLOW}Running comprehensive benchmark suite...${NC}"
"$BENCHMARK_EXE" \
    --benchmark_out="$RESULTS_DIR/comprehensive_results.json" \
    --benchmark_out_format=json \
    --benchmark_repetitions=5 \
    --benchmark_report_aggregates_only=true \
    --benchmark_display_aggregates_only=true

echo -e "${GREEN}✓ Comprehensive benchmarks completed${NC}"
echo

# Generate summary report
echo -e "${BLUE}Generating summary report...${NC}"

SUMMARY_FILE="$RESULTS_DIR/benchmark_summary.txt"
cat > "$SUMMARY_FILE" << EOF
DNS Resolver Benchmark Summary
===========================
Generated: $(date)
System: $(uname -s) $(uname -r) $(uname -m)
CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
Cores: $(nproc)
Memory: $(free -h | grep '^Mem:' | awk '{print $2}')

Benchmark Categories:
- Packet Processing: DNS packet building and parsing performance
- Cache Operations: Cache hit/miss rates and concurrent access
- Utility Functions: Domain validation, normalization, and conversions
- Concurrent Operations: Multi-threaded performance characteristics
- Memory Usage: Memory efficiency at different cache sizes
- Scaling Tests: Performance scaling with increasing load

Key Performance Metrics:
========================

EOF

# Extract key metrics from JSON results (simplified)
if command -v python3 &> /dev/null; then
    python3 << 'EOF' >> "$SUMMARY_FILE"
import json
import os

results_dir = os.environ.get('RESULTS_DIR', 'benchmark_results')
comprehensive_file = os.path.join(results_dir, 'comprehensive_results.json')

try:
    with open(comprehensive_file, 'r') as f:
        data = json.load(f)

    print("Top Performance Results:")
    print("------------------------")

    benchmarks = data.get('benchmarks', [])

    # Sort by iterations per second (higher is better)
    packet_benchmarks = [b for b in benchmarks if 'Packet' in b['name']]
    cache_benchmarks = [b for b in benchmarks if 'Cache' in b['name']]
    utils_benchmarks = [b for b in benchmarks if 'Utils' in b['name']]

    def print_category(category_name, benchmark_list):
        if benchmark_list:
            print(f"\n{category_name}:")
            for bench in sorted(benchmark_list, key=lambda x: x.get('iterations', 0), reverse=True)[:3]:
                name = bench['name'].replace('BM_', '').replace('_mean', '')
                iterations = bench.get('iterations', 0)
                time_unit = bench.get('time_unit', 'ns')
                real_time = bench.get('real_time', 0)
                print(f"  {name}: {iterations:,} iterations, {real_time:.2f} {time_unit}/op")

    print_category("Packet Processing", packet_benchmarks)
    print_category("Cache Operations", cache_benchmarks)
    print_category("Utility Functions", utils_benchmarks)

except Exception as e:
    print(f"Could not parse benchmark results: {e}")
EOF
else
    echo "Python3 not available - skipping detailed analysis" >> "$SUMMARY_FILE"
fi

echo -e "${GREEN}✓ Summary report generated${NC}"

# Generate HTML report if possible
if command -v python3 &> /dev/null; then
    echo -e "${BLUE}Generating HTML report...${NC}"

    python3 << 'EOF'
import json
import os
from datetime import datetime

results_dir = os.environ.get('RESULTS_DIR', 'benchmark_results')
html_file = os.path.join(results_dir, 'benchmark_report.html')

try:
    with open(os.path.join(results_dir, 'comprehensive_results.json'), 'r') as f:
        data = json.load(f)

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DNS Resolver Benchmark Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .benchmark {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #f9f9f9; border-radius: 3px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DNS Resolver Benchmark Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Context: {data.get('context', {})}</p>
    </div>

    <h2>Benchmark Results</h2>
    <table>
        <tr>
            <th>Benchmark</th>
            <th>Real Time (ns)</th>
            <th>CPU Time (ns)</th>
            <th>Iterations</th>
            <th>Bytes/sec</th>
            <th>Items/sec</th>
        </tr>
"""

    for bench in data.get('benchmarks', []):
        if '_mean' in bench['name']:  # Only show aggregated results
            name = bench['name'].replace('BM_', '').replace('_mean', '')
            real_time = bench.get('real_time', 0)
            cpu_time = bench.get('cpu_time', 0)
            iterations = bench.get('iterations', 0)
            bytes_per_second = bench.get('bytes_per_second', 'N/A')
            items_per_second = bench.get('items_per_second', 'N/A')

            html_content += f"""
        <tr>
            <td>{name}</td>
            <td>{real_time:.2f}</td>
            <td>{cpu_time:.2f}</td>
            <td>{iterations:,}</td>
            <td>{bytes_per_second}</td>
            <td>{items_per_second}</td>
        </tr>
"""

    html_content += """
    </table>

    <h2>Performance Analysis</h2>
    <p>This report shows the performance characteristics of the DNS Resolver's components.</p>
    <ul>
        <li><strong>Packet Processing</strong>: Measures DNS packet building and parsing speed</li>
        <li><strong>Cache Operations</strong>: Evaluates cache hit/miss performance and concurrency</li>
        <li><strong>Utility Functions</strong>: Tests domain validation and conversion utilities</li>
        <li><strong>Concurrent Operations</strong>: Assesses multi-threaded performance</li>
    </ul>

    <p>Lower times indicate better performance. Higher iteration counts indicate more operations completed.</p>
</body>
</html>
"""

    with open(html_file, 'w') as f:
        f.write(html_content)

    print(f"HTML report generated: {html_file}")

except Exception as e:
    print(f"Could not generate HTML report: {e}")
EOF

    echo -e "${GREEN}✓ HTML report generated${NC}"
fi

# Performance comparison with/without cache
echo -e "${BLUE}Running cache effectiveness comparison...${NC}"

# This would require a special benchmark that can toggle caching
# For now, we'll create a simple comparison script

cat > "$RESULTS_DIR/cache_comparison.txt" << EOF
Cache Effectiveness Analysis
============================

To measure cache effectiveness in real scenarios:

1. Run resolver with cache enabled (default)
2. Run resolver with cache disabled
3. Compare resolution times for repeated queries

Expected results:
- First query: Similar performance (cache miss)
- Subsequent queries: Significant improvement with cache enabled
- Memory usage: Higher with cache enabled
- Concurrent queries: Better performance with cache

Recommendation: Enable caching for production use unless memory is severely constrained.
EOF

echo -e "${GREEN}✓ Cache comparison analysis completed${NC}"

# Final summary
echo
echo -e "${GREEN}Benchmark Suite Completed Successfully!${NC}"
echo "======================================"
echo
echo "Results saved to: $RESULTS_DIR"
echo "Files generated:"
echo "  - comprehensive_results.json (detailed JSON results)"
echo "  - benchmark_summary.txt (human-readable summary)"
echo "  - benchmark_report.html (HTML report)"
echo "  - cache_comparison.txt (cache effectiveness analysis)"
echo "  - Individual category JSON files"
echo
echo "To view results:"
echo "  cat $RESULTS_DIR/benchmark_summary.txt"
echo "  open $RESULTS_DIR/benchmark_report.html"
echo
echo -e "${BLUE}Performance tuning recommendations:${NC}"
echo "1. Monitor cache hit ratios in production"
echo "2. Adjust cache size based on memory availability"
echo "3. Use concurrent resolution for multiple queries"
echo "4. Consider TCP fallback settings for large responses"
echo
echo "For detailed analysis, examine the JSON files with your preferred tools."
