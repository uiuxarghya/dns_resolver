#!/bin/bash

# DNS Resolver Build and Test Script
# Comprehensive build, test, and validation script

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

echo -e "${GREEN}DNS Resolver Build and Test Script${NC}"
echo "================================="
echo "Project root: $PROJECT_ROOT"
echo "Build directory: $BUILD_DIR"
echo

# Function to print section headers
print_section() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
    echo
}

# Function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1 successful${NC}"
    else
        echo -e "${RED}✗ $1 failed${NC}"
        exit 1
    fi
}

# Check prerequisites
print_section "Checking Prerequisites"

# Check for required tools
echo "Checking required tools..."

if ! command -v cmake &> /dev/null; then
    echo -e "${RED}Error: CMake not found${NC}"
    echo "Please install CMake 3.20 or higher"
    exit 1
fi

CMAKE_VERSION=$(cmake --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "CMake version: $CMAKE_VERSION"

if ! command -v make &> /dev/null; then
    echo -e "${RED}Error: Make not found${NC}"
    exit 1
fi

# Check C++ compiler
if command -v g++ &> /dev/null; then
    GCC_VERSION=$(g++ --version | head -1)
    echo "GCC: $GCC_VERSION"
elif command -v clang++ &> /dev/null; then
    CLANG_VERSION=$(clang++ --version | head -1)
    echo "Clang: $CLANG_VERSION"
else
    echo -e "${RED}Error: No C++ compiler found${NC}"
    echo "Please install GCC 12+ or Clang 15+"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites check passed${NC}"

# Clean previous build
print_section "Cleaning Previous Build"

if [ -d "$BUILD_DIR" ]; then
    echo "Removing existing build directory..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
echo -e "${GREEN}✓ Build directory prepared${NC}"

# Configure project
print_section "Configuring Project"

cd "$BUILD_DIR"

echo "Running CMake configuration..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_VERBOSE_MAKEFILE=ON

check_success "CMake configuration"

# Build project
print_section "Building Project"

echo "Building main executable..."
make dns_resolver -j$(nproc)
check_success "Main executable build"

echo "Building tests..."
make dns_resolver_tests -j$(nproc)
check_success "Tests build"

echo "Building benchmarks..."
make dns_resolver_benchmark -j$(nproc)
check_success "Benchmarks build"

# Verify executables
print_section "Verifying Executables"

MAIN_EXE="$BUILD_DIR/dns_resolver"
TEST_EXE="$BUILD_DIR/tests/dns_resolver_tests"
BENCH_EXE="$BUILD_DIR/benchmarks/dns_resolver_benchmark"

if [ -f "$MAIN_EXE" ]; then
    echo -e "${GREEN}✓ Main executable found: $MAIN_EXE${NC}"
    echo "Size: $(du -h "$MAIN_EXE" | cut -f1)"
else
    echo -e "${RED}✗ Main executable not found${NC}"
    exit 1
fi

if [ -f "$TEST_EXE" ]; then
    echo -e "${GREEN}✓ Test executable found: $TEST_EXE${NC}"
    echo "Size: $(du -h "$TEST_EXE" | cut -f1)"
else
    echo -e "${RED}✗ Test executable not found${NC}"
    exit 1
fi

if [ -f "$BENCH_EXE" ]; then
    echo -e "${GREEN}✓ Benchmark executable found: $BENCH_EXE${NC}"
    echo "Size: $(du -h "$BENCH_EXE" | cut -f1)"
else
    echo -e "${RED}✗ Benchmark executable not found${NC}"
    exit 1
fi

# Test basic functionality
print_section "Testing Basic Functionality"

echo "Testing help output..."
if "$MAIN_EXE" --help > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Help command works${NC}"
else
    echo -e "${RED}✗ Help command failed${NC}"
    exit 1
fi

echo "Testing version output..."
if "$MAIN_EXE" --version > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Version command works${NC}"
else
    echo -e "${RED}✗ Version command failed${NC}"
    exit 1
fi

echo "Testing invalid domain handling..."
if ! "$MAIN_EXE" "invalid..domain" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Invalid domain properly rejected${NC}"
else
    echo -e "${YELLOW}⚠ Invalid domain not properly rejected${NC}"
fi

# Run unit tests
print_section "Running Unit Tests"

echo "Running all unit tests..."
cd "$BUILD_DIR"
if "$TEST_EXE" --gtest_output=xml:test_results.xml; then
    echo -e "${GREEN}✓ All unit tests passed${NC}"
else
    echo -e "${RED}✗ Some unit tests failed${NC}"
    echo "Check test_results.xml for details"
    exit 1
fi

# Run quick benchmarks
print_section "Running Quick Benchmarks"

echo "Running quick performance benchmarks..."
if "$BENCH_EXE" --benchmark_filter="BM_PacketBuilder_SimpleQuery" --benchmark_min_time=0.1; then
    echo -e "${GREEN}✓ Benchmarks completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ Benchmarks had issues (non-critical)${NC}"
fi

# Code quality checks
print_section "Code Quality Checks"

cd "$PROJECT_ROOT"

# Run formatting check
if [ -f "scripts/format.sh" ]; then
    echo "Checking code formatting..."
    if ./scripts/format.sh --check; then
        echo -e "${GREEN}✓ Code formatting is correct${NC}"
    else
        echo -e "${YELLOW}⚠ Code formatting issues found${NC}"
        echo "Run './scripts/format.sh' to fix formatting"
    fi
fi

# Run linting (if available)
if [ -f "scripts/lint.sh" ] && command -v clang-tidy &> /dev/null; then
    echo "Running static analysis..."
    if ./scripts/lint.sh > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Static analysis passed${NC}"
    else
        echo -e "${YELLOW}⚠ Static analysis found issues${NC}"
        echo "Run './scripts/lint.sh' for details"
    fi
fi

# Memory leak check (if valgrind is available)
if command -v valgrind &> /dev/null; then
    print_section "Memory Leak Check"

    echo "Running memory leak detection..."
    cd "$BUILD_DIR"

    # Test with a simple query that should fail quickly
    if valgrind --leak-check=full --error-exitcode=1 --quiet \
       "$MAIN_EXE" "invalid..domain" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ No memory leaks detected${NC}"
    else
        echo -e "${YELLOW}⚠ Potential memory leaks detected${NC}"
        echo "Run valgrind manually for detailed analysis"
    fi
fi

# Integration test (if network is available)
print_section "Integration Test"

echo "Testing network connectivity..."
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo "Network connectivity available, running integration test..."

    # Try to resolve a well-known domain with short timeout
    cd "$BUILD_DIR"
    if timeout 10 "$MAIN_EXE" -T 5 "google.com" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Integration test passed${NC}"
    else
        echo -e "${YELLOW}⚠ Integration test failed (may be network-related)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No network connectivity, skipping integration test${NC}"
fi

# Final summary
print_section "Build Summary"

echo "Build and test completed successfully!"
echo
echo "Executables built:"
echo "  - Main: $MAIN_EXE"
echo "  - Tests: $TEST_EXE"
echo "  - Benchmarks: $BENCH_EXE"
echo
echo "Next steps:"
echo "  1. Run './dns_resolver --help' for usage information"
echo "  2. Test with: './dns_resolver google.com'"
echo "  3. Run full test suite: 'make test'"
echo "  4. Run benchmarks: './benchmarks/run_benchmarks.sh'"
echo "  5. Install system-wide: 'sudo make install'"
echo
echo -e "${GREEN}✓ DNS Resolver is ready for use!${NC}"

cd "$PROJECT_ROOT"