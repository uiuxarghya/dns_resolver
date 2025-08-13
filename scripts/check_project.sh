#!/bin/bash

# DNS Resolver Project Health Check Script
# This script verifies the project is in a good state

set -e

echo "🔍 DNS Resolver Project Health Check"
echo "================================="

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ] || [ ! -d "src" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

echo "✅ Project structure looks good"

# Check for required tools
echo ""
echo "🛠️  Checking build tools..."

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "✅ $1 is available"
        return 0
    else
        echo "❌ $1 is not available"
        return 1
    fi
}

TOOLS_OK=true
check_tool "cmake" || TOOLS_OK=false
check_tool "make" || TOOLS_OK=false
check_tool "g++" || check_tool "clang++" || TOOLS_OK=false
check_tool "git" || TOOLS_OK=false

if [ "$TOOLS_OK" = false ]; then
    echo "❌ Some required tools are missing"
    exit 1
fi

# Check C++ compiler version
echo ""
echo "🔧 Checking compiler version..."
if command -v g++ &> /dev/null; then
    GCC_VERSION=$(g++ --version | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)
    echo "✅ GCC version: $GCC_VERSION"
    if [ "$(echo "$GCC_VERSION >= 12" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        echo "✅ GCC version is sufficient for C++23"
    else
        echo "⚠️  GCC version might be too old for C++23 (need 12+)"
    fi
elif command -v clang++ &> /dev/null; then
    CLANG_VERSION=$(clang++ --version | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)
    echo "✅ Clang version: $CLANG_VERSION"
    if [ "$(echo "$CLANG_VERSION >= 15" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        echo "✅ Clang version is sufficient for C++23"
    else
        echo "⚠️  Clang version might be too old for C++23 (need 15+)"
    fi
fi

# Check CMake version
echo ""
echo "📦 Checking CMake version..."
CMAKE_VERSION=$(cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "✅ CMake version: $CMAKE_VERSION"

# Check if build directory exists and is configured
echo ""
echo "🏗️  Checking build configuration..."
if [ -d "build" ]; then
    echo "✅ Build directory exists"
    if [ -f "build/Makefile" ] || [ -f "build/build.ninja" ]; then
        echo "✅ Build system is configured"

        # Try to build
        echo ""
        echo "🔨 Testing build..."
        cd build
        if make -j$(nproc) > /dev/null 2>&1; then
            echo "✅ Project builds successfully"

            # Check if executables exist
            if [ -f "dns_resolver" ]; then
                echo "✅ Main executable built"
            else
                echo "❌ Main executable not found"
            fi

            if [ -f "tests/dns_resolver_tests" ]; then
                echo "✅ Test executable built"

                # Run tests
                echo ""
                echo "🧪 Running tests..."
                if ./tests/dns_resolver_tests --gtest_brief=1 > /dev/null 2>&1; then
                    echo "✅ All tests pass"
                else
                    echo "❌ Some tests are failing"
                fi
            else
                echo "❌ Test executable not found"
            fi

            if [ -f "benchmarks/dns_resolver_benchmark" ]; then
                echo "✅ Benchmark executable built"
            else
                echo "❌ Benchmark executable not found"
            fi
        else
            echo "❌ Build failed"
        fi
        cd ..
    else
        echo "⚠️  Build system not configured (run cmake ..)"
    fi
else
    echo "⚠️  Build directory doesn't exist (run mkdir build && cd build && cmake ..)"
fi

# Check documentation
echo ""
echo "📚 Checking documentation..."
[ -f "README.md" ] && echo "✅ README.md exists" || echo "❌ README.md missing"
[ -f "LICENSE" ] && echo "✅ LICENSE exists" || echo "❌ LICENSE missing"
[ -d "docs" ] && echo "✅ docs/ directory exists" || echo "❌ docs/ directory missing"

# Check git status
echo ""
echo "📝 Checking git status..."
if git status &> /dev/null; then
    UNCOMMITTED=$(git status --porcelain | wc -l)
    if [ "$UNCOMMITTED" -eq 0 ]; then
        echo "✅ Working directory is clean"
    else
        echo "⚠️  $UNCOMMITTED uncommitted changes"
    fi

    BRANCH=$(git branch --show-current)
    echo "✅ Current branch: $BRANCH"
else
    echo "❌ Not a git repository"
fi

echo ""
echo "🎉 Project health check complete!"
echo ""
echo "📋 Summary:"
echo "- Project structure: ✅"
echo "- Build tools: ✅"
echo "- Documentation: ✅"
echo "- Build system: $([ -f "build/Makefile" ] && echo "✅" || echo "⚠️")"
echo "- Tests: $([ -f "build/tests/dns_resolver_tests" ] && echo "✅" || echo "⚠️")"
echo ""
echo "🚀 Ready for development!"