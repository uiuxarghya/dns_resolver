#!/bin/bash

# DNS Resolver Code Linting Script
# Uses clang-tidy to perform static analysis on C++ source files

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

echo -e "${GREEN}DNS Resolver Code Linter${NC}"
echo "Project root: $PROJECT_ROOT"

# Check if clang-tidy is available
if ! command -v clang-tidy &> /dev/null; then
    echo -e "${RED}Error: clang-tidy not found${NC}"
    echo "Please install clang-tidy:"
    echo "  Ubuntu/Debian: sudo apt install clang-tidy"
    echo "  macOS: brew install llvm"
    echo "  Arch Linux: sudo pacman -S clang"
    exit 1
fi

# Check clang-tidy version
CLANG_TIDY_VERSION=$(clang-tidy --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "Using clang-tidy version: $CLANG_TIDY_VERSION"

# Create .clang-tidy config if it doesn't exist
CLANG_TIDY_CONFIG="$PROJECT_ROOT/.clang-tidy"
if [ ! -f "$CLANG_TIDY_CONFIG" ]; then
    echo -e "${YELLOW}Creating .clang-tidy configuration...${NC}"
    cat > "$CLANG_TIDY_CONFIG" << 'EOF'
---
Checks: >
  *,
  -abseil-*,
  -altera-*,
  -android-*,
  -fuchsia-*,
  -google-*,
  -llvm-*,
  -llvmlibc-*,
  -zircon-*,
  -readability-magic-numbers,
  -cppcoreguidelines-avoid-magic-numbers,
  -modernize-use-trailing-return-type,
  -readability-function-cognitive-complexity,
  -bugprone-easily-swappable-parameters,
  -misc-non-private-member-variables-in-classes,
  -cppcoreguidelines-non-private-member-variables-in-classes

WarningsAsErrors: ''
HeaderFilterRegex: '.*'
AnalyzeTemporaryDtors: false
FormatStyle: file
CheckOptions:
  - key: readability-identifier-naming.NamespaceCase
    value: lower_case
  - key: readability-identifier-naming.ClassCase
    value: CamelCase
  - key: readability-identifier-naming.StructCase
    value: CamelCase
  - key: readability-identifier-naming.TemplateParameterCase
    value: CamelCase
  - key: readability-identifier-naming.FunctionCase
    value: lower_case
  - key: readability-identifier-naming.VariableCase
    value: lower_case
  - key: readability-identifier-naming.ClassMemberCase
    value: lower_case
  - key: readability-identifier-naming.ClassMemberSuffix
    value: _
  - key: readability-identifier-naming.PrivateMemberSuffix
    value: _
  - key: readability-identifier-naming.ProtectedMemberSuffix
    value: _
  - key: readability-identifier-naming.EnumConstantCase
    value: UPPER_CASE
  - key: readability-identifier-naming.ConstantCase
    value: UPPER_CASE
  - key: readability-identifier-naming.StaticConstantCase
    value: UPPER_CASE
  - key: readability-identifier-naming.GlobalConstantCase
    value: UPPER_CASE
  - key: readability-identifier-naming.TypeAliasCase
    value: CamelCase
  - key: readability-identifier-naming.TypedefCase
    value: CamelCase
  - key: modernize-loop-convert.MaxCopySize
    value: 16
  - key: modernize-loop-convert.MinConfidence
    value: reasonable
  - key: modernize-loop-convert.NamingStyle
    value: CamelCase
  - key: modernize-pass-by-value.IncludeStyle
    value: llvm
  - key: modernize-replace-auto-ptr.IncludeStyle
    value: llvm
  - key: modernize-use-nullptr.NullMacros
    value: 'NULL'
EOF
    echo -e "${GREEN}Created .clang-tidy configuration${NC}"
fi

# Check if compile_commands.json exists
COMPILE_COMMANDS="$PROJECT_ROOT/build/compile_commands.json"
if [ ! -f "$COMPILE_COMMANDS" ]; then
    echo -e "${YELLOW}compile_commands.json not found. Building project first...${NC}"

    # Create build directory if it doesn't exist
    mkdir -p "$PROJECT_ROOT/build"
    cd "$PROJECT_ROOT/build"

    # Generate compile commands
    cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

    if [ ! -f "$COMPILE_COMMANDS" ]; then
        echo -e "${RED}Failed to generate compile_commands.json${NC}"
        echo "Please build the project first with CMake"
        exit 1
    fi

    cd "$PROJECT_ROOT"
fi

# Find all C++ source files
echo -e "${YELLOW}Finding C++ source files...${NC}"
CPP_FILES=$(find "$PROJECT_ROOT/src" -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.cc" -o -name "*.cxx" \) \
    ! -path "*/build/*" \
    ! -path "*/.git/*" \
    ! -path "*/third_party/*")

if [ -z "$CPP_FILES" ]; then
    echo -e "${YELLOW}No C++ files found to lint${NC}"
    exit 0
fi

echo "Found $(echo "$CPP_FILES" | wc -l) C++ files"

# Parse command line arguments
FIX_MODE=false
VERBOSE=false
SPECIFIC_CHECKS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_MODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --checks)
            SPECIFIC_CHECKS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --fix         Apply automatic fixes where possible"
            echo "  -v, --verbose Show detailed output"
            echo "  --checks      Specify specific checks to run"
            echo "  -h, --help    Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build clang-tidy command
CLANG_TIDY_CMD="clang-tidy"
CLANG_TIDY_ARGS="-p $PROJECT_ROOT/build"

if [ "$FIX_MODE" = true ]; then
    CLANG_TIDY_ARGS="$CLANG_TIDY_ARGS --fix"
    echo -e "${YELLOW}Running in fix mode (changes will be applied)${NC}"
fi

if [ -n "$SPECIFIC_CHECKS" ]; then
    CLANG_TIDY_ARGS="$CLANG_TIDY_ARGS --checks=$SPECIFIC_CHECKS"
    echo -e "${BLUE}Using specific checks: $SPECIFIC_CHECKS${NC}"
fi

# Run clang-tidy on each file
TOTAL_ISSUES=0
FILES_WITH_ISSUES=0

echo -e "${YELLOW}Running clang-tidy analysis...${NC}"
echo

for file in $CPP_FILES; do
    echo -e "${BLUE}Analyzing: $file${NC}"

    # Run clang-tidy and capture output
    if [ "$VERBOSE" = true ]; then
        OUTPUT=$($CLANG_TIDY_CMD $CLANG_TIDY_ARGS "$file" 2>&1)
    else
        OUTPUT=$($CLANG_TIDY_CMD $CLANG_TIDY_ARGS "$file" 2>&1 | grep -E "(warning|error):")
    fi

    if [ -n "$OUTPUT" ]; then
        echo "$OUTPUT"

        # Count issues
        ISSUE_COUNT=$(echo "$OUTPUT" | grep -c -E "(warning|error):" || true)
        if [ "$ISSUE_COUNT" -gt 0 ]; then
            TOTAL_ISSUES=$((TOTAL_ISSUES + ISSUE_COUNT))
            FILES_WITH_ISSUES=$((FILES_WITH_ISSUES + 1))
        fi
        echo
    else
        echo -e "${GREEN}✓ No issues found${NC}"
        echo
    fi
done

# Summary
echo -e "${BLUE}=== Linting Summary ===${NC}"
echo "Files analyzed: $(echo "$CPP_FILES" | wc -l)"
echo "Files with issues: $FILES_WITH_ISSUES"
echo "Total issues found: $TOTAL_ISSUES"

if [ "$TOTAL_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}🎉 No issues found! Code quality looks good.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Found $TOTAL_ISSUES issues in $FILES_WITH_ISSUES files.${NC}"

    if [ "$FIX_MODE" = false ]; then
        echo
        echo "To automatically fix issues where possible, run:"
        echo "  ./scripts/lint.sh --fix"
    fi

    exit 1
fi