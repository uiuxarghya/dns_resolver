#!/bin/bash

# DNS Resolver Code Formatting Script
# Uses clang-format to format all C++ source files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${GREEN}DNS Resolver Code Formatter${NC}"
echo "Project root: $PROJECT_ROOT"

# Check if clang-format is available
if ! command -v clang-format &> /dev/null; then
    echo -e "${RED}Error: clang-format not found${NC}"
    echo "Please install clang-format:"
    echo "  Ubuntu/Debian: sudo apt install clang-format"
    echo "  macOS: brew install clang-format"
    echo "  Arch Linux: sudo pacman -S clang"
    exit 1
fi

# Check clang-format version
CLANG_FORMAT_VERSION=$(clang-format --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
echo "Using clang-format version: $CLANG_FORMAT_VERSION"

# Create .clang-format config if it doesn't exist
CLANG_FORMAT_CONFIG="$PROJECT_ROOT/.clang-format"
if [ ! -f "$CLANG_FORMAT_CONFIG" ]; then
    echo -e "${YELLOW}Creating .clang-format configuration...${NC}"
    cat > "$CLANG_FORMAT_CONFIG" << 'EOF'
---
Language: Cpp
BasedOnStyle: Google
AccessModifierOffset: -2
AlignAfterOpenBracket: Align
AlignConsecutiveAssignments: false
AlignConsecutiveDeclarations: false
AlignEscapedNewlines: Left
AlignOperands: true
AlignTrailingComments: true
AllowAllParametersOfDeclarationOnNextLine: true
AllowShortBlocksOnASingleLine: false
AllowShortCaseLabelsOnASingleLine: false
AllowShortFunctionsOnASingleLine: All
AllowShortIfStatementsOnASingleLine: true
AllowShortLoopsOnASingleLine: true
AlwaysBreakAfterDefinitionReturnType: None
AlwaysBreakAfterReturnType: None
AlwaysBreakBeforeMultilineStrings: true
AlwaysBreakTemplateDeclarations: true
BinPackArguments: true
BinPackParameters: true
BraceWrapping:
  AfterClass: false
  AfterControlStatement: false
  AfterEnum: false
  AfterFunction: false
  AfterNamespace: false
  AfterObjCDeclaration: false
  AfterStruct: false
  AfterUnion: false
  BeforeCatch: false
  BeforeElse: false
  IndentBraces: false
BreakBeforeBinaryOperators: None
BreakBeforeBraces: Attach
BreakBeforeTernaryOperators: true
BreakConstructorInitializersBeforeComma: false
BreakAfterJavaFieldAnnotations: false
BreakStringLiterals: true
ColumnLimit: 100
CommentPragmas: '^ IWYU pragma:'
ConstructorInitializerAllOnOneLineOrOnePerLine: true
ConstructorInitializerIndentWidth: 4
ContinuationIndentWidth: 4
Cpp11BracedListStyle: true
DerivePointerAlignment: true
DisableFormat: false
ExperimentalAutoDetectBinPacking: false
ForEachMacros: [ foreach, Q_FOREACH, BOOST_FOREACH ]
IncludeCategories:
  - Regex: '^<.*\.h>'
    Priority: 1
  - Regex: '^<.*'
    Priority: 2
  - Regex: '.*'
    Priority: 3
IncludeIsMainRegex: '([-_](test|unittest))?$'
IndentCaseLabels: true
IndentWidth: 2
IndentWrappedFunctionNames: false
JavaScriptQuotes: Leave
JavaScriptWrapImports: true
KeepEmptyLinesAtTheStartOfBlocks: false
MacroBlockBegin: ''
MacroBlockEnd: ''
MaxEmptyLinesToKeep: 1
NamespaceIndentation: None
ObjCBlockIndentWidth: 2
ObjCSpaceAfterProperty: false
ObjCSpaceBeforeProtocolList: false
PenaltyBreakBeforeFirstCallParameter: 1
PenaltyBreakComment: 300
PenaltyBreakFirstLessLess: 120
PenaltyBreakString: 1000
PenaltyExcessCharacter: 1000000
PenaltyReturnTypeOnItsOwnLine: 200
PointerAlignment: Left
ReflowComments: true
SortIncludes: true
SpaceAfterCStyleCast: false
SpaceAfterTemplateKeyword: true
SpaceBeforeAssignmentOperators: true
SpaceBeforeParens: ControlStatements
SpaceInEmptyParentheses: false
SpacesBeforeTrailingComments: 2
SpacesInAngles: false
SpacesInContainerLiterals: true
SpacesInCStyleCastParentheses: false
SpacesInParentheses: false
SpacesInSquareBrackets: false
Standard: Cpp11
TabWidth: 8
UseTab: Never
EOF
    echo -e "${GREEN}Created .clang-format configuration${NC}"
fi

# Find all C++ source files
echo -e "${YELLOW}Finding C++ source files...${NC}"
CPP_FILES=$(find "$PROJECT_ROOT" -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.cc" -o -name "*.cxx" \) \
    ! -path "*/build/*" \
    ! -path "*/.git/*" \
    ! -path "*/third_party/*")

if [ -z "$CPP_FILES" ]; then
    echo -e "${YELLOW}No C++ files found to format${NC}"
    exit 0
fi

echo "Found $(echo "$CPP_FILES" | wc -l) C++ files"

# Check if we should just check formatting or apply it
CHECK_ONLY=false
if [ "$1" = "--check" ] || [ "$1" = "-c" ]; then
    CHECK_ONLY=true
    echo -e "${YELLOW}Running in check mode (no changes will be made)${NC}"
fi

# Format files
FORMATTED_COUNT=0
NEEDS_FORMATTING=()

for file in $CPP_FILES; do
    if [ "$CHECK_ONLY" = true ]; then
        # Check if file needs formatting
        if ! clang-format --dry-run --Werror "$file" &>/dev/null; then
            NEEDS_FORMATTING+=("$file")
            echo -e "${RED}✗${NC} $file needs formatting"
        else
            echo -e "${GREEN}✓${NC} $file is properly formatted"
        fi
    else
        # Apply formatting
        echo "Formatting: $file"
        clang-format -i "$file"
        FORMATTED_COUNT=$((FORMATTED_COUNT + 1))
    fi
done

# Summary
echo
if [ "$CHECK_ONLY" = true ]; then
    if [ ${#NEEDS_FORMATTING[@]} -eq 0 ]; then
        echo -e "${GREEN}All files are properly formatted!${NC}"
        exit 0
    else
        echo -e "${RED}${#NEEDS_FORMATTING[@]} files need formatting:${NC}"
        for file in "${NEEDS_FORMATTING[@]}"; do
            echo "  $file"
        done
        echo
        echo "Run './scripts/format.sh' to fix formatting issues"
        exit 1
    fi
else
    echo -e "${GREEN}Formatted $FORMATTED_COUNT files successfully!${NC}"
    echo
    echo "To check formatting without making changes, use:"
    echo "  ./scripts/format.sh --check"
fi