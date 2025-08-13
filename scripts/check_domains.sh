#!/bin/bash

# DNS Resolver Test Script
# Tests all domains in domains.txt and tracks results and failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAINS_FILE="./tests/data/domains.txt"
RESULTS_FILE="./tests/results/results.txt"
FAILED_FILE="./tests/results/failed_domains.txt"
SUMMARY_FILE="./tests/results/summary.txt"
DNS_RESOLVER="./build/dns_resolver"
TIMEOUT_SECONDS=10

# Initialize files
echo "=== DNS Resolver Test Results ===" > "$RESULTS_FILE"
echo "Test started at: $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

echo "=== Failed Domains ===" > "$FAILED_FILE"
echo "Test started at: $(date)" >> "$FAILED_FILE"
echo "" >> "$FAILED_FILE"

echo "=== Test Summary ===" > "$SUMMARY_FILE"
echo "Test started at: $(date)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# Counters
total_domains=0
successful_domains=0
failed_domains=0

# Check if dns_resolver exists
if [ ! -f "$DNS_RESOLVER" ]; then
    echo -e "${RED}Error: DNS resolver executable not found at $DNS_RESOLVER${NC}"
    echo "Please build the project first by running 'make' or 'cmake --build build/'"
    exit 1
fi

# Make sure the executable has proper permissions
chmod +x "$DNS_RESOLVER"

# Check if domains file exists
if [ ! -f "$DOMAINS_FILE" ]; then
    echo -e "${RED}Error: Domains file not found at $DOMAINS_FILE${NC}"
    exit 1
fi

echo -e "${BLUE}Starting DNS resolution tests...${NC}"
echo -e "${YELLOW}Domains file: $DOMAINS_FILE${NC}"
echo -e "${YELLOW}Results file: $RESULTS_FILE${NC}"
echo -e "${YELLOW}Failed domains file: $FAILED_FILE${NC}"
echo ""

# Read domains and test each one
while IFS= read -r domain || [ -n "$domain" ]; do
    # Skip empty lines and comments
    if [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    # Remove any trailing whitespace
    domain=$(echo "$domain" | tr -d '\r\n' | xargs)

    if [ -z "$domain" ]; then
        continue
    fi

    total_domains=$((total_domains + 1))

    echo -ne "${BLUE}Testing domain $total_domains: $domain${NC}"

    # Run DNS resolver with timeout
    if timeout "$TIMEOUT_SECONDS" "$DNS_RESOLVER" "$domain" > /tmp/dns_output 2>&1; then
        exit_code=$?
        output=$(cat /tmp/dns_output)

        # Check if the output contains an IP address (successful resolution)
        if echo "$output" | grep -qE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
            echo -e " ${GREEN}✓ SUCCESS${NC}"
            successful_domains=$((successful_domains + 1))

            # Log successful result
            echo "SUCCESS: $domain" >> "$RESULTS_FILE"
            echo "$output" >> "$RESULTS_FILE"
            echo "----------------------------------------" >> "$RESULTS_FILE"
        else
            echo -e " ${RED}✗ FAILED (no IP found)${NC}"
            failed_domains=$((failed_domains + 1))

            # Log failed domain
            echo "$domain" >> "$FAILED_FILE"
            echo "FAILED: $domain (no IP address in output)" >> "$RESULTS_FILE"
            echo "$output" >> "$RESULTS_FILE"
            echo "----------------------------------------" >> "$RESULTS_FILE"
        fi
    else
        exit_code=$?
        echo -e " ${RED}✗ FAILED (timeout/error)${NC}"
        failed_domains=$((failed_domains + 1))

        # Log failed domain
        echo "$domain" >> "$FAILED_FILE"

        if [ $exit_code -eq 124 ]; then
            echo "FAILED: $domain (timeout after ${TIMEOUT_SECONDS}s)" >> "$RESULTS_FILE"
        else
            echo "FAILED: $domain (exit code: $exit_code)" >> "$RESULTS_FILE"
            if [ -f /tmp/dns_output ]; then
                cat /tmp/dns_output >> "$RESULTS_FILE"
            fi
        fi
        echo "----------------------------------------" >> "$RESULTS_FILE"
    fi

    # Clean up temporary file
    rm -f /tmp/dns_output

    # Add a small delay to avoid overwhelming the system
    sleep 0.1

done < "$DOMAINS_FILE"

# Summary
echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "${YELLOW}Total domains tested: $total_domains${NC}"
echo -e "${GREEN}Successful resolutions: $successful_domains${NC}"
echo -e "${RED}Failed resolutions: $failed_domains${NC}"

if [ $total_domains -gt 0 ]; then
    success_rate=$(( (successful_domains * 100) / total_domains ))
    echo -e "${YELLOW}Success rate: $success_rate%${NC}"
fi

# Add summary to summary file
echo "Test completed at: $(date)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Total domains tested: $total_domains" >> "$SUMMARY_FILE"
echo "Successful resolutions: $successful_domains" >> "$SUMMARY_FILE"
echo "Failed resolutions: $failed_domains" >> "$SUMMARY_FILE"
if [ $total_domains -gt 0 ]; then
    echo "Success rate: $success_rate%" >> "$SUMMARY_FILE"
fi

# Add summary to failed domains file
echo "" >> "$FAILED_FILE"
echo "=== Summary ===" >> "$FAILED_FILE"
echo "Test completed at: $(date)" >> "$FAILED_FILE"
echo "Total failed domains: $failed_domains" >> "$FAILED_FILE"

echo ""
echo -e "${BLUE}Results saved to: $RESULTS_FILE${NC}"
echo -e "${BLUE}Failed domains saved to: $FAILED_FILE${NC}"
echo -e "${BLUE}Summary saved to: $SUMMARY_FILE${NC}"

# Exit with error code if there were failures
if [ $failed_domains -gt 0 ]; then
    exit 1
else
    exit 0
fi
