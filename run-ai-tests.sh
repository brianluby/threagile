#!/bin/bash

# AI Threat Model Generation Test Runner

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test result tracking
PASSED=0
FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_result="$3"
    
    echo -e "\n${YELLOW}Running Test: $test_name${NC}"
    echo "Command: $command"
    
    # Run command and capture result
    if [ "$expected_result" = "should_fail" ]; then
        if $command 2>/dev/null; then
            echo -e "${RED}✗ FAILED${NC} - Expected failure but command succeeded"
            ((FAILED++))
        else
            echo -e "${GREEN}✓ PASSED${NC} - Failed as expected"
            ((PASSED++))
        fi
    else
        if $command; then
            echo -e "${GREEN}✓ PASSED${NC}"
            ((PASSED++))
        else
            echo -e "${RED}✗ FAILED${NC}"
            ((FAILED++))
        fi
    fi
}

# Check if threagile is built
if [ ! -f "./threagile" ]; then
    echo "Error: threagile binary not found. Please run 'make all' first."
    exit 1
fi

# Setup test environment
echo "Setting up test environment..."
if [ ! -d "test-website-demo" ]; then
    bash setup-test-demo.sh
fi

# Clean up any previous test outputs
rm -f threagile-generated.yaml custom-model.yaml

echo -e "\n${YELLOW}=== Starting AI Threat Model Generation Tests ===${NC}"

# Test 1: Basic Terraform Parsing
run_test "TC1: Basic Terraform Parsing" \
    "./threagile ai-generate --iac-dirs test-website-demo/terraform/" \
    "should_pass"

# Validate output
if [ -f "threagile-generated.yaml" ]; then
    echo "✓ Output file created"
    # Check for expected content
    if grep -q "web_server" threagile-generated.yaml && \
       grep -q "api_server" threagile-generated.yaml && \
       grep -q "web_lb" threagile-generated.yaml; then
        echo "✓ Contains expected assets"
    else
        echo "✗ Missing expected assets"
        ((FAILED++))
    fi
else
    echo "✗ Output file not created"
    ((FAILED++))
fi

# Clean up for next test
rm -f threagile-generated.yaml

# Test 2: Kubernetes Manifest Parsing
run_test "TC2: Kubernetes Manifest Parsing" \
    "./threagile ai-generate --iac-dirs test-website-demo/kubernetes/" \
    "should_pass"

# Validate Kubernetes output
if [ -f "threagile-generated.yaml" ]; then
    if grep -q "frontend" threagile-generated.yaml && \
       grep -q "backend_api" threagile-generated.yaml && \
       grep -q "production" threagile-generated.yaml; then
        echo "✓ Contains Kubernetes assets"
    fi
fi

rm -f threagile-generated.yaml

# Test 3: Mixed Infrastructure
run_test "TC3: Mixed Infrastructure Parsing" \
    "./threagile ai-generate --iac-dirs test-website-demo/terraform/,test-website-demo/kubernetes/" \
    "should_pass"

rm -f threagile-generated.yaml

# Test 4: Context File Integration
run_test "TC4: Context File Integration" \
    "./threagile ai-generate --iac-dirs test-website-demo/ --context-files test-website-demo/CLAUDE.md" \
    "should_pass"

# Check if context was applied
if [ -f "threagile-generated.yaml" ]; then
    if grep -q "E-Commerce" threagile-generated.yaml; then
        echo "✓ Context applied to model title"
    fi
fi

rm -f threagile-generated.yaml

# Test 5: JSON Output
run_test "TC5: JSON Output Mode" \
    "./threagile ai-generate --iac-dirs test-website-demo/ --json" \
    "should_pass"

# Test 6: Invalid Directory
run_test "TC6: Invalid Directory Error" \
    "./threagile ai-generate --iac-dirs /nonexistent/path/" \
    "should_fail"

# Test 7: Empty Directory
run_test "TC7: No IaC Files Error" \
    "./threagile ai-generate --iac-dirs test-website-demo/empty/" \
    "should_fail"

# Test 8: Detailed Mode Error
run_test "TC8: Detailed Mode Not Implemented" \
    "./threagile ai-generate --mode detailed --iac-dirs test-website-demo/" \
    "should_fail"

# Test 9: Custom Output Path
run_test "TC9: Custom Output Path" \
    "./threagile ai-generate --iac-dirs test-website-demo/ --output-file custom-model.yaml" \
    "should_pass"

if [ -f "custom-model.yaml" ]; then
    echo "✓ Custom output file created"
    rm -f custom-model.yaml
else
    echo "✗ Custom output file not created"
    ((FAILED++))
fi

# Test 10: Full Integration (Generate + Analyze)
echo -e "\n${YELLOW}Running Full Integration Test${NC}"
run_test "TC10a: Generate Model" \
    "./threagile ai-generate --iac-dirs test-website-demo/" \
    "should_pass"

if [ -f "threagile-generated.yaml" ]; then
    run_test "TC10b: Analyze Model" \
        "./threagile analyze-model" \
        "should_pass"
fi

# Summary
echo -e "\n${YELLOW}=== Test Summary ===${NC}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo -e "Total: $((PASSED + FAILED))"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi