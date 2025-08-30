# 🚀 Run AI Threat Model Tests NOW

Follow these steps to test the AI threat model generation feature:

## Step 1: Build Threagile (Required)
```bash
make all
```
Wait for build to complete (about 30 seconds).

## Step 2: Quick Verification (1 minute)
```bash
./minimal-test.sh
```

You should see:
```
✅ Success! Threat model generated.
```

## Step 3: Run Full Test Suite (5 minutes)
```bash
# Setup test files
./setup-test-demo.sh

# Run all tests
./run-ai-tests.sh
```

Expected output:
```
=== Test Summary ===
Passed: 10
Failed: 0
Total: 10

All tests passed!
```

## Step 4: Try with Your Website Demo

If you have a website demo with infrastructure files:

```bash
# Replace with your actual path
./threagile ai-generate --iac-dirs /path/to/your/website/

# Check the output
ls -la threagile-generated.yaml
```

## What Each Test Script Does

- **minimal-test.sh** - Creates one Terraform file and generates a model
- **setup-test-demo.sh** - Creates a full demo project with Terraform & K8s files  
- **run-ai-tests.sh** - Runs 10 automated test cases
- **TEST_PLAN.md** - Detailed test documentation

## If You Hit Issues

1. **Build fails?**
   ```bash
   go mod download
   make clean
   make all
   ```

2. **Permission denied?**
   ```bash
   chmod +x *.sh
   chmod +x threagile
   ```

3. **No output generated?**
   - Check that your IaC files have .tf or .yaml extensions
   - Try with -v flag for verbose output (if implemented)

## Success Criteria

✅ `minimal-test.sh` generates a threat model
✅ `run-ai-tests.sh` shows all tests passed
✅ Your own infrastructure files generate a model

---

**Ready? Start with Step 1: `make all`**