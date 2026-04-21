# Quick Reference: Running Bionex Backend Tests

## Installation & Setup

```bash
# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock pytest-asyncio pytest-timeout

# Verify installation
pytest --version
```

---

## Quick Start

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Phase
```bash
# Phase 1: Cryptography
pytest tests/test_crypto.py -v

# Phase 2: Authentication
pytest tests/test_auth.py -v

# Phase 3: Access Control
pytest tests/test_access_control.py -v

# Phase 4: Audit Logs
pytest tests/test_audit_logs.py -v

# Phase 5: Data Protection
pytest tests/test_data_protection.py -v

# Phase 6: Security Features
pytest tests/test_security_features.py -v

# Phase 7A: Performance
pytest tests/test_phase7_performance.py -v

# Phase 7B: Chaos/Resilience
pytest tests/test_phase7_chaos.py -v

# Phase 7C: Integration
pytest tests/test_phase7_integration.py -v
```

---

## Common Commands

### Run with Coverage Report
```bash
pytest tests/ --cov=app --cov-report=html --cov-report=term
```

### Run Specific Test
```bash
pytest tests/test_crypto.py::TestCryptoManager::test_aes_encrypt -v
```

### Run Tests Matching Pattern
```bash
pytest tests/ -k "encryption" -v
```

### Run with Output
```bash
pytest tests/ -v -s
```

### Run with Detailed Failures
```bash
pytest tests/ -vv --tb=long
```

---

## Performance Testing

### Run Performance Benchmarks
```bash
pytest tests/test_phase7_performance.py -v -s
```

### Run Specific Performance Test
```bash
pytest tests/test_phase7_performance.py::TestEncryptionThroughput -v
```

### Run with Timing
```bash
pytest tests/ --durations=10 -v
```

---

## Chaos Testing

### Run All Chaos Tests
```bash
pytest tests/test_phase7_chaos.py -v
```

### Run Specific Failure Scenario
```bash
pytest tests/test_phase7_chaos.py::TestRedisUnavailability -v
```

---

## Integration Testing

### Run Integration Tests
```bash
pytest tests/test_phase7_integration.py -v
```

### Run End-to-End Workflow
```bash
pytest tests/test_phase7_integration.py::TestE2ECompleteWorkflow -v
```

---

## Continuous Integration Setup

### GitHub Actions Workflow
```bash
# Quick test (on PR)
pytest tests/ -x -q

# Full test (on push to main)
pytest tests/ -v --cov=app --cov-report=xml

# Extended test (nightly)
pytest tests/ -v --timeout=300
```

### Pre-commit Hook
```bash
#!/bin/bash
pytest tests/ -x -q
if [ $? -ne 0 ]; then
  echo "Tests failed. Commit aborted."
  exit 1
fi
```

---

## Troubleshooting

### Test Fails: Connection Error
```bash
# Ensure database is running/seeded
python -m app.database init

# Clear cache
redis-cli FLUSHALL
```

### Test Fails: Import Error
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Test Fails: Timeout
```bash
# Increase timeout for slow systems
pytest tests/ --timeout=300 -v
```

### Test Fails: Permission Error
```bash
# Ensure vault is accessible
export VAULT_ADDR=http://localhost:8200
vault status
```

---

## Test Configuration

### Configuration File: `pytest.ini`
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --strict-markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration
    performance: marks tests as performance
timeout = 300
```

### Running by Marker
```bash
# Run only fast tests
pytest tests/ -m "not slow" -v

# Run only integration tests
pytest tests/ -m integration -v

# Run only performance tests
pytest tests/ -m performance -v
```

---

## Generating Reports

### HTML Coverage Report
```bash
pytest tests/ --cov=app --cov-report=html
open htmlcov/index.html
```

### XML Report (for CI)
```bash
pytest tests/ --cov=app --cov-report=xml
```

### JSON Report
```bash
pytest tests/ --json-report --json-report-file=report.json
```

### JUnit XML
```bash
pytest tests/ --junit-xml=junit.xml
```

---

## Performance Profiling

### Profile with Pytest Profiling
```bash
pytest tests/ --profile

# Profile with specific sort key
pytest tests/ --profile --profile-svg
```

### Memory Profiling
```bash
pytest tests/ --memprof --memprof-compare
```

---

## Test Development

### Create New Test File
```bash
touch tests/test_new_feature.py
```

### Test Template
```python
import pytest
from unittest.mock import Mock

class TestNewFeature:
    """Test new feature"""
    
    @pytest.fixture
    def setup(self):
        """Setup"""
        return {'db': Mock()}
    
    def test_example(self, setup):
        """Test example"""
        result = setup['db'].query()
        assert result is not None
```

### Run New Tests
```bash
pytest tests/test_new_feature.py -v
```

---

## Debugging Tests

### Enable Debug Output
```bash
pytest tests/ -vv --tb=long
```

### Drop into Debugger on Failure
```bash
pytest tests/ --pdb
```

### Print Statements in Tests
```bash
pytest tests/ -s
```

### List All Tests (Don't Run)
```bash
pytest tests/ --collect-only
```

---

## Performance Benchmarks

### View Performance Targets
```bash
# Encryption: 1000+ ops/sec, <1ms
# Decryption: 1000+ ops/sec, <1ms
# Key Exchange: <100ms
# Database Query: <10ms (indexed)
# Cache Hit: <1ms
# Load Capacity: 1000 RPS sustained
```

### Run Benchmark Test
```bash
pytest tests/test_phase7_performance.py::TestEncryptionThroughput -v -s
```

---

## Cleanup

### Remove Test Database
```bash
rm -f test.db
```

### Clear Test Cache
```bash
rm -rf .pytest_cache __pycache__
redis-cli FLUSHALL
```

### Remove Coverage Data
```bash
rm -rf .coverage htmlcov
```

---

## Tips & Best Practices

1. **Run Tests Frequently**
   ```bash
   # Before committing
   pytest tests/ -x -q
   ```

2. **Watch for Changes**
   ```bash
   # Use pytest-watch
   ptw tests/
   ```

3. **Parallel Execution**
   ```bash
   # Faster execution with pytest-xdist
   pytest tests/ -n auto
   ```

4. **Selective Testing**
   ```bash
   # Only modified files
   pytest tests/ --lf
   ```

5. **Fail Fast**
   ```bash
   # Stop on first failure
   pytest tests/ -x
   ```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Tests pass locally but fail in CI | Ensure all env vars set in CI config |
| Intermittent failures | Check for timing issues, use --timeout |
| Slow tests | Check DB indices, use caching |
| Mock not working | Verify patch path matches import path |
| Import errors | Check PYTHONPATH, install deps |
| Permission errors | Check file permissions, run as proper user |

---

## Summary

**Quick Commands**:
- `pytest tests/ -v` - Run all tests
- `pytest tests/test_crypto.py -v` - Run phase 1
- `pytest tests/ --cov=app` - Coverage report
- `pytest tests/ -k encryption -v` - Pattern matching
- `pytest tests/ --collect-only` - List tests

**Expected Outcomes**:
- ✓ 50+ tests passing
- ✓ 91%+ code coverage
- ✓ All performance targets met
- ✓ All security features verified

**For More Info**: See `TESTING_FRAMEWORK.md` and `TEST_VERIFICATION_CHECKLIST.md`
