# Finding #5: Exception Handling Specificity

**Priority:** High  
**Impact:** Better error handling and debugging  
**Effort:** 2-3 hours  

---

## Problem

Broad exception catching with generic `Exception` makes debugging harder and can hide unexpected errors.

### Current Code

```python
# In download_cve_data.py
try:
    response = requests.get(self.nvd_url, stream=True)
    # ... processing
except Exception as e:  # Too broad!
    print(f"Error: {e}")
    return None
```

### Issues

1. Catches all exceptions including `KeyboardInterrupt`
2. Can't distinguish between network errors and data parsing errors
3. Makes testing harder (can't verify specific errors)

---

## Solution

### Pattern 1: Request Errors

```python
# Before
try:
    response = requests.get(url)
except Exception as e:
    print(f"Download failed: {e}")

# After
import requests

try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
except requests.ConnectionError as e:
    print(f"Network error: {e}")
except requests.Timeout as e:
    print(f"Request timeout: {e}")
except requests.HTTPError as e:
    print(f"HTTP error {e.response.status_code}: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
    raise  # Re-raise if we can't handle it
```

### Pattern 2: File Operations

```python
# Before
try:
    with open(filepath) as f:
        data = json.load(f)
except Exception as e:
    print(f"Error: {e}")

# After
import json

try:
    with open(filepath) as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"File not found: {filepath}")
    return None
except json.JSONDecodeError as e:
    print(f"Invalid JSON at line {e.lineno}: {e.msg}")
    return None
except IOError as e:
    print(f"File read error: {e}")
    raise
```

### Pattern 3: JSON/Data Parsing

```python
# Before
try:
    data = json.load(f)
except Exception:
    return {}

# After
try:
    data = json.load(f)
except json.JSONDecodeError as e:
    logger.error(f"JSON decode error: {e}")
    return {}
except (ValueError, KeyError) as e:
    logger.error(f"Data structure error: {e}")
    return {}
```

---

## Changes by File

### `download_cve_data.py`

```python
# Before
except requests.RequestException as e:
    print(f"Download failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")

# After
except requests.ConnectionError as e:
    logger.error(f"Connection failed: {e}")
except requests.Timeout as e:
    logger.error(f"Request timed out after {timeout}s")
except requests.HTTPError as e:
    logger.error(f"HTTP {e.response.status_code}: {e.response.reason}")
except requests.RequestException as e:
    logger.error(f"Request failed: {e}")
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise
```

### `cve_v5_processor.py`

```python
# Better subprocess error handling
try:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600
    )
except subprocess.TimeoutExpired:
    logger.error(f"Command timed out after 600s")
    return False
except FileNotFoundError:
    logger.error(f"Command not found: {cmd[0]}")
    return False
except Exception as e:
    logger.error(f"Command failed: {e}")
    return False
```

---

## Custom Exception Classes

For complex logic, create custom exceptions:

```python
class CVEDataError(Exception):
    """Base exception for CVE data processing."""
    pass

class InvalidCVEFormat(CVEDataError):
    """Raised when CVE data format is invalid."""
    pass

class MissingCVEData(CVEDataError):
    """Raised when required CVE data is missing."""
    pass

# Usage
try:
    if not cve_data.get('cve'):
        raise MissingCVEData(f"Missing 'cve' field in {cve_id}")
    if 'id' not in cve_data['cve']:
        raise InvalidCVEFormat(f"Invalid structure in {cve_id}")
except CVEDataError as e:
    logger.error(f"Data error: {e}")
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise
```

---

## Testing Exception Handling

```python
import pytest

def test_missing_file():
    """Test handling of missing files."""
    with pytest.raises(FileNotFoundError):
        load_data(Path('/nonexistent/file.json'))

def test_invalid_json():
    """Test handling of invalid JSON."""
    with pytest.raises(json.JSONDecodeError):
        json.loads('{ invalid json }')

def test_custom_exception():
    """Test custom exceptions."""
    with pytest.raises(MissingCVEData):
        validate_cve({'no': 'cve field'})
```

---

## Summary of Exception Types to Use

| Scenario | Exception | Example |
|----------|-----------|---------|
| File not found | `FileNotFoundError` | Missing cache file |
| Invalid JSON | `json.JSONDecodeError` | Corrupted data file |
| Network error | `requests.ConnectionError` | Network down |
| Timeout | `requests.Timeout` or `subprocess.TimeoutExpired` | Long-running operation |
| Invalid data | Custom exception | MissingCVEData, InvalidCVEFormat |
| Type error | `TypeError` | Wrong argument type |
| Value error | `ValueError` | Invalid value |

---

## References

- [Python Exceptions](https://docs.python.org/3/library/exceptions.html)
- [requests Library Exceptions](https://docs.requests.org/en/latest/user/advanced/#errors-and-exceptions)
- [json Module Exceptions](https://docs.python.org/3/library/json.html#json.JSONDecodeError)
