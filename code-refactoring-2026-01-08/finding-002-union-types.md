# Finding #2: Traditional Union Types (Pre-PEP 604)

**Priority:** High  
**Impact:** Code clarity, modernization  
**Effort:** 2-3 hours (mostly global find/replace)  
**Python Version:** 3.10+ required  

---

## Problem Description

The codebase still uses `Optional[X]` and `Union[X, Y]` from the `typing` module instead of the cleaner PEP 604 syntax (`X | None`, `X | Y`).

### Current Usage (Pre-3.10)

```python
from typing import Optional, Union

def method(path: Optional[str]) -> Union[int, None]:
    ...
```

### Modern Usage (3.10+)

```python
def method(path: str | None) -> int | None:
    ...
```

---

## Why Change?

1. **Cleaner syntax** - Less imports, more readable
2. **Python 3.10+ standard** - Industry best practice
3. **No runtime overhead** - With `from __future__ import annotations`
4. **Better IDE support** - Preferred by type checkers

---

## Implementation

### Step 1: Global Find & Replace

**Replace all instances of:**

```
Optional[TYPE] → TYPE | None
Union[A, B, C] → A | B | C
```

### Step 2: Remove `typing.Union` Import

**Before:**
```python
from typing import Optional, Union, List, Dict
```

**After:**
```python
from typing import Any, TypedDict, TypeAlias
from collections.abc import Mapping, Sequence, Iterable
```

### Step 3: Update Type Aliases

**Before:**
```python
from typing import Dict, List, Optional

CVEData = Dict[str, Optional[Any]]
YearList = List[int]
```

**After:**
```python
CVEData: TypeAlias = dict[str, Any | None]
YearList: TypeAlias = list[int]
```

---

## Examples by Module

### `build.py`

**Before:**
```python
from typing import Optional, Union

def ensure_data_available(self) -> Optional[Path]:
    ...

def generate_data(self, years: Union[List[int], int]) -> Optional[Dict]:
    ...
```

**After:**
```python
def ensure_data_available(self) -> Path | None:
    ...

def generate_data(self, years: list[int] | int) -> dict | None:
    ...
```

### `data/download_cve_data.py`

**Before:**
```python
from typing import Optional, Union

def __init__(self, cache_dir: Optional[Union[str, Path]] = None, quiet: bool = False):
    ...

def is_cache_valid(self) -> Optional[bool]:
    ...
```

**After:**
```python
def __init__(self, cache_dir: str | Path | None = None, quiet: bool = False):
    ...

def is_cache_valid(self) -> bool | None:
    ...
```

---

## Complete Example

**Before:**
```python
from typing import Optional, Union, Dict, List
from pathlib import Path

class Analyzer:
    def __init__(self, base_dir: Optional[Union[str, Path]] = None) -> None:
        ...
    
    def process_data(self, data: Dict[str, List[int]]) -> Union[Dict, None]:
        ...
    
    def get_year(self, year: int) -> Optional[Dict[str, any]]:
        ...
```

**After:**
```python
from __future__ import annotations
from pathlib import Path
from typing import Any, TypeAlias

YearData: TypeAlias = dict[str, Any]

class Analyzer:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        ...
    
    def process_data(self, data: dict[str, list[int]]) -> dict | None:
        ...
    
    def get_year(self, year: int) -> YearData | None:
        ...
```

---

## Testing

```bash
# Verify syntax is correct
python -m py_compile data/download_cve_data.py

# Type check with mypy
python -m mypy data/download_cve_data.py
```

---

## Notes

- Use `X | None` instead of `Optional[X]` (cleaner, same meaning)
- Use `A | B | C` instead of `Union[A, B, C]`
- Use lowercase `dict`, `list`, `set`, `tuple` instead of `Dict`, `List`, etc.
- These are valid in function signatures even without future imports on 3.10+
