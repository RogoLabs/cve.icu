#!/usr/bin/env python3
"""
Test doubles (fakes) for CVE.ICU protocols.

Provides in-memory implementations of protocols for unit testing.
These fakes allow tests to run without actual file system access
or HTTP requests, making tests faster and more deterministic.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FakeHttpResponse:
    """Fake HTTP response for testing.
    
    Simulates requests.Response interface with configurable
    status codes, content, and headers.
    """
    
    def __init__(
        self,
        status_code: int = 200,
        content: bytes = b'',
        headers: dict[str, str] | None = None,
        json_data: Any | None = None
    ) -> None:
        self._status_code = status_code
        self._content = content
        self._headers = headers or {}
        self._json_data = json_data
        
        # If json_data provided, serialize it to content
        if json_data is not None and not content:
            self._content = json.dumps(json_data).encode('utf-8')
    
    @property
    def status_code(self) -> int:
        return self._status_code
    
    @property
    def content(self) -> bytes:
        return self._content
    
    @property
    def text(self) -> str:
        return self._content.decode('utf-8')
    
    @property
    def headers(self) -> dict[str, str]:
        return self._headers
    
    def json(self) -> Any:
        if self._json_data is not None:
            return self._json_data
        return json.loads(self._content.decode('utf-8'))
    
    def raise_for_status(self) -> None:
        if self._status_code >= 400:
            raise FakeHttpError(f"HTTP {self._status_code}")
    
    def iter_content(self, chunk_size: int = 1) -> Any:
        """Yield content in chunks."""
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]


class FakeHttpError(Exception):
    """Fake HTTP error for testing error handling."""
    pass


class FakeHttpClient:
    """Fake HTTP client for testing.
    
    Provides configurable responses for specific URLs.
    Tracks request history for assertions.
    
    Example:
        client = FakeHttpClient()
        client.add_response('https://example.com/data.json', 
                           json_data={'key': 'value'})
        response = client.get('https://example.com/data.json')
        assert response.json() == {'key': 'value'}
        assert client.request_count == 1
    """
    
    def __init__(self) -> None:
        self._responses: dict[str, FakeHttpResponse] = {}
        self._request_history: list[dict[str, Any]] = []
        self._default_response: FakeHttpResponse | None = None
    
    def add_response(
        self,
        url: str,
        *,
        status_code: int = 200,
        content: bytes = b'',
        headers: dict[str, str] | None = None,
        json_data: Any | None = None
    ) -> None:
        """Add a fake response for a specific URL."""
        self._responses[url] = FakeHttpResponse(
            status_code=status_code,
            content=content,
            headers=headers or {'content-length': str(len(content))},
            json_data=json_data
        )
    
    def set_default_response(
        self,
        status_code: int = 200,
        content: bytes = b'',
        json_data: Any | None = None
    ) -> None:
        """Set default response for unregistered URLs."""
        self._default_response = FakeHttpResponse(
            status_code=status_code,
            content=content,
            json_data=json_data
        )
    
    def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
        stream: bool = False
    ) -> FakeHttpResponse:
        """Perform fake HTTP GET request."""
        self._request_history.append({
            'url': url,
            'timeout': timeout,
            'stream': stream
        })
        
        if url in self._responses:
            return self._responses[url]
        
        if self._default_response is not None:
            return self._default_response
        
        # Return 404 for unregistered URLs
        return FakeHttpResponse(status_code=404, content=b'Not Found')
    
    @property
    def request_count(self) -> int:
        """Number of requests made."""
        return len(self._request_history)
    
    @property
    def request_history(self) -> list[dict[str, Any]]:
        """List of all requests made."""
        return self._request_history.copy()
    
    def clear_history(self) -> None:
        """Clear request history."""
        self._request_history.clear()


class FakeDataReader:
    """Fake data reader for testing.
    
    Provides in-memory file system simulation.
    
    Example:
        reader = FakeDataReader()
        reader.add_json(Path('config.json'), {'debug': True})
        config = reader.read_json(Path('config.json'))
        assert config == {'debug': True}
    """
    
    def __init__(self) -> None:
        self._files: dict[str, bytes] = {}
        self._json_files: dict[str, Any] = {}
    
    def add_file(self, path: Path, content: bytes | str) -> None:
        """Add a fake file."""
        key = str(path)
        if isinstance(content, str):
            self._files[key] = content.encode('utf-8')
        else:
            self._files[key] = content
    
    def add_json(self, path: Path, data: Any) -> None:
        """Add a fake JSON file."""
        key = str(path)
        self._json_files[key] = data
        self._files[key] = json.dumps(data).encode('utf-8')
    
    def add_directory(self, path: Path, files: list[str]) -> None:
        """Add a fake directory with file names."""
        key = str(path)
        # Store directory marker and contents
        self._files[f"{key}/__dir__"] = b''
        for file_name in files:
            file_path = path / file_name
            if str(file_path) not in self._files:
                self._files[str(file_path)] = b''
    
    def read_json(self, path: Path) -> Any:
        """Read and parse JSON from fake file."""
        key = str(path)
        if key in self._json_files:
            return self._json_files[key]
        if key in self._files:
            return json.loads(self._files[key].decode('utf-8'))
        raise FileNotFoundError(f"Fake file not found: {path}")
    
    def read_text(self, path: Path) -> str:
        """Read text content from fake file."""
        key = str(path)
        if key in self._files:
            return self._files[key].decode('utf-8')
        raise FileNotFoundError(f"Fake file not found: {path}")
    
    def read_bytes(self, path: Path) -> bytes:
        """Read binary content from fake file."""
        key = str(path)
        if key in self._files:
            return self._files[key]
        raise FileNotFoundError(f"Fake file not found: {path}")
    
    def exists(self, path: Path) -> bool:
        """Check if fake path exists."""
        key = str(path)
        return key in self._files or f"{key}/__dir__" in self._files
    
    def list_dir(self, path: Path) -> list[Path]:
        """List fake directory contents."""
        key = str(path)
        result = []
        prefix = f"{key}/"
        seen = set()
        
        for file_key in self._files:
            if file_key.startswith(prefix) and file_key != f"{key}/__dir__":
                # Get the immediate child
                remainder = file_key[len(prefix):]
                child = remainder.split('/')[0]
                if child not in seen:
                    seen.add(child)
                    result.append(Path(path) / child)
        
        return result


class FakeDataWriter:
    """Fake data writer for testing.
    
    Captures all writes in memory for assertions.
    
    Example:
        writer = FakeDataWriter()
        writer.write_json(Path('output.json'), {'result': 42})
        assert writer.get_json(Path('output.json')) == {'result': 42}
    """
    
    def __init__(self) -> None:
        self._files: dict[str, bytes] = {}
        self._directories: set[str] = set()
    
    def write_json(self, path: Path, data: Any, indent: int = 2) -> None:
        """Write data as JSON to fake file."""
        key = str(path)
        self._files[key] = json.dumps(data, indent=indent).encode('utf-8')
    
    def write_text(self, path: Path, content: str) -> None:
        """Write text content to fake file."""
        key = str(path)
        self._files[key] = content.encode('utf-8')
    
    def write_bytes(self, path: Path, content: bytes) -> None:
        """Write binary content to fake file."""
        key = str(path)
        self._files[key] = content
    
    def mkdir(self, path: Path, parents: bool = True, exist_ok: bool = True) -> None:
        """Create fake directory."""
        key = str(path)
        if key in self._directories and not exist_ok:
            raise FileExistsError(f"Directory exists: {path}")
        self._directories.add(key)
    
    # Assertion helpers
    
    def get_json(self, path: Path) -> Any:
        """Get written JSON data for assertions."""
        key = str(path)
        if key not in self._files:
            raise KeyError(f"File not written: {path}")
        return json.loads(self._files[key].decode('utf-8'))
    
    def get_text(self, path: Path) -> str:
        """Get written text content for assertions."""
        key = str(path)
        if key not in self._files:
            raise KeyError(f"File not written: {path}")
        return self._files[key].decode('utf-8')
    
    def get_bytes(self, path: Path) -> bytes:
        """Get written binary content for assertions."""
        key = str(path)
        if key not in self._files:
            raise KeyError(f"File not written: {path}")
        return self._files[key]
    
    def was_written(self, path: Path) -> bool:
        """Check if file was written."""
        return str(path) in self._files
    
    def was_directory_created(self, path: Path) -> bool:
        """Check if directory was created."""
        return str(path) in self._directories
    
    @property
    def written_files(self) -> list[str]:
        """List all written file paths."""
        return list(self._files.keys())
    
    @property
    def created_directories(self) -> list[str]:
        """List all created directories."""
        return list(self._directories)


class FakeCacheManager:
    """Fake cache manager for testing.
    
    In-memory cache with configurable validity.
    
    Example:
        cache = FakeCacheManager()
        cache.set('key', 'value', ttl_seconds=3600)
        assert cache.get('key') == 'value'
        assert cache.is_valid('key') == True
    """
    
    def __init__(self, default_valid: bool = True) -> None:
        self._cache: dict[str, Any] = {}
        self._validity: dict[str, bool] = {}
        self._default_valid = default_valid
    
    def is_valid(self, key: str) -> bool:
        """Check if cache entry is valid."""
        if key not in self._cache:
            return False
        return self._validity.get(key, self._default_valid)
    
    def get(self, key: str) -> Any | None:
        """Get cached value."""
        return self._cache.get(key)
    
    def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Set cache value."""
        self._cache[key] = value
        self._validity[key] = True
    
    def invalidate(self, key: str) -> None:
        """Invalidate cache entry."""
        self._validity[key] = False
    
    def set_validity(self, key: str, valid: bool) -> None:
        """Manually set validity for testing."""
        self._validity[key] = valid
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._validity.clear()


# =============================================================================
# Async Test Doubles
# =============================================================================

class FakeAsyncHttpResponse:
    """Fake async HTTP response for testing.
    
    Simulates httpx.Response interface for async testing.
    """
    
    def __init__(
        self,
        status_code: int = 200,
        content: bytes = b'',
        headers: dict[str, str] | None = None,
        json_data: Any | None = None
    ) -> None:
        self._status_code = status_code
        self._content = content
        self._headers = headers or {}
        self._json_data = json_data
        
        if json_data is not None and not content:
            self._content = json.dumps(json_data).encode('utf-8')
    
    @property
    def status_code(self) -> int:
        return self._status_code
    
    @property
    def content(self) -> bytes:
        return self._content
    
    @property
    def text(self) -> str:
        return self._content.decode('utf-8')
    
    @property
    def headers(self) -> dict[str, str]:
        return self._headers
    
    def json(self) -> Any:
        if self._json_data is not None:
            return self._json_data
        return json.loads(self._content.decode('utf-8'))
    
    def raise_for_status(self) -> None:
        if self._status_code >= 400:
            raise FakeHttpError(f"HTTP {self._status_code}")


class FakeAsyncHttpClient:
    """Fake async HTTP client for testing.
    
    Provides configurable responses for async HTTP requests.
    Supports context manager protocol for async with.
    
    Example:
        client = FakeAsyncHttpClient()
        client.add_response('https://example.com/api', json_data={'key': 'value'})
        
        async with client:
            response = await client.get('https://example.com/api')
            assert response.json() == {'key': 'value'}
    """
    
    def __init__(self) -> None:
        self._responses: dict[str, FakeAsyncHttpResponse] = {}
        self._request_history: list[dict[str, Any]] = []
        self._default_response: FakeAsyncHttpResponse | None = None
    
    def add_response(
        self,
        url: str,
        *,
        status_code: int = 200,
        content: bytes = b'',
        headers: dict[str, str] | None = None,
        json_data: Any | None = None
    ) -> None:
        """Add a fake response for a specific URL."""
        self._responses[url] = FakeAsyncHttpResponse(
            status_code=status_code,
            content=content,
            headers=headers or {'content-length': str(len(content))},
            json_data=json_data
        )
    
    def set_default_response(
        self,
        status_code: int = 200,
        content: bytes = b'',
        json_data: Any | None = None
    ) -> None:
        """Set default response for unregistered URLs."""
        self._default_response = FakeAsyncHttpResponse(
            status_code=status_code,
            content=content,
            json_data=json_data
        )
    
    async def __aenter__(self) -> "FakeAsyncHttpClient":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        pass
    
    async def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
    ) -> FakeAsyncHttpResponse:
        """Perform fake async HTTP GET request."""
        self._request_history.append({
            'url': url,
            'timeout': timeout,
        })
        
        if url in self._responses:
            return self._responses[url]
        
        if self._default_response is not None:
            return self._default_response
        
        return FakeAsyncHttpResponse(status_code=404, content=b'Not Found')
    
    @property
    def request_count(self) -> int:
        """Number of requests made."""
        return len(self._request_history)
    
    @property
    def request_history(self) -> list[dict[str, Any]]:
        """List of all requests made."""
        return self._request_history.copy()
    
    def clear_history(self) -> None:
        """Clear request history."""
        self._request_history.clear()

