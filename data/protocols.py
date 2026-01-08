#!/usr/bin/env python3
"""
Protocol definitions for CVE.ICU

Defines abstract interfaces using typing.Protocol for dependency injection
and testability. These protocols enable mocking external dependencies like
HTTP requests and file system operations in unit tests.

Python 3.8+ Protocol classes provide structural subtyping - any class that
implements the required methods is considered a valid implementation without
explicit inheritance.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HttpClient(Protocol):
    """Protocol for HTTP client operations.
    
    Abstracts HTTP GET requests to enable mocking in tests.
    Real implementation: requests.Session or httpx.Client
    Test implementation: FakeHttpClient with predefined responses
    """
    
    def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
        stream: bool = False
    ) -> HttpResponse:
        """Perform HTTP GET request.
        
        Args:
            url: The URL to fetch
            timeout: Request timeout in seconds
            stream: Whether to stream the response
            
        Returns:
            HttpResponse object with status_code, content, headers
        """
        ...


@runtime_checkable
class HttpResponse(Protocol):
    """Protocol for HTTP response objects.
    
    Matches the interface of requests.Response for compatibility.
    """
    
    @property
    def status_code(self) -> int:
        """HTTP status code (e.g., 200, 404, 500)"""
        ...
    
    @property
    def content(self) -> bytes:
        """Raw response content as bytes"""
        ...
    
    @property
    def text(self) -> str:
        """Response content decoded as text"""
        ...
    
    @property
    def headers(self) -> dict[str, str]:
        """Response headers"""
        ...
    
    def json(self) -> Any:
        """Parse response as JSON"""
        ...
    
    def raise_for_status(self) -> None:
        """Raise exception if status code indicates error"""
        ...
    
    def iter_content(self, chunk_size: int = 1) -> Any:
        """Iterate over response content in chunks"""
        ...


@runtime_checkable
class DataReader(Protocol):
    """Protocol for reading data from various sources.
    
    Abstracts file and data reading to enable testing without
    actual file system access.
    """
    
    def read_json(self, path: Path) -> Any:
        """Read and parse JSON from file.
        
        Args:
            path: Path to JSON file
            
        Returns:
            Parsed JSON data (dict, list, etc.)
        """
        ...
    
    def read_text(self, path: Path) -> str:
        """Read text content from file.
        
        Args:
            path: Path to text file
            
        Returns:
            File contents as string
        """
        ...
    
    def read_bytes(self, path: Path) -> bytes:
        """Read binary content from file.
        
        Args:
            path: Path to binary file
            
        Returns:
            File contents as bytes
        """
        ...
    
    def exists(self, path: Path) -> bool:
        """Check if path exists.
        
        Args:
            path: Path to check
            
        Returns:
            True if path exists, False otherwise
        """
        ...
    
    def list_dir(self, path: Path) -> list[Path]:
        """List directory contents.
        
        Args:
            path: Directory path
            
        Returns:
            List of paths in directory
        """
        ...


@runtime_checkable
class DataWriter(Protocol):
    """Protocol for writing data to various destinations.
    
    Abstracts file writing to enable testing without
    actual file system modifications.
    """
    
    def write_json(self, path: Path, data: Any, indent: int = 2) -> None:
        """Write data as JSON to file.
        
        Args:
            path: Path to write to
            data: Data to serialize as JSON
            indent: JSON indentation level
        """
        ...
    
    def write_text(self, path: Path, content: str) -> None:
        """Write text content to file.
        
        Args:
            path: Path to write to
            content: Text content to write
        """
        ...
    
    def write_bytes(self, path: Path, content: bytes) -> None:
        """Write binary content to file.
        
        Args:
            path: Path to write to
            content: Binary content to write
        """
        ...
    
    def mkdir(self, path: Path, parents: bool = True, exist_ok: bool = True) -> None:
        """Create directory.
        
        Args:
            path: Directory path to create
            parents: Create parent directories if needed
            exist_ok: Don't raise error if directory exists
        """
        ...


@runtime_checkable
class CacheManager(Protocol):
    """Protocol for cache management operations.
    
    Abstracts caching logic for data downloads and processing results.
    """
    
    def is_valid(self, key: str) -> bool:
        """Check if cache entry is valid and not expired.
        
        Args:
            key: Cache key to check
            
        Returns:
            True if cache is valid, False if expired or missing
        """
        ...
    
    def get(self, key: str) -> Any | None:
        """Get cached value.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        ...
    
    def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Set cache value.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Time-to-live in seconds (None for default)
        """
        ...
    
    def invalidate(self, key: str) -> None:
        """Invalidate cache entry.
        
        Args:
            key: Cache key to invalidate
        """
        ...


# =============================================================================
# Default implementations for production use
# =============================================================================

class FileSystemDataReader:
    """Default DataReader implementation using the file system."""
    
    def read_json(self, path: Path) -> Any:
        """Read and parse JSON from file."""
        import json
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def read_text(self, path: Path) -> str:
        """Read text content from file."""
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def read_bytes(self, path: Path) -> bytes:
        """Read binary content from file."""
        with open(path, 'rb') as f:
            return f.read()
    
    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        return path.exists()
    
    def list_dir(self, path: Path) -> list[Path]:
        """List directory contents."""
        return list(path.iterdir()) if path.is_dir() else []


class FileSystemDataWriter:
    """Default DataWriter implementation using the file system."""
    
    def write_json(self, path: Path, data: Any, indent: int = 2) -> None:
        """Write data as JSON to file."""
        import json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent)
    
    def write_text(self, path: Path, content: str) -> None:
        """Write text content to file."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def write_bytes(self, path: Path, content: bytes) -> None:
        """Write binary content to file."""
        with open(path, 'wb') as f:
            f.write(content)
    
    def mkdir(self, path: Path, parents: bool = True, exist_ok: bool = True) -> None:
        """Create directory."""
        path.mkdir(parents=parents, exist_ok=exist_ok)


class RequestsHttpClient:
    """Default HttpClient implementation using requests library."""
    
    def __init__(self, session: Any | None = None) -> None:
        """Initialize with optional requests.Session."""
        import requests
        self._session = session or requests.Session()
    
    def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
        stream: bool = False
    ) -> Any:
        """Perform HTTP GET request."""
        return self._session.get(url, timeout=timeout, stream=stream)


# =============================================================================
# Async Protocol and Implementation for Parallel Downloads
# =============================================================================

@runtime_checkable
class AsyncHttpClient(Protocol):
    """Protocol for async HTTP client operations.
    
    Enables parallel HTTP requests using asyncio.
    Real implementation: httpx.AsyncClient
    Test implementation: FakeAsyncHttpClient
    """
    
    async def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
    ) -> HttpResponse:
        """Perform async HTTP GET request.
        
        Args:
            url: The URL to fetch
            timeout: Request timeout in seconds
            
        Returns:
            HttpResponse object with status_code, content, headers
        """
        ...
    
    async def __aenter__(self) -> "AsyncHttpClient":
        """Async context manager entry."""
        ...
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        ...


class HttpxAsyncClient:
    """Async HTTP client implementation using httpx library.
    
    Supports parallel downloads via asyncio.gather().
    
    Example:
        async with HttpxAsyncClient() as client:
            responses = await asyncio.gather(
                client.get('https://api1.example.com'),
                client.get('https://api2.example.com'),
            )
    """
    
    def __init__(self, timeout: int = 120) -> None:
        """Initialize with default timeout."""
        self._timeout = timeout
        self._client: Any = None
    
    async def __aenter__(self) -> "HttpxAsyncClient":
        """Create httpx.AsyncClient on context entry."""
        import httpx
        self._client = httpx.AsyncClient(timeout=self._timeout)
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close httpx.AsyncClient on context exit."""
        if self._client:
            await self._client.aclose()
    
    async def get(
        self,
        url: str,
        *,
        timeout: int | None = None,
    ) -> Any:
        """Perform async HTTP GET request."""
        if self._client is None:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        return await self._client.get(url, timeout=timeout or self._timeout)

