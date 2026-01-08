#!/usr/bin/env python3
"""
Tests for protocol implementations and test fakes.

Validates that:
1. Default implementations conform to protocols
2. Test fakes provide expected behavior
3. Protocol-based code can use either implementation
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Import protocols
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'data'))

from protocols import (
    HttpClient,
    DataReader,
    DataWriter,
    CacheManager,
    FileSystemDataReader,
    FileSystemDataWriter,
    RequestsHttpClient,
)

# Import fakes from tests directory
from tests.fakes import (
    FakeHttpClient,
    FakeHttpResponse,
    FakeDataReader,
    FakeDataWriter,
    FakeCacheManager,
)


class TestFakeHttpClient:
    """Tests for FakeHttpClient test double."""
    
    def test_returns_configured_response(self):
        """Fake client returns configured response for URL."""
        client = FakeHttpClient()
        client.add_response(
            'https://example.com/api',
            json_data={'status': 'ok'}
        )
        
        response = client.get('https://example.com/api')
        
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}
    
    def test_returns_404_for_unknown_url(self):
        """Fake client returns 404 for unconfigured URLs."""
        client = FakeHttpClient()
        
        response = client.get('https://unknown.com')
        
        assert response.status_code == 404
    
    def test_tracks_request_history(self):
        """Fake client tracks all requests made."""
        client = FakeHttpClient()
        client.set_default_response(json_data={})
        
        client.get('https://example.com/a')
        client.get('https://example.com/b', timeout=30)
        
        assert client.request_count == 2
        assert client.request_history[0]['url'] == 'https://example.com/a'
        assert client.request_history[1]['timeout'] == 30
    
    def test_raise_for_status_on_error(self):
        """Fake response raises on error status codes."""
        client = FakeHttpClient()
        client.add_response('https://example.com/error', status_code=500)
        
        response = client.get('https://example.com/error')
        
        with pytest.raises(Exception):
            response.raise_for_status()
    
    def test_iter_content_yields_chunks(self):
        """Fake response yields content in chunks."""
        client = FakeHttpClient()
        client.add_response(
            'https://example.com/data',
            content=b'Hello World'
        )
        
        response = client.get('https://example.com/data')
        chunks = list(response.iter_content(chunk_size=5))
        
        assert chunks == [b'Hello', b' Worl', b'd']


class TestFakeDataReader:
    """Tests for FakeDataReader test double."""
    
    def test_reads_json_file(self):
        """Fake reader returns configured JSON data."""
        reader = FakeDataReader()
        reader.add_json(Path('/data/config.json'), {'debug': True})
        
        data = reader.read_json(Path('/data/config.json'))
        
        assert data == {'debug': True}
    
    def test_reads_text_file(self):
        """Fake reader returns configured text content."""
        reader = FakeDataReader()
        reader.add_file(Path('/data/readme.txt'), 'Hello World')
        
        content = reader.read_text(Path('/data/readme.txt'))
        
        assert content == 'Hello World'
    
    def test_reads_binary_file(self):
        """Fake reader returns configured binary content."""
        reader = FakeDataReader()
        reader.add_file(Path('/data/image.png'), b'\x89PNG')
        
        content = reader.read_bytes(Path('/data/image.png'))
        
        assert content == b'\x89PNG'
    
    def test_exists_returns_true_for_added_files(self):
        """Fake reader reports existence correctly."""
        reader = FakeDataReader()
        reader.add_file(Path('/exists.txt'), 'content')
        
        assert reader.exists(Path('/exists.txt')) is True
        assert reader.exists(Path('/missing.txt')) is False
    
    def test_raises_on_missing_file(self):
        """Fake reader raises FileNotFoundError for missing files."""
        reader = FakeDataReader()
        
        with pytest.raises(FileNotFoundError):
            reader.read_json(Path('/missing.json'))
    
    def test_list_dir_returns_children(self):
        """Fake reader lists directory contents."""
        reader = FakeDataReader()
        reader.add_directory(Path('/data'), ['a.json', 'b.json', 'c.txt'])
        
        contents = reader.list_dir(Path('/data'))
        names = [p.name for p in contents]
        
        assert sorted(names) == ['a.json', 'b.json', 'c.txt']


class TestFakeDataWriter:
    """Tests for FakeDataWriter test double."""
    
    def test_captures_json_writes(self):
        """Fake writer captures JSON writes for assertions."""
        writer = FakeDataWriter()
        
        writer.write_json(Path('/output.json'), {'result': 42})
        
        assert writer.get_json(Path('/output.json')) == {'result': 42}
        assert writer.was_written(Path('/output.json')) is True
    
    def test_captures_text_writes(self):
        """Fake writer captures text writes for assertions."""
        writer = FakeDataWriter()
        
        writer.write_text(Path('/output.txt'), 'Hello World')
        
        assert writer.get_text(Path('/output.txt')) == 'Hello World'
    
    def test_captures_binary_writes(self):
        """Fake writer captures binary writes for assertions."""
        writer = FakeDataWriter()
        
        writer.write_bytes(Path('/output.bin'), b'\x00\x01\x02')
        
        assert writer.get_bytes(Path('/output.bin')) == b'\x00\x01\x02'
    
    def test_tracks_directory_creation(self):
        """Fake writer tracks directory creation."""
        writer = FakeDataWriter()
        
        writer.mkdir(Path('/new/dir'))
        
        assert writer.was_directory_created(Path('/new/dir')) is True
        assert writer.was_directory_created(Path('/other')) is False
    
    def test_lists_written_files(self):
        """Fake writer lists all written files."""
        writer = FakeDataWriter()
        writer.write_text(Path('/a.txt'), 'a')
        writer.write_text(Path('/b.txt'), 'b')
        
        assert len(writer.written_files) == 2


class TestFakeCacheManager:
    """Tests for FakeCacheManager test double."""
    
    def test_stores_and_retrieves_values(self):
        """Fake cache stores and retrieves values."""
        cache = FakeCacheManager()
        
        cache.set('key', {'data': 'value'})
        
        assert cache.get('key') == {'data': 'value'}
        assert cache.is_valid('key') is True
    
    def test_returns_none_for_missing_keys(self):
        """Fake cache returns None for missing keys."""
        cache = FakeCacheManager()
        
        assert cache.get('missing') is None
        assert cache.is_valid('missing') is False
    
    def test_invalidation_works(self):
        """Fake cache invalidation works."""
        cache = FakeCacheManager()
        cache.set('key', 'value')
        
        cache.invalidate('key')
        
        assert cache.is_valid('key') is False
        assert cache.get('key') == 'value'  # Data still there, just invalid
    
    def test_manual_validity_control(self):
        """Fake cache allows manual validity control for testing."""
        cache = FakeCacheManager()
        cache.set('key', 'value')
        
        cache.set_validity('key', False)
        
        assert cache.is_valid('key') is False


class TestProtocolConformance:
    """Tests that implementations conform to protocols."""
    
    def test_fake_http_client_is_http_client(self):
        """FakeHttpClient conforms to HttpClient protocol."""
        client = FakeHttpClient()
        assert isinstance(client, HttpClient)
    
    def test_fake_data_reader_is_data_reader(self):
        """FakeDataReader conforms to DataReader protocol."""
        reader = FakeDataReader()
        assert isinstance(reader, DataReader)
    
    def test_fake_data_writer_is_data_writer(self):
        """FakeDataWriter conforms to DataWriter protocol."""
        writer = FakeDataWriter()
        assert isinstance(writer, DataWriter)
    
    def test_fake_cache_manager_is_cache_manager(self):
        """FakeCacheManager conforms to CacheManager protocol."""
        cache = FakeCacheManager()
        assert isinstance(cache, CacheManager)
    
    def test_filesystem_reader_is_data_reader(self):
        """FileSystemDataReader conforms to DataReader protocol."""
        reader = FileSystemDataReader()
        assert isinstance(reader, DataReader)
    
    def test_filesystem_writer_is_data_writer(self):
        """FileSystemDataWriter conforms to DataWriter protocol."""
        writer = FileSystemDataWriter()
        assert isinstance(writer, DataWriter)


class TestFileSystemIntegration:
    """Integration tests for FileSystem implementations with real files."""
    
    def test_reader_reads_real_json(self, tmp_path):
        """FileSystemDataReader reads actual JSON files."""
        test_file = tmp_path / 'test.json'
        test_file.write_text('{"key": "value"}')
        
        reader = FileSystemDataReader()
        data = reader.read_json(test_file)
        
        assert data == {'key': 'value'}
    
    def test_writer_writes_real_json(self, tmp_path):
        """FileSystemDataWriter writes actual JSON files."""
        test_file = tmp_path / 'output.json'
        
        writer = FileSystemDataWriter()
        writer.write_json(test_file, {'result': 42})
        
        # Verify with reader
        reader = FileSystemDataReader()
        assert reader.read_json(test_file) == {'result': 42}
    
    def test_reader_exists_check(self, tmp_path):
        """FileSystemDataReader checks file existence correctly."""
        existing = tmp_path / 'exists.txt'
        existing.write_text('content')
        
        reader = FileSystemDataReader()
        
        assert reader.exists(existing) is True
        assert reader.exists(tmp_path / 'missing.txt') is False
    
    def test_writer_creates_directories(self, tmp_path):
        """FileSystemDataWriter creates directories."""
        new_dir = tmp_path / 'new' / 'nested' / 'dir'
        
        writer = FileSystemDataWriter()
        writer.mkdir(new_dir)
        
        assert new_dir.exists()
        assert new_dir.is_dir()
