"""Tests for Request Parser."""

import pytest
from app.request_processing.parser import RequestParser, HTTPRequest


class TestRequestParser:
    """Test the request parser."""

    def setup_method(self):
        self.parser = RequestParser()

    def test_parse_basic_get(self):
        """Test parsing a basic GET request."""
        request = self.parser.parse(
            method="GET",
            path="/search",
            headers={"user-agent": "Test/1.0"},
            query_string="q=laptop",
        )

        assert request.method == "GET"
        assert request.path == "/search"
        assert request.query_string == "q=laptop"
        assert request.url_length > 0

    def test_parse_post_with_body(self):
        """Test parsing a POST request with form body."""
        body = b"username=admin&password=test123"
        request = self.parser.parse(
            method="POST",
            path="/login",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "user-agent": "Test/1.0",
            },
            body=body,
        )

        assert request.method == "POST"
        assert request.body_size == len(body)
        assert "username" in request.body_fields
        assert "password" in request.body_fields

    def test_parse_json_body(self):
        """Test parsing a POST request with JSON body."""
        import json
        body = json.dumps({"username": "admin", "password": "secret"}).encode()
        request = self.parser.parse(
            method="POST",
            path="/api/data",
            headers={
                "content-type": "application/json",
                "user-agent": "Test/1.0",
            },
            body=body,
        )

        assert request.body_size == len(body)
        assert "username" in request.body_fields
        assert "password" in request.body_fields

    def test_request_id_generated(self):
        """Test that request IDs are generated."""
        request = self.parser.parse(
            method="GET", path="/", headers={}, source_id="TEST"
        )
        assert request.request_id.startswith("REQ-")

    def test_empty_request(self):
        """Test parsing minimal request."""
        request = self.parser.parse(
            method="GET",
            path="/",
            headers={},
        )

        assert request.method == "GET"
        assert request.path == "/"
        assert request.body_size == 0
        assert len(request.body_fields) == 0

    def test_query_string_parsing(self):
        """Test query string is preserved."""
        request = self.parser.parse(
            method="GET",
            path="/search",
            headers={},
            query_string="q=test&page=1&limit=10",
        )

        assert "q=test" in request.query_string
        assert "page=1" in request.query_string


class TestHTTPRequestModel:
    """Test the HTTPRequest model."""

    def test_compute_lengths(self):
        """Test length computation."""
        request = HTTPRequest(
            path="/search",
            query_string="q=laptop&page=1",
        )
        request.compute_lengths()

        assert request.path_length == len("/search")
        assert request.query_length == len("q=laptop&page=1")
        assert request.url_length == request.path_length + request.query_length

    def test_default_values(self):
        """Test default values."""
        request = HTTPRequest()
        assert request.method == "GET"
        assert request.path == "/"
        assert request.body_size == 0
