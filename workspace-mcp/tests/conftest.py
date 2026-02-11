"""Shared pytest fixtures for workspace-mcp tests."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Authentication Fixtures
# =============================================================================


@pytest.fixture
def mock_auth() -> Generator[MagicMock, None, None]:
    """Mock authentication for tools that require owner access."""
    with patch("octoprox.tools.openapi._require_owner") as mock:
        mock.return_value = None
        yield mock


@pytest.fixture
def mock_introspect_url() -> Generator[str, None, None]:
    """Set a mock introspect URL for testing."""
    original_url = os.environ.get("MANAGER_INTROSPECT_URL", "")
    os.environ["MANAGER_INTROSPECT_URL"] = "http://localhost:8000/internal/auth/introspect"
    yield os.environ["MANAGER_INTROSPECT_URL"]
    os.environ["MANAGER_INTROSPECT_URL"] = original_url


# =============================================================================
# Workspace Fixtures
# =============================================================================


@pytest.fixture
def workspace_root(tmp_path: Path) -> Path:
    """Create a temporary workspace root directory."""
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    return workspace_dir


# =============================================================================
# HTTP Client Fixtures
# =============================================================================


@pytest.fixture
def mock_httpx_client() -> Generator[MagicMock, None, None]:
    """Mock httpx client for external HTTP calls."""
    with patch("httpx.get") as mock_get, \
         patch("httpx.request") as mock_request, \
         patch("httpx.AsyncClient") as mock_async_client:
        
        # Setup mock response for sync get
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {}
        mock_response.text = "{}"
        mock_response.content = b"{}"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        # Setup mock for sync request
        mock_request_response = MagicMock()
        mock_request_response.status_code = 200
        mock_request_response.headers = {"content-type": "application/json"}
        mock_request_response.json.return_value = {}
        mock_request_response.text = "{}"
        mock_request_response.content = b"{}"
        mock_request.return_value = mock_request_response
        
        # Setup mock for async client
        async_mock = AsyncMock()
        async_mock.post = AsyncMock()
        async_mock.aclose = AsyncMock()
        mock_async_client.return_value = async_mock
        
        yield {
            "get": mock_get,
            "request": mock_request,
            "async_client": mock_async_client,
            "response": mock_response,
            "request_response": mock_request_response,
        }


# =============================================================================
# Subprocess Fixtures
# =============================================================================


@pytest.fixture
def mock_subprocess() -> Generator[MagicMock, None, None]:
    """Mock subprocess for git/shell commands."""
    with patch("subprocess.run") as mock_run, \
         patch("subprocess.check_output") as mock_check_output, \
         patch("asyncio.create_subprocess_exec") as mock_async_subprocess:
        
        # Setup mock for sync run
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "mock output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        # Setup mock for check_output
        mock_check_output.return_value = b"mock output"
        
        # Setup mock for async subprocess
        async_process = AsyncMock()
        async_process.wait = AsyncMock(return_value=0)
        async_process.communicate = AsyncMock(return_value=(b"stdout", b"stderr"))
        async_process.returncode = 0
        mock_async_subprocess.return_value = async_process
        
        yield {
            "run": mock_run,
            "check_output": mock_check_output,
            "async_subprocess": mock_async_subprocess,
            "result": mock_result,
            "async_process": async_process,
        }


# =============================================================================
# MCP App Fixtures
# =============================================================================


@pytest.fixture
def mcp_app() -> Generator[Any, None, None]:
    """MCP app fixture for testing."""
    from octoprox import OctoproxMCP
    
    app = OctoproxMCP("test-octoprox")
    yield app


# =============================================================================
# Sample OpenAPI Spec Fixtures
# =============================================================================


@pytest.fixture
def sample_openapi_spec() -> dict[str, Any]:
    """Return a sample OpenAPI 3.0 specification."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "A test API for testing",
        },
        "servers": [
            {"url": "https://api.example.com/v1"}
        ],
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "listPets",
                    "summary": "List all pets",
                    "tags": ["pets"],
                    "parameters": [
                        {"$ref": "#/components/parameters/LimitParam"}
                    ],
                    "responses": {
                        "200": {"$ref": "#/components/responses/PetsResponse"}
                    }
                },
                "post": {
                    "operationId": "createPet",
                    "summary": "Create a new pet",
                    "tags": ["pets"],
                    "requestBody": {"$ref": "#/components/requestBodies/PetInput"},
                    "responses": {
                        "201": {"$ref": "#/components/responses/PetResponse"}
                    }
                }
            },
            "/pets/{petId}": {
                "get": {
                    "operationId": "getPet",
                    "summary": "Get a pet by ID",
                    "tags": ["pets"],
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"$ref": "#/components/responses/PetResponse"}
                    }
                }
            },
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "summary": "List all users",
                    "tags": ["users"],
                    "responses": {
                        "200": {"description": "List of users"}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Pet": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "status": {"type": "string"}
                    }
                },
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "username": {"type": "string"}
                    }
                }
            },
            "parameters": {
                "LimitParam": {
                    "name": "limit",
                    "in": "query",
                    "schema": {"type": "integer", "default": 20}
                }
            },
            "requestBodies": {
                "PetInput": {
                    "description": "Pet to create",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Pet"}
                        }
                    }
                }
            },
            "responses": {
                "PetResponse": {
                    "description": "A pet",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Pet"}
                        }
                    }
                },
                "PetsResponse": {
                    "description": "List of pets",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/Pet"}
                            }
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def sample_swagger_spec() -> dict[str, Any]:
    """Return a sample Swagger 2.0 specification."""
    return {
        "swagger": "2.0",
        "info": {
            "title": "Test Swagger API",
            "version": "1.0.0"
        },
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/items": {
                "get": {
                    "operationId": "listItems",
                    "summary": "List all items",
                    "responses": {
                        "200": {"description": "List of items"}
                    }
                }
            }
        }
    }


@pytest.fixture
def sample_yaml_spec() -> str:
    """Return a sample OpenAPI spec in YAML format."""
    return """
openapi: "3.0.0"
info:
  title: YAML Test API
  version: "1.0.0"
servers:
  - url: https://yaml.example.com/v1
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        "200":
          description: OK
"""


@pytest.fixture
def sample_json_spec() -> str:
    """Return a sample OpenAPI spec in JSON format."""
    import json
    return json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "JSON Test API", "version": "1.0.0"},
        "servers": [{"url": "https://json.example.com/v1"}],
        "paths": {
            "/test": {
                "get": {
                    "summary": "Test endpoint",
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    })


# =============================================================================
# Environment Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def clean_environment() -> Generator[None, None, None]:
    """Clean up environment variables after each test."""
    # Store original env vars
    original_env = {
        "ENABLE_OPENAPI": os.environ.get("ENABLE_OPENAPI"),
        "WORKSPACE_OWNER_USER_ID": os.environ.get("WORKSPACE_OWNER_USER_ID"),
        "MANAGER_INTROSPECT_URL": os.environ.get("MANAGER_INTROSPECT_URL"),
    }
    
    yield
    
    # Restore original env vars
    for key, value in original_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture
def clean_loaded_apis() -> Generator[None, None, None]:
    """Clean up loaded APIs after each test."""
    yield
    # Clear loaded APIs after test
    from octoprox.tools.openapi import _loaded_apis
    _loaded_apis.clear()
