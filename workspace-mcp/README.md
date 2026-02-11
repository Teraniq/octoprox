# Octoprox - OpenAPI-to-MCP Adapter

Octoprox is an OpenAPI-to-MCP (Model Context Protocol) adapter that enables LLMs to interact with REST APIs through a standardized interface. It runs as an MCP server within workspace containers, providing a rich set of tools for filesystem operations, Git integration, API consumption, and more.

## Overview

Octoprox bridges the gap between LLMs and external APIs by:

- **Loading OpenAPI specifications** dynamically from URLs or inline content
- **Discovering endpoints** through intelligent filtering and pagination
- **Resolving $ref pointers** for complete schema understanding
- **Executing API calls** with proper parameter substitution and authentication
- **Providing filesystem and Git tools** for workspace management

## Features

- 🔌 **Generic OpenAPI Adapter** - Connect to any REST API with an OpenAPI spec
- 🦊 **GitLab Integration** - Built-in GitLab API tools with spec caching
- 📁 **Filesystem Tools** - Secure file read/write/list operations within workspace bounds
- 🔧 **Git Tools** - Whitelisted git commands for version control
- 🔐 **Secure by Design** - Path traversal protection, command injection prevention, SSRF protection
- 🚀 **MCP Compliant** - Full Model Context Protocol implementation

## Quick Start

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run the MCP server
python -m octoprox
```

### Running with Docker

```bash
# Build the image
docker build -t octoprox .

# Run with environment variables
docker run -p 7000:7000 \
  -e WORKSPACE_OWNER_USER_ID=123 \
  -e MANAGER_INTROSPECT_URL=http://manager:8000/api/v1/auth/introspect \
  octoprox
```

### Using docker-compose

```yaml
services:
  mcp-server:
    build:
      context: ./workspace-mcp
      args:
        INSTALL_PLAYWRIGHT: "true"
    environment:
      - WORKSPACE_OWNER_USER_ID=${WORKSPACE_OWNER_USER_ID}
      - MANAGER_INTROSPECT_URL=http://workspace-manager:8000/api/v1/auth/introspect
      - MCP_PORT=7000
    volumes:
      - workspace-data:/workspace
```

## Tool Inventory

Octoprox provides the following tools organized by capability:

| Tool | Description | Capability | File |
|------|-------------|------------|------|
| `fs_list` | List files and directories at a path | Filesystem | filesystem.py |
| `fs_read_text` | Read text content from a file | Filesystem | filesystem.py |
| `fs_write_text` | Write text content to a file | Filesystem | filesystem.py |
| `fs_delete` | Delete a file or directory | Filesystem | filesystem.py |
| `git` | Execute whitelisted git commands | Git | git.py |
| `gitlab_request` | Proxy GitLab REST API requests | GitLab | gitlab.py |
| `gitlab_openapi_spec` | Return GitLab OpenAPI YAML spec | GitLab | gitlab.py |
| `gitlab_openapi_paths` | List GitLab OpenAPI paths and methods | GitLab | gitlab.py |
| `gitlab_openapi_operation` | Get schema details for path+method | GitLab | gitlab.py |
| `gitlab_tool_help` | Return help for GitLab MCP tools | GitLab | gitlab.py |
| `ssh_public_key` | Get the SSH public key for this workspace | SSH | ssh.py |
| `openapi_load` | Load an OpenAPI specification | OpenAPI Adapter | openapi.py |
| `openapi_list_apis` | List all loaded APIs | OpenAPI Adapter | openapi.py |
| `openapi_list_endpoints` | List endpoints with filtering | OpenAPI Adapter | openapi.py |
| `openapi_get_operation` | Get detailed operation information | OpenAPI Adapter | openapi.py |
| `openapi_call` | Call an API operation | OpenAPI Adapter | openapi.py |

## Feature Flags

All features can be controlled via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOPROX_ENABLE_OPENAPI` | `true` | Enable OpenAPI adapter tools |
| `OCTOPROX_ENABLE_GITLAB` | `true` | Enable GitLab integration tools |
| `OCTOPROX_ENABLE_FETCH` | `true` | Enable HTTP fetch tools |
| `OCTOPROX_ENABLE_BROWSER` | `false` | Enable headless browser automation |
| `OCTOPROX_ENABLE_READABILITY` | `true` | Enable HTML-to-markdown conversion |
| `OCTOPROX_ENABLE_SEARCH` | `true` | Enable web search capabilities |
| `OCTOPROX_ENABLE_SHELL` | `false` | Enable shell command execution |
| `OCTOPROX_ENABLE_DATABASE` | `false` | Enable database query tools |
| `OCTOPROX_ENABLE_MEMORY` | `true` | Enable memory/knowledge tools |
| `OCTOPROX_ENABLE_TIME` | `true` | Enable time/date utilities |

> **Note:** Some features require additional dependencies or configuration. See [DOCKER.md](docs/DOCKER.md) for details.

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `WORKSPACE_OWNER_USER_ID` | User ID of the workspace owner for authorization |
| `MANAGER_INTROSPECT_URL` | URL for token introspection endpoint |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_PORT` | `7000` | Port to bind the MCP server |
| `MCP_BIND_HOST` | `0.0.0.0` | Host to bind the MCP server |
| `GITLAB_BASE_URL` | `https://gitlab.com` | GitLab instance URL |
| `GITLAB_TOKEN` | - | GitLab personal access token |
| `ENABLE_OPENAPI` | `true` | Enable/disable OpenAPI adapter |

## Usage Examples

### Loading an OpenAPI Spec

```python
# Load from URL
result = await openapi_load(
    name="petstore",
    spec_url="https://petstore.swagger.io/v2/swagger.json"
)
# Returns: {"name": "petstore", "title": "Swagger Petstore", "version": "1.0.0", "endpoint_count": 20}

# Load from inline content
result = await openapi_load(
    name="myapi",
    spec_content="""
    openapi: 3.0.0
    info:
      title: My API
      version: 1.0.0
    paths:
      /users:
        get:
          summary: List users
    """
)
```

### Listing Endpoints

```python
# List all endpoints
endpoints = await openapi_list_endpoints(name="petstore")

# Filter by path substring
endpoints = await openapi_list_endpoints(
    name="petstore",
    filter="pet",
    limit=10
)

# Filter by tag
endpoints = await openapi_list_endpoints(
    name="petstore",
    tag="store",
    limit=20,
    offset=0
)
```

### Calling an API Operation

```python
# Call with path parameters
result = await openapi_call(
    name="petstore",
    path="/pet/{petId}",
    method="GET",
    path_params={"petId": 123}
)

# Call with query parameters
result = await openapi_call(
    name="petstore",
    path="/pet/findByStatus",
    method="GET",
    query_params={"status": "available"}
)

# Call with request body
result = await openapi_call(
    name="petstore",
    path="/pet",
    method="POST",
    body={
        "name": "Fluffy",
        "status": "available"
    }
)
```

### Using Filesystem Tools

```python
# List directory contents
files = await fs_list(path="src")

# Read a file
content = await fs_read_text(path="README.md", max_bytes=50000)

# Write a file
result = await fs_write_text(
    path="output.txt",
    text="Hello, World!",
    mkdirs=True
)

# Delete a file
result = await fs_delete(path="temp.txt", recursive=False)
```

### Using Git Tools

```python
# Check repository status
result = await git(args=["status", "--short", "--branch"])

# View commit history
result = await git(args=["log", "--oneline", "--max-count=10"])

# Clone a repository
result = await git(args=[
    "clone",
    "--depth=1",
    "https://github.com/example/repo.git",
    "./repo"
])

# Stage and commit changes
result = await git(args=["add", "-A"])
result = await git(args=["commit", "-m", "Update files"])
```

### Using GitLab Tools

```python
# List GitLab endpoints
endpoints = await gitlab_openapi_paths(filter_text="issues", limit=20)

# Get operation details
operation = await gitlab_openapi_operation(
    path="/projects/{id}/issues",
    method="GET"
)

# Make a GitLab API request
result = await gitlab_request(
    endpoint="https://gitlab.com/api/v4",
    token="your-gitlab-token",
    path="/projects/123/issues",
    method="GET",
    params={"state": "opened"}
)
```

## Authentication

Octoprox uses OAuth2 token introspection for authentication:

1. Client presents a Bearer token in the Authorization header
2. Token is validated against the workspace-manager introspection endpoint
3. User ID from token is compared to `WORKSPACE_OWNER_USER_ID`
4. If mismatch, request is rejected with 403 Forbidden

See [SECURITY.md](docs/SECURITY.md) for detailed security information.

## Documentation

- [Tools Reference](docs/TOOLS.md) - Complete documentation for all 16 tools
- [Security Guide](docs/SECURITY.md) - Security measures and best practices
- [Docker Guide](docs/DOCKER.md) - Container deployment and configuration

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   Octoprox MCP   │────▶│   Target APIs   │
│  (LLM/Agent)    │     │    Server        │     │  (OpenAPI/Swagger)│
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Workspace FS    │
                        │  Git Repository  │
                        └──────────────────┘
```

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
