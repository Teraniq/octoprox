# Tools Reference

Complete reference for all Octoprox MCP tools organized by capability category.

## Table of Contents

- [Filesystem](#filesystem)
- [Git](#git)
- [SSH](#ssh)
- [GitLab](#gitlab)
- [OpenAPI Adapter](#openapi-adapter)

---

## Filesystem

Tools for secure file operations within the workspace root (`/workspace`).

### fs_list

**Description:** List files and directories at the given path.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | str | No | "." | Path relative to workspace root |

**Returns:**

```json
["file1.txt", "file2.py", "directory1"]
```

Returns an empty list if the path does not exist.

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# List root directory
files = await fs_list()

# List specific directory
files = await fs_list(path="src/components")
```

**Errors:**
- `ValueError` - Path escapes workspace root (path traversal attempt)
- `ValueError` - Path contains null bytes or control characters
- `ValueError` - Path exceeds 4096 characters

---

### fs_read_text

**Description:** Read text content from a file.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | str | Yes | - | Path to file relative to workspace root |
| max_bytes | int | No | 200000 | Maximum bytes to read |

**Returns:**

```json
"File contents as string..."
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Read entire file (up to default max)
content = await fs_read_text(path="README.md")

# Read with custom limit
content = await fs_read_text(path="large.log", max_bytes=10000)
```

**Errors:**
- `FileNotFoundError` - File does not exist
- `ValueError` - Path validation errors

---

### fs_write_text

**Description:** Write text content to a file atomically.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | str | Yes | - | Path to file relative to workspace root |
| text | str | Yes | - | Content to write |
| mkdirs | bool | No | True | Create parent directories if needed |

**Returns:**

```json
"ok"
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False |
| destructiveHint | True |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Write to existing directory
result = await fs_write_text(
    path="output.txt",
    text="Hello, World!"
)

# Write with automatic directory creation
result = await fs_write_text(
    path="docs/guide.md",
    text="# Guide\n\nContent here...",
    mkdirs=True
)
```

**Notes:**
- Uses atomic write via temporary file to prevent corruption
- Automatically creates parent directories when `mkdirs=True`

---

### fs_delete

**Description:** Delete a file or directory.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | str | Yes | - | Path to delete |
| recursive | bool | No | False | Recursively delete directories |

**Returns:**

```json
"ok"
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False |
| destructiveHint | True |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Delete a file
result = await fs_delete(path="temp.txt")

# Delete a directory recursively
result = await fs_delete(path="build", recursive=True)
```

**Errors:**
- `IsADirectoryError` - Attempting to delete directory without `recursive=True`
- `ValueError` - Path validation errors

---

## Git

Tools for version control operations within the workspace.

### git

**Description:** Execute whitelisted git commands within the workspace.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| args | list[str] | Yes | - | Git command and arguments |
| timeout_s | int | No | 120 | Command timeout in seconds (1-300) |

**Returns:**

```json
{
  "returncode": 0,
  "stdout": "On branch main\nYour branch is up to date...",
  "stderr": ""
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False (varies by command) |
| destructiveHint | True (for modifying commands) |
| idempotentHint | False (varies by command) |
| openWorldHint | False |

**Example:**

```python
# Check status
result = await git(args=["status", "--short", "--branch"])

# View log
result = await git(args=["log", "--oneline", "--max-count=5"])

# Clone repository
result = await git(args=[
    "clone",
    "--depth=1",
    "https://github.com/user/repo.git",
    "./myrepo"
])

# Stage and commit
result = await git(args=["add", "-A"])
result = await git(args=["commit", "-m", "Initial commit"])
```

**Whitelisted Commands:**

| Command | Description | Max Args | Key Allowed Prefixes |
|---------|-------------|----------|---------------------|
| `clone` | Clone repository | 10 | `--depth=`, `--branch=`, `--single-branch` |
| `pull` | Pull changes | 5 | `--ff-only`, `--rebase`, `--autostash` |
| `fetch` | Fetch refs | 10 | `--all`, `--prune`, `--depth=` |
| `status` | Working tree status | 5 | `--short`, `--branch`, `--porcelain` |
| `log` | Commit history | 10 | `--oneline`, `--max-count=`, `--since=` |
| `diff` | Show changes | 10 | `--cached`, `--stat`, `--name-only` |
| `show` | Show objects | 5 | `--stat`, `--format=`, `--quiet` |
| `branch` | Branch operations | 10 | `--list`, `--all`, `-d`, `-m` |
| `checkout` | Switch branches | 5 | `-b`, `-B`, `--track`, `--ours` |
| `add` | Stage files | 50 | `-A`, `--all`, `-u`, `-f` |
| `reset` | Reset state | 5 | `--soft`, `--mixed`, `--hard` |
| `commit` | Record changes | 10 | `-m`, `--amend`, `--all`, `--signoff` |
| `push` | Push commits | 10 | `--all`, `--force`, `--force-with-lease` |
| `remote` | Remote management | 10 | `-v`, `add`, `remove`, `set-url` |
| `config` | Configuration | 5 | `--global`, `--local`, `user.name` |
| `init` | Initialize repo | 5 | `--bare`, `--initial-branch=` |

**Security Features:**
- Shell injection prevention (blocks `;`, `|`, `&`, `$`, `` ` ``, etc.)
- Command substitution prevention (blocks `$(...)` and `` `...` ``)
- Path traversal detection in arguments
- No `shell=True` execution
- Custom SSH command with strict host key checking

**Errors:**
- `ValueError` - Command not in whitelist
- `ValueError` - Argument contains invalid characters
- `ValueError` - Too many arguments
- `subprocess.TimeoutExpired` - Command timeout

---

## SSH

Tools for SSH key management within the workspace.

### ssh_public_key

**Description:** Get the SSH public key for this workspace.

**Parameters:** None

**Returns:**

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID0e3lTv... workspace@octoprox
```

Returns empty string if key does not exist.

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Get public key for adding to GitHub/GitLab
pubkey = await ssh_public_key()
print(f"Add this key to your Git provider:\n{pubkey}")
```

**Notes:**
- Keys are automatically generated on first access if they don't exist
- Private key stored at `/workspace/.ssh/id_ed25519`
- Public key stored at `/workspace/.ssh/id_ed25519.pub`
- `known_hosts` is pre-populated with `gitlab.com` host key

---

## GitLab

Tools for GitLab API integration with OpenAPI spec support.

### gitlab_request

**Description:** Proxy any GitLab REST API request.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| endpoint | str | Yes | - | GitLab API base URL |
| token | str | Yes | - | GitLab personal access token |
| path | str | Yes | - | API path (e.g., `/projects`) |
| method | str | No | GET | HTTP method |
| params | dict | No | null | Query parameters |
| json_body | any | No | null | JSON request body |
| form | dict | No | null | Form data |
| headers | dict | No | null | Additional headers |
| files | list | No | null | Multipart files (see below) |
| timeout_s | int | No | 30 | Request timeout |
| max_bytes | int | No | 200000 | Max response size |
| include_text | bool | No | True | Include text in response |
| include_base64 | bool | No | False | Include base64-encoded content |

**Files Format:**

```python
[
  {
    "name": "file",
    "filename": "upload.txt",
    "data_base64": "SGVsbG8gV29ybGQ=",
    "content_type": "text/plain"
  }
]
```

**Returns:**

```json
{
  "status_code": 200,
  "headers": {...},
  "text": "{\"id\": 123, ...}",
  "json": {"id": 123, ...},
  "truncated": false,
  "base64": "..."  // if include_base64=True
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False |
| destructiveHint | True (for modifying methods) |
| idempotentHint | False (varies by method) |
| openWorldHint | True |

**Example:**

```python
# List projects
result = await gitlab_request(
    endpoint="https://gitlab.com/api/v4",
    token="glpat-xxxxxxxx",
    path="/projects",
    params={"membership": True, "per_page": 10}
)

# Create issue
result = await gitlab_request(
    endpoint="https://gitlab.com/api/v4",
    token="glpat-xxxxxxxx",
    path="/projects/123/issues",
    method="POST",
    json_body={
        "title": "Bug: Something is broken",
        "description": "Details here..."
    }
)

# Download raw file (binary)
result = await gitlab_request(
    endpoint="https://gitlab.com/api/v4",
    token="glpat-xxxxxxxx",
    path="/projects/123/repository/files/README.md/raw",
    params={"ref": "main"},
    include_base64=True
)
```

---

### gitlab_openapi_spec

**Description:** Return the GitLab OpenAPI YAML specification (chunked for large specs).

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| spec_url | str | No | GitLab v18.8.2 spec URL | URL to OpenAPI spec |
| offset | int | No | 0 | Byte offset for pagination |
| max_bytes | int | No | 200000 | Max bytes to return |
| refresh | bool | No | False | Bypass cache and re-fetch |

**Returns:**

```json
{
  "status_code": 200,
  "offset": 0,
  "total_bytes": 2500000,
  "truncated": true,
  "text": "openapi: 3.0.0\ninfo:\n  title: GitLab API..."
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | True |

**Example:**

```python
# Get first chunk
chunk1 = await gitlab_openapi_spec()

# Get next chunk
chunk2 = await gitlab_openapi_spec(offset=200000)

# Refresh cache
spec = await gitlab_openapi_spec(refresh=True)
```

**Notes:**
- Spec is cached for 1 hour (3600 seconds)
- Use offset/max_bytes to paginate through large specs

---

### gitlab_openapi_paths

**Description:** List GitLab OpenAPI paths and methods for endpoint discovery.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| spec_url | str | No | GitLab v18.8.2 spec URL | URL to OpenAPI spec |
| filter_text | str | No | null | Filter by path/method/summary |
| limit | int | No | 200 | Max results to return |
| offset | int | No | 0 | Pagination offset |
| refresh | bool | No | False | Bypass cache |

**Returns:**

```json
{
  "total": 1500,
  "offset": 0,
  "limit": 200,
  "entries": [
    {
      "path": "/projects/{id}/issues",
      "method": "GET",
      "summary": "List project issues"
    },
    ...
  ]
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Search for issues endpoints
endpoints = await gitlab_openapi_paths(filter_text="issues", limit=20)

# Paginate through all endpoints
page1 = await gitlab_openapi_paths(limit=100, offset=0)
page2 = await gitlab_openapi_paths(limit=100, offset=100)
```

---

### gitlab_openapi_operation

**Description:** Get schema details for a specific GitLab API path and method.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | str | Yes | - | API path (e.g., `/projects/{id}/issues`) |
| method | str | Yes | - | HTTP method (GET, POST, etc.) |
| spec_url | str | No | GitLab v18.8.2 spec URL | URL to OpenAPI spec |
| refresh | bool | No | False | Bypass cache |

**Returns:**

```json
{
  "summary": "List project issues",
  "description": "Get all issues...",
  "operationId": "getProjectIssues",
  "tags": ["issues"],
  "parameters": [...],
  "requestBody": {...},
  "responses": {...}
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# Get details for list issues endpoint
operation = await gitlab_openapi_operation(
    path="/projects/{id}/issues",
    method="GET"
)

# Get details for create issue endpoint
operation = await gitlab_openapi_operation(
    path="/projects/{id}/issues",
    method="POST"
)
```

---

### gitlab_tool_help

**Description:** Return machine-readable help for GitLab MCP tools.

**Parameters:** None

**Returns:**

```json
{
  "overview": "Use gitlab_openapi_paths to discover endpoints...",
  "tools": {
    "gitlab_openapi_paths": {
      "purpose": "Search and list available GitLab REST endpoints.",
      "inputs": ["spec_url?", "filter_text?", "limit?", "offset?", "refresh?"],
      "output": "entries[{path, method, summary}], plus pagination metadata.",
      "example": {"filter_text": "issues", "limit": 20}
    },
    ...
  },
  "notes": [
    "Set endpoint to the GitLab REST base URL...",
    "Set token to a GitLab personal access token..."
  ]
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
help = await gitlab_tool_help()
print(help["overview"])
```

---

## OpenAPI Adapter

Generic tools for loading and interacting with any OpenAPI-compliant API.

### openapi_load

**Description:** Load an OpenAPI specification and register it for use.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| name | str | Yes | - | Unique identifier for this API |
| spec_url | str | No | null | URL to fetch spec from |
| spec_content | str | No | null | Inline spec (YAML or JSON) |
| auth_header | str | No | null | Auth header value for API calls |
| auth_header_name | str | No | Authorization | Header name for auth |
| base_url_override | str | No | null | Override base URL from spec |

**Returns:**

```json
{
  "name": "petstore",
  "title": "Swagger Petstore",
  "version": "1.0.5",
  "endpoint_count": 20
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | True |

**Example:**

```python
# Load from URL with auth
result = await openapi_load(
    name="petstore",
    spec_url="https://petstore.swagger.io/v2/swagger.json",
    auth_header="Bearer token123"
)

# Load inline YAML
result = await openapi_load(
    name="myapi",
    spec_content="""
openapi: 3.0.0
info:
  title: My API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      summary: List users
"""
)

# Override base URL
result = await openapi_load(
    name="staging-api",
    spec_url="https://api.example.com/openapi.json",
    base_url_override="https://staging-api.example.com"
)
```

**Errors:**
- `ValueError` - Neither spec_url nor spec_content provided
- `ValueError` - Invalid YAML/JSON format
- `RuntimeError` - Failed to fetch from URL

---

### openapi_list_apis

**Description:** List all loaded APIs.

**Parameters:** None

**Returns:**

```json
{
  "apis": [
    {
      "name": "petstore",
      "title": "Swagger Petstore",
      "version": "1.0.5",
      "endpoint_count": 20
    },
    {
      "name": "gitlab",
      "title": "GitLab API",
      "version": "v4",
      "endpoint_count": 1500
    }
  ]
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
apis = await openapi_list_apis()
for api in apis["apis"]:
    print(f"{api['name']}: {api['title']} ({api['endpoint_count']} endpoints)")
```

---

### openapi_list_endpoints

**Description:** List endpoints from a loaded API with optional filtering.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| name | str | Yes | - | API name |
| filter | str | No | null | Filter by path substring (case-insensitive) |
| tag | str | No | null | Filter by OpenAPI tag |
| limit | int | No | 50 | Max results |
| offset | int | No | 0 | Pagination offset |

**Returns:**

```json
{
  "total": 20,
  "offset": 0,
  "limit": 50,
  "entries": [
    {
      "path": "/pet/{petId}",
      "method": "GET",
      "summary": "Find pet by ID",
      "tags": ["pet"]
    }
  ]
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
# List all endpoints
all_endpoints = await openapi_list_endpoints(name="petstore")

# Filter by path
pet_endpoints = await openapi_list_endpoints(
    name="petstore",
    filter="pet",
    limit=10
)

# Filter by tag
store_endpoints = await openapi_list_endpoints(
    name="petstore",
    tag="store"
)
```

---

### openapi_get_operation

**Description:** Get detailed information about a specific API operation with resolved `$ref` pointers.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| name | str | Yes | - | API name |
| path | str | Yes | - | API path |
| method | str | Yes | - | HTTP method |

**Returns:**

```json
{
  "path": "/pet/{petId}",
  "method": "GET",
  "summary": "Find pet by ID",
  "description": "Returns a single pet",
  "operationId": "getPetById",
  "parameters": [
    {
      "name": "petId",
      "in": "path",
      "required": true,
      "schema": {"type": "integer", "format": "int64"}
    }
  ],
  "responses": {
    "200": {
      "description": "successful operation",
      "content": {
        "application/json": {
          "schema": {"$ref": "#/components/schemas/Pet"}
        }
      }
    }
  }
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | True |
| destructiveHint | False |
| idempotentHint | True |
| openWorldHint | False |

**Example:**

```python
operation = await openapi_get_operation(
    name="petstore",
    path="/pet/{petId}",
    method="GET"
)

# Access resolved schema
print(operation["parameters"][0]["schema"])
```

**Notes:**
- All `$ref` pointers are recursively resolved
- Returns full operation object from OpenAPI spec

---

### openapi_call

**Description:** Call an API operation with the loaded OpenAPI spec.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| name | str | Yes | - | API name |
| path | str | Yes | - | Path with `{param}` placeholders |
| method | str | Yes | - | HTTP method |
| path_params | dict | No | null | Path parameter values |
| query_params | dict | No | null | Query parameters |
| headers | dict | No | null | Additional headers |
| body | any | No | null | Request body |
| timeout_s | int | No | 30 | Request timeout |
| max_response_bytes | int | No | 100000 | Max response size |

**Returns:**

```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": {"id": 1, "name": "Fluffy", "status": "available"},
  "truncated": false
}
```

**Annotations:**

| Annotation | Value |
|------------|-------|
| readOnlyHint | False |
| destructiveHint | True |
| idempotentHint | False |
| openWorldHint | True |

**Example:**

```python
# GET with path params
result = await openapi_call(
    name="petstore",
    path="/pet/{petId}",
    method="GET",
    path_params={"petId": 1}
)

# GET with query params
result = await openapi_call(
    name="petstore",
    path="/pet/findByStatus",
    method="GET",
    query_params={"status": "available"}
)

# POST with body
result = await openapi_call(
    name="petstore",
    path="/pet",
    method="POST",
    body={
        "name": "Fluffy",
        "photoUrls": ["http://example.com/fluffy.jpg"],
        "status": "available"
    }
)

# With custom headers
result = await openapi_call(
    name="petstore",
    path="/pet",
    method="POST",
    body={"name": "Buddy"},
    headers={"X-Custom-Header": "value"}
)
```

**Errors:**
- `ValueError` - Missing required path parameters
- `ValueError` - API not found (not loaded)
- `RuntimeError` - Request failed

---

## Tool Annotations Reference

All tools include MCP annotations that describe their behavior:

| Annotation | Description |
|------------|-------------|
| `readOnlyHint` | True if the tool only reads data, False if it modifies state |
| `destructiveHint` | True if the tool can cause data loss or significant side effects |
| `idempotentHint` | True if calling the tool multiple times has the same effect as calling it once |
| `openWorldHint` | True if the tool interacts with external systems outside the workspace |

### Annotation Patterns

**Read-Only Tools:**
- `readOnlyHint=True`, `destructiveHint=False`
- Examples: `fs_list`, `fs_read_text`, `git log`, `openapi_list_apis`

**Safe Write Tools:**
- `readOnlyHint=False`, `destructiveHint=False`
- Examples: `fs_write_text` (overwrites but not destructive), `git add`

**Destructive Tools:**
- `readOnlyHint=False`, `destructiveHint=True`
- Examples: `fs_delete`, `git push --force`, `openapi_call` (POST/DELETE)

**External Tools:**
- `openWorldHint=True` for tools that call external APIs
- Examples: All `gitlab_*` tools, all `openapi_*` tools
