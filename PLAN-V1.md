# Octoprox v1.0 Implementation Plan

> **Goal:** Transform Octoprox into a full MCP Server hub providing every tool an LLM needs to accomplish any human or machine task.

## Table of Contents

- [Current State](#current-state)
- [Architecture Decisions](#architecture-decisions)
- [Capability 1: HTTP Fetch](#capability-1-http-fetch)
- [Capability 2: Playwright Browser Automation](#capability-2-playwright-browser-automation)
- [Capability 3: Fast Readable Page Extractor](#capability-3-fast-readable-page-extractor)
- [Capability 4: Web Search](#capability-4-web-search)
- [Capability 5: Filesystem (Expand Existing)](#capability-5-filesystem-expand-existing)
- [Capability 6: Git (Expand Existing)](#capability-6-git-expand-existing)
- [Capability 7: Command Execution](#capability-7-command-execution)
- [Capability 8: SQL Database (PostgreSQL)](#capability-8-sql-database-postgresql)
- [Capability 9: Memory](#capability-9-memory)
- [Capability 10: Time](#capability-10-time)
- [Capability 11: OpenAPI-to-MCP Adapter](#capability-11-openapi-to-mcp-adapter)

---

## Current State

### Existing Tools in `workspace-mcp/app.py`

| Tool | Status | Notes |
|------|--------|-------|
| `fs_list` | Exists | Lists directory entries |
| `fs_read_text` | Exists | Reads text files (200 KB default cap) |
| `fs_write_text` | Exists | Atomic writes with optional `mkdirs` |
| `fs_delete` | Exists | Supports recursive delete |
| `git` | Exists | Whitelisted subcommands, injection protection |
| `ssh_public_key` | Exists | Returns workspace SSH pubkey |
| `gitlab_request` | Exists | Proxies GitLab REST API calls |
| `gitlab_openapi_spec` | Exists | Fetches GitLab OpenAPI YAML (chunked) |
| `gitlab_openapi_paths` | Exists | Lists/filters OpenAPI paths |
| `gitlab_openapi_operation` | Exists | Returns schema for path+method |
| `gitlab_tool_help` | Exists | Machine-readable help for GitLab tools |

### Tech Stack

- **Language:** Python 3.12+
- **MCP SDK:** `mcp==1.26.0` with `FastMCP`
- **Transport:** Streamable HTTP on port 7000
- **HTTP client:** `httpx==0.28.1`
- **Container:** Docker (python:3.12-slim base)
- **Auth:** Token introspection against workspace-manager

### File Structure (current)

```
workspace-mcp/
├── app.py            # Single file: all tools + server setup
├── Dockerfile
└── requirements.txt
```

---

## Architecture Decisions

### AD-1: Modular Source Layout

**Decision:** Refactor `app.py` into a package with one module per capability domain.

**New structure:**

```
workspace-mcp/
├── octoprox/
│   ├── __init__.py          # FastMCP app creation, auth, shared helpers
│   ├── auth.py              # ManagerTokenVerifier, _require_owner, token cache
│   ├── path_utils.py        # _resolve_path, _atomic_write, WORKSPACE_ROOT
│   ├── tools/
│   │   ├── __init__.py      # Imports all tool modules to trigger registration
│   │   ├── filesystem.py    # Capability 5
│   │   ├── git.py           # Capability 6
│   │   ├── fetch.py         # Capability 1
│   │   ├── browser.py       # Capability 2
│   │   ├── readability.py   # Capability 3
│   │   ├── search.py        # Capability 4
│   │   ├── shell.py         # Capability 7
│   │   ├── database.py      # Capability 8
│   │   ├── memory.py        # Capability 9
│   │   ├── time.py          # Capability 10
│   │   ├── openapi.py       # Capability 11
│   │   ├── gitlab.py        # Existing GitLab tools (moved)
│   │   └── ssh.py           # Existing SSH key tool (moved)
│   └── config.py            # Feature flags via env vars
├── app.py                   # Entrypoint: `from octoprox import app`
├── Dockerfile
└── requirements.txt
```

**Refactoring steps (must be done first, before any new capability):**

1. Create `octoprox/` package directory and `octoprox/__init__.py`.
2. Move `ManagerTokenVerifier`, `_require_owner`, `introspect_token`, token cache, `_get_httpx_client`, `_close_httpx_client` into `octoprox/auth.py`.
3. Move `_resolve_path`, `_atomic_write`, `WORKSPACE_ROOT` into `octoprox/path_utils.py`.
4. Create `octoprox/config.py` that reads feature-flag env vars (see AD-2).
5. In `octoprox/__init__.py`:
   - Import `FastMCP` and create the `mcp` instance.
   - Import `AuthSettings` and `ManagerTokenVerifier`.
   - Create `app = mcp.streamable_http_app()`.
   - Import `octoprox.tools` to trigger tool registration.
6. Move existing filesystem tools into `octoprox/tools/filesystem.py`, importing `mcp` from `octoprox`.
7. Move existing git tools into `octoprox/tools/git.py`.
8. Move existing GitLab tools into `octoprox/tools/gitlab.py`.
9. Move SSH tool into `octoprox/tools/ssh.py`.
10. Update `app.py` entrypoint to simply: `from octoprox import app`.
11. Verify all existing tests pass (adjust import paths if needed).
12. Update `Dockerfile` to `COPY octoprox/ /app/octoprox/` and keep `COPY app.py /app/app.py`.

### AD-2: Feature Flags

**Decision:** Each capability is guarded by an environment variable so operators can enable/disable features per workspace.

```python
# octoprox/config.py
import os

ENABLE_FETCH = os.getenv("OCTOPROX_ENABLE_FETCH", "true").lower() == "true"
ENABLE_BROWSER = os.getenv("OCTOPROX_ENABLE_BROWSER", "false").lower() == "true"
ENABLE_READABILITY = os.getenv("OCTOPROX_ENABLE_READABILITY", "true").lower() == "true"
ENABLE_SEARCH = os.getenv("OCTOPROX_ENABLE_SEARCH", "true").lower() == "true"
ENABLE_SHELL = os.getenv("OCTOPROX_ENABLE_SHELL", "false").lower() == "true"
ENABLE_DATABASE = os.getenv("OCTOPROX_ENABLE_DATABASE", "false").lower() == "true"
ENABLE_MEMORY = os.getenv("OCTOPROX_ENABLE_MEMORY", "true").lower() == "true"
ENABLE_TIME = os.getenv("OCTOPROX_ENABLE_TIME", "true").lower() == "true"
ENABLE_OPENAPI = os.getenv("OCTOPROX_ENABLE_OPENAPI", "true").lower() == "true"
ENABLE_GITLAB = os.getenv("OCTOPROX_ENABLE_GITLAB", "true").lower() == "true"
```

Each tool module checks its flag at import time and skips tool registration if disabled. Browser and shell are disabled by default due to security surface area. Database is disabled by default because it requires a connection string.

### AD-3: Playwright as Optional Docker Build Stage

**Decision:** Playwright and its browser binaries add ~500 MB to the image. Use a multi-stage Dockerfile with an optional `--build-arg INSTALL_PLAYWRIGHT=true` to include it. When disabled, the `browser.py` module gracefully skips registration.

### AD-4: Tool Annotations

**Decision:** All tools must declare MCP tool annotations for LLM consumption:

- `readOnlyHint` — whether the tool only reads data
- `destructiveHint` — whether the tool can destroy data
- `idempotentHint` — whether repeated calls are safe
- `openWorldHint` — whether the tool interacts with external systems

---

## Capability 1: HTTP Fetch

**File:** `octoprox/tools/fetch.py`

### Overview

Fetches a URL over HTTP(S), follows redirects, converts HTML to LLM-friendly Markdown/text, and returns metadata. This is the workhorse for web retrieval when JavaScript execution is not required.

### Tools to Implement

#### 1.1 `fetch_url`

```
Tool: fetch_url
Description: "Fetch a URL and return its content as LLM-friendly text. Converts HTML to
             Markdown, follows redirects, respects robots.txt optionally, and returns
             metadata. Use this for static web pages, APIs, and raw file downloads."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | `str` | Yes | — | The URL to fetch (http or https) |
| `method` | `str` | No | `"GET"` | HTTP method |
| `headers` | `dict[str, str]` | No | `None` | Extra request headers |
| `body` | `str` | No | `None` | Request body (for POST/PUT) |
| `content_type` | `str` | No | `None` | Content-Type for the request body |
| `max_bytes` | `int` | No | `500000` | Maximum response bytes to process |
| `timeout_s` | `int` | No | `30` | Request timeout in seconds |
| `follow_redirects` | `bool` | No | `True` | Follow HTTP redirects |
| `extract_main_content` | `bool` | No | `True` | Strip nav/footer/ads, extract article body |
| `output_format` | `str` | No | `"markdown"` | Output format: `"markdown"`, `"text"`, `"html"`, `"raw"` |
| `include_links` | `bool` | No | `True` | Include extracted links in output |
| `include_metadata` | `bool` | No | `True` | Include title, description, canonical URL |

**Return schema:**

```json
{
  "url": "string (final URL after redirects)",
  "status_code": "number",
  "content_type": "string",
  "title": "string | null",
  "description": "string | null",
  "content": "string (converted text/markdown)",
  "links": [{"text": "string", "href": "string"}],
  "truncated": "boolean",
  "byte_count": "number"
}
```

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
```

### Implementation Steps

1. **Add dependencies to `requirements.txt`:**
   ```
   beautifulsoup4==4.13.3
   markdownify==0.14.1
   ```
   - `beautifulsoup4` — HTML parsing and main-content extraction
   - `markdownify` — HTML-to-Markdown conversion

2. **Create `octoprox/tools/fetch.py`:**
   - Import `httpx`, `bs4`, `markdownify`.
   - Import `mcp` from `octoprox` and `_require_owner` from `octoprox.auth`.
   - Import `ENABLE_FETCH` from `octoprox.config`.
   - Guard tool registration: `if not ENABLE_FETCH: return` at module level (use a wrapper pattern).

3. **Implement URL validation:**
   - Parse with `urllib.parse.urlparse`.
   - Allow only `http` and `https` schemes.
   - Reject private/internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x, ::1, link-local) to prevent SSRF.
   - Reject `file://`, `ftp://`, `data:` schemes.
   - Validate hostname is not empty.
   - Maximum URL length: 8192 chars.

4. **Implement `_extract_main_content(html: str) -> str`:**
   - Use BeautifulSoup to parse HTML.
   - Remove `<script>`, `<style>`, `<nav>`, `<header>`, `<footer>`, `<aside>`, `<noscript>` tags.
   - Try to find `<article>` or `<main>` or element with `role="main"`.
   - Fall back to `<body>` if no main content element found.
   - Return cleaned HTML string.

5. **Implement `_html_to_markdown(html: str) -> str`:**
   - Use `markdownify.markdownify(html, heading_style="ATX", strip=['img'])`.
   - Collapse multiple blank lines to max 2.
   - Strip leading/trailing whitespace.

6. **Implement `_extract_links(soup: BeautifulSoup, base_url: str) -> list[dict]`:**
   - Find all `<a>` tags with `href`.
   - Resolve relative URLs against `base_url` using `urllib.parse.urljoin`.
   - Filter out `javascript:` and `mailto:` links.
   - Return list of `{"text": ..., "href": ...}`.

7. **Implement `_extract_metadata(soup: BeautifulSoup) -> dict`:**
   - Extract `<title>` text.
   - Extract `<meta name="description">` content.
   - Extract `<link rel="canonical">` href.
   - Extract Open Graph title/description as fallbacks.

8. **Register the `fetch_url` tool:**
   ```python
   @mcp.tool(
       name="fetch_url",
       description="Fetch a URL and return its content as LLM-friendly text. ..."
   )
   def fetch_url(url: str, method: str = "GET", ...) -> dict[str, Any]:
       _require_owner()
       _validate_url(url)
       # ... implementation
   ```

9. **Handle different content types in the response:**
   - `text/html` → parse, extract, convert to markdown.
   - `application/json` → pretty-print JSON.
   - `text/plain` → return as-is.
   - `application/xml`, `text/xml` → return as-is.
   - `application/pdf` → return raw bytes info (note: "use shell tool with pdftotext for extraction").
   - Binary types → return metadata only with content-type info.

10. **Add error handling:**
    - Catch `httpx.TimeoutException` → return error with timeout info.
    - Catch `httpx.ConnectError` → return error with connection info.
    - Catch `httpx.TooManyRedirects` → return error.
    - All errors return a dict with `"error"` key instead of raising.

11. **Add tests in `workspace-mcp/tests/test_fetch.py`:**
    - Test URL validation (valid URLs, SSRF rejection, scheme rejection).
    - Test HTML-to-Markdown conversion.
    - Test main content extraction.
    - Test link extraction with relative URL resolution.
    - Test metadata extraction.
    - Test max_bytes truncation.
    - Test error handling for timeouts and connection errors (mock httpx).

---

## Capability 2: Playwright Browser Automation

**File:** `octoprox/tools/browser.py`

### Overview

Drives a real Chromium browser via Playwright for pages that require JavaScript execution, single-page apps, sites with authentication flows, or any page that can't be meaningfully fetched with simple HTTP.

### Tools to Implement

#### 2.1 `browser_navigate`

```
Tool: browser_navigate
Description: "Open a URL in a headless browser, wait for the page to load (including
             JavaScript), and return the page content. Use when fetch_url fails to get
             meaningful content due to client-side rendering."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | `str` | Yes | — | URL to navigate to |
| `wait_until` | `str` | No | `"networkidle"` | Wait condition: `"load"`, `"domcontentloaded"`, `"networkidle"` |
| `wait_for_selector` | `str` | No | `None` | CSS selector to wait for before extracting |
| `timeout_ms` | `int` | No | `30000` | Navigation timeout in milliseconds |
| `output_format` | `str` | No | `"markdown"` | `"markdown"`, `"text"`, `"html"`, `"accessibility"` |
| `extract_main_content` | `bool` | No | `True` | Strip nav/footer, extract main content |
| `include_links` | `bool` | No | `True` | Include links in output |
| `screenshot` | `bool` | No | `False` | Take a screenshot (returned as base64 PNG) |

**Return schema:**

```json
{
  "url": "string (final URL)",
  "title": "string",
  "content": "string",
  "links": [{"text": "string", "href": "string"}],
  "screenshot_base64": "string | null",
  "error": "string | null"
}
```

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=True
```

#### 2.2 `browser_click`

```
Tool: browser_click
Description: "Click an element on the current page by CSS selector or text content."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `selector` | `str` | No | `None` | CSS selector to click |
| `text` | `str` | No | `None` | Text content to find and click (uses `get_by_text`) |
| `timeout_ms` | `int` | No | `5000` | Timeout waiting for element |

**Return:** `{"success": bool, "url": str, "error": str | null}`

**Annotations:**
```python
readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
```

#### 2.3 `browser_type`

```
Tool: browser_type
Description: "Type text into an input field identified by CSS selector."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `selector` | `str` | Yes | — | CSS selector of the input field |
| `text` | `str` | Yes | — | Text to type |
| `press_enter` | `bool` | No | `False` | Press Enter after typing |
| `clear_first` | `bool` | No | `True` | Clear the field before typing |

**Return:** `{"success": bool, "error": str | null}`

**Annotations:**
```python
readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
```

#### 2.4 `browser_screenshot`

```
Tool: browser_screenshot
Description: "Take a screenshot of the current page or a specific element."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `selector` | `str` | No | `None` | CSS selector to screenshot (full page if omitted) |
| `full_page` | `bool` | No | `False` | Capture the entire scrollable page |

**Return:** `{"screenshot_base64": str, "width": int, "height": int}`

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
```

#### 2.5 `browser_get_content`

```
Tool: browser_get_content
Description: "Get the current page content without navigating. Returns accessibility tree
             snapshot, full HTML, or extracted text/markdown."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `output_format` | `str` | No | `"accessibility"` | `"accessibility"`, `"markdown"`, `"text"`, `"html"` |

**Return:** `{"url": str, "title": str, "content": str}`

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
```

#### 2.6 `browser_execute_js`

```
Tool: browser_execute_js
Description: "Execute JavaScript in the browser page context and return the result."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `script` | `str` | Yes | — | JavaScript to execute |
| `timeout_ms` | `int` | No | `5000` | Execution timeout |

**Return:** `{"result": Any, "error": str | null}`

**Annotations:**
```python
readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
```

#### 2.7 `browser_close`

```
Tool: browser_close
Description: "Close the browser session and free resources."
```

**Parameters:** None.

**Return:** `{"success": bool}`

**Annotations:**
```python
readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
```

### Implementation Steps

1. **Update `Dockerfile` with multi-stage Playwright support:**

   ```dockerfile
   ARG INSTALL_PLAYWRIGHT=false

   # Stage: playwright deps (only when enabled)
   FROM python:3.12-slim AS playwright-deps
   RUN pip install playwright==1.49.1 && playwright install --with-deps chromium

   # Stage: main
   FROM python:3.12-slim AS main
   # ... existing setup ...
   # Conditionally copy playwright from deps stage
   ARG INSTALL_PLAYWRIGHT
   COPY --from=playwright-deps /root/.cache/ms-playwright /root/.cache/ms-playwright
   # (only if INSTALL_PLAYWRIGHT=true, handled by build script)
   ```

   Alternatively, use a simpler approach:
   ```dockerfile
   ARG INSTALL_PLAYWRIGHT=false
   RUN if [ "$INSTALL_PLAYWRIGHT" = "true" ]; then \
         pip install playwright==1.49.1 && \
         playwright install --with-deps chromium; \
       fi
   ```

2. **Add conditional dependency in `requirements.txt`:**
   - Add a separate `requirements-browser.txt` with `playwright==1.49.1`.
   - The main `requirements.txt` does not include playwright.
   - The Dockerfile installs it conditionally.

3. **Create `octoprox/tools/browser.py`:**
   - At module top, try `import playwright`; if `ImportError`, set `PLAYWRIGHT_AVAILABLE = False`.
   - Check `ENABLE_BROWSER` from config AND `PLAYWRIGHT_AVAILABLE`. Skip registration if either is false.

4. **Implement browser session management:**
   - Use a module-level singleton `_browser_context`:
     ```python
     _playwright: Playwright | None = None
     _browser: Browser | None = None
     _page: Page | None = None
     ```
   - `_ensure_browser()` → lazily creates playwright instance, launches Chromium headless, creates page.
   - `_close_browser()` → closes page, browser, playwright; resets to None.
   - Browser launch args for security:
     ```python
     browser = await playwright.chromium.launch(
         headless=True,
         args=[
             "--no-sandbox",
             "--disable-dev-shm-usage",
             "--disable-gpu",
             "--disable-extensions",
             "--disable-background-networking",
         ]
     )
     ```

5. **Implement `browser_navigate`:**
   - Call `_ensure_browser()`.
   - Validate URL (same SSRF checks as fetch).
   - `await page.goto(url, wait_until=wait_until, timeout=timeout_ms)`.
   - If `wait_for_selector`, `await page.wait_for_selector(selector, timeout=timeout_ms)`.
   - Extract content based on `output_format`:
     - `"accessibility"` → `await page.accessibility.snapshot()` (serialize to string).
     - `"html"` → `await page.content()`.
     - `"markdown"` → get HTML, use same conversion as fetch.
     - `"text"` → `await page.inner_text("body")`.
   - If `screenshot`, `await page.screenshot()` → base64 encode.

6. **Implement `browser_click`:**
   - If `selector`: `await page.click(selector, timeout=timeout_ms)`.
   - If `text`: `await page.get_by_text(text).click(timeout=timeout_ms)`.
   - Return current URL after click.

7. **Implement `browser_type`:**
   - If `clear_first`: `await page.fill(selector, "")`.
   - `await page.type(selector, text)`.
   - If `press_enter`: `await page.press(selector, "Enter")`.

8. **Implement `browser_screenshot`:**
   - If `selector`: `element = page.locator(selector); await element.screenshot()`.
   - Else: `await page.screenshot(full_page=full_page)`.
   - Base64 encode the PNG bytes.

9. **Implement `browser_get_content`:**
   - Switch on `output_format` and extract from the current `_page`.

10. **Implement `browser_execute_js`:**
    - `result = await page.evaluate(script)`.
    - Serialize result to JSON-safe format.

11. **Implement `browser_close`:**
    - Call `_close_browser()`.

12. **Add timeout guard:** Wrap all browser operations in `asyncio.wait_for` with max 60-second timeout to prevent hanging.

13. **Add tests in `workspace-mcp/tests/test_browser.py`:**
    - Mock Playwright to test tool logic without actual browser.
    - Test SSRF URL validation.
    - Test graceful handling when Playwright is not installed.
    - Test session management (ensure → close cycle).

---

## Capability 3: Fast Readable Page Extractor

**File:** `octoprox/tools/readability.py`

### Overview

A lightweight, fast alternative to full browser automation. Fetches a page, applies Mozilla's Readability algorithm to extract the article content, caches results, and returns token-efficient Markdown.

### Tools to Implement

#### 3.1 `read_page`

```
Tool: read_page
Description: "Fetch a web page and extract its main readable content (article body) as
             clean Markdown. Faster and more token-efficient than browser_navigate.
             Includes caching for repeated reads of the same URL."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | `str` | Yes | — | URL to read |
| `timeout_s` | `int` | No | `15` | HTTP timeout |
| `max_chars` | `int` | No | `50000` | Maximum output characters |
| `use_cache` | `bool` | No | `True` | Use/update the read cache |
| `include_images` | `bool` | No | `False` | Include image alt text and URLs |

**Return schema:**

```json
{
  "url": "string",
  "title": "string",
  "byline": "string | null",
  "excerpt": "string | null",
  "content": "string (clean markdown)",
  "word_count": "number",
  "truncated": "boolean",
  "cached": "boolean"
}
```

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
```

### Implementation Steps

1. **Add dependency to `requirements.txt`:**
   ```
   readability-lxml==0.8.4.1
   lxml==5.3.1
   ```
   `readability-lxml` is a Python port of Mozilla's Readability.js. `lxml` is required by readability-lxml.

2. **Create `octoprox/tools/readability.py`:**
   - Import `readability.Document` for content extraction.
   - Import `markdownify` (already added for Capability 1) for HTML→Markdown.
   - Import `httpx` for fetching.

3. **Implement page cache:**
   ```python
   from cachetools import TTLCache
   _page_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=100, ttl=900)  # 15 min TTL
   ```

4. **Implement `_fetch_and_extract(url: str, timeout_s: int) -> dict`:**
   - Fetch URL with httpx (reuse singleton client from auth module).
   - Pass response HTML to `readability.Document(html)`.
   - Extract:
     - `doc.title()` → title
     - `doc.summary()` → cleaned HTML of main content
     - `doc.short_title()` → byline (if available)
   - Convert summary HTML to Markdown via `markdownify`.
   - Optionally strip image references if `include_images=False`.

5. **Implement polite crawling:**
   - Set a proper `User-Agent` header: `"Octoprox/1.0 (MCP Server; +https://github.com/octoprox)"`.
   - Respect `Retry-After` headers on 429 responses.
   - Rate limit: max 1 request per second per domain (use a simple per-domain timestamp tracker).

6. **Register the `read_page` tool:**
   - Check `ENABLE_READABILITY` feature flag.
   - Validate URL (same SSRF protection as Capability 1).
   - Check cache first if `use_cache=True`.
   - Truncate output to `max_chars`.
   - Calculate `word_count` from content.

7. **Add tests in `workspace-mcp/tests/test_readability.py`:**
   - Test extraction from sample HTML.
   - Test caching behavior (hit/miss).
   - Test truncation.
   - Test polite crawling rate limiter.

---

## Capability 4: Web Search

**File:** `octoprox/tools/search.py`

### Overview

Provides web search functionality so the LLM can discover URLs before fetching them. Uses SearxNG (a self-hosted meta-search engine) as the backend, configurable via environment variable.

### Tools to Implement

#### 4.1 `web_search`

```
Tool: web_search
Description: "Search the web and return ranked results with titles, URLs, and snippets.
             Use this to find relevant pages before fetching them with fetch_url or
             read_page."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | `str` | Yes | — | Search query |
| `num_results` | `int` | No | `10` | Number of results to return (max 50) |
| `language` | `str` | No | `"en"` | Search language (ISO 639-1) |
| `time_range` | `str` | No | `None` | Time filter: `"day"`, `"week"`, `"month"`, `"year"` |
| `categories` | `list[str]` | No | `["general"]` | Search categories: `"general"`, `"images"`, `"news"`, `"science"`, `"it"` |
| `engines` | `list[str]` | No | `None` | Specific engines to query (e.g., `["google", "duckduckgo"]`) |

**Return schema:**

```json
{
  "query": "string",
  "results": [
    {
      "title": "string",
      "url": "string",
      "snippet": "string",
      "engine": "string",
      "score": "number | null"
    }
  ],
  "total_results": "number",
  "suggestions": ["string"]
}
```

**Annotations:**
```python
readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=True
```

### Implementation Steps

1. **No new Python dependencies required** (uses `httpx` already available).

2. **Add environment variables:**
   ```python
   # octoprox/config.py
   SEARXNG_BASE_URL = os.getenv("OCTOPROX_SEARXNG_URL", "")
   ```

3. **Create `octoprox/tools/search.py`:**
   - Check `ENABLE_SEARCH` AND `SEARXNG_BASE_URL` is non-empty.
   - If no SearxNG URL configured, tool registration is skipped (with a warning log).

4. **Implement `web_search` tool:**
   ```python
   @mcp.tool(name="web_search", description="...")
   async def web_search(query: str, num_results: int = 10, ...) -> dict[str, Any]:
       _require_owner()
       # Validate inputs
       if not query.strip():
           raise ValueError("Query cannot be empty")
       if num_results < 1 or num_results > 50:
           raise ValueError("num_results must be between 1 and 50")

       # Call SearxNG JSON API
       params = {
           "q": query,
           "format": "json",
           "language": language,
           "pageno": 1,
           "safesearch": 1,
       }
       if time_range:
           params["time_range"] = time_range
       if categories:
           params["categories"] = ",".join(categories)
       if engines:
           params["engines"] = ",".join(engines)

       client = _get_httpx_client()
       response = await client.get(
           f"{SEARXNG_BASE_URL}/search",
           params=params,
           timeout=15,
       )
       response.raise_for_status()
       data = response.json()

       results = []
       for item in data.get("results", [])[:num_results]:
           results.append({
               "title": item.get("title", ""),
               "url": item.get("url", ""),
               "snippet": item.get("content", ""),
               "engine": ", ".join(item.get("engines", [])),
               "score": item.get("score"),
           })

       return {
           "query": query,
           "results": results,
           "total_results": len(results),
           "suggestions": data.get("suggestions", []),
       }
   ```

5. **Add SearxNG to `docker-compose.yml` (optional service):**
   ```yaml
   searxng:
     image: searxng/searxng:latest
     container_name: searxng
     environment:
       - SEARXNG_BASE_URL=http://searxng:8888
     volumes:
       - searxng-data:/etc/searxng
     networks:
       - mcpnet
     profiles: ["search"]
   ```

6. **Update workspace provisioning** to pass `OCTOPROX_SEARXNG_URL=http://searxng:8888` to workspace containers when search is enabled.

7. **Add tests in `workspace-mcp/tests/test_search.py`:**
   - Mock SearxNG responses.
   - Test query validation.
   - Test result parsing.
   - Test behavior when SearxNG URL is not configured.

---

## Capability 5: Filesystem (Expand Existing)

**File:** `octoprox/tools/filesystem.py`

### Overview

Expand the existing filesystem tools to cover all operations an LLM needs: move/copy, glob, file info/stat, directory tree, applying patches, reading binary files (base64), and appending.

### New Tools to Add

#### 5.1 `fs_stat`

```
Tool: fs_stat
Description: "Return metadata about a file or directory: size, type, permissions, timestamps."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | Yes | — | Path relative to workspace root |

**Return schema:**

```json
{
  "path": "string",
  "type": "string (file|directory|symlink)",
  "size_bytes": "number",
  "created": "string (ISO 8601)",
  "modified": "string (ISO 8601)",
  "permissions": "string (octal, e.g. '0644')"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 5.2 `fs_move`

```
Tool: fs_move
Description: "Move or rename a file or directory."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | `str` | Yes | — | Source path |
| `destination` | `str` | Yes | — | Destination path |
| `overwrite` | `bool` | No | `False` | Overwrite destination if it exists |

**Return:** `"ok"`

**Annotations:** `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False`

#### 5.3 `fs_copy`

```
Tool: fs_copy
Description: "Copy a file or directory (recursive for directories)."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | `str` | Yes | — | Source path |
| `destination` | `str` | Yes | — | Destination path |
| `overwrite` | `bool` | No | `False` | Overwrite destination if it exists |

**Return:** `"ok"`

**Annotations:** `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 5.4 `fs_glob`

```
Tool: fs_glob
Description: "Find files matching a glob pattern within the workspace."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `pattern` | `str` | Yes | — | Glob pattern (e.g., `"**/*.py"`, `"src/*.ts"`) |
| `path` | `str` | No | `"."` | Base directory for the search |
| `max_results` | `int` | No | `1000` | Maximum results to return |

**Return:** `list[str]` (relative paths)

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 5.5 `fs_tree`

```
Tool: fs_tree
Description: "Return a directory tree structure as a nested text representation."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | No | `"."` | Root directory |
| `max_depth` | `int` | No | `3` | Maximum recursion depth |
| `include_hidden` | `bool` | No | `False` | Include dotfiles/dotdirs |
| `dirs_only` | `bool` | No | `False` | Only show directories |

**Return:** `str` (tree-formatted text)

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 5.6 `fs_read_bytes`

```
Tool: fs_read_bytes
Description: "Read a binary file and return its content as base64."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | Yes | — | File path |
| `max_bytes` | `int` | No | `500000` | Maximum bytes to read |

**Return schema:**

```json
{
  "base64": "string",
  "size_bytes": "number",
  "truncated": "boolean"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 5.7 `fs_append`

```
Tool: fs_append
Description: "Append text to a file, creating it if it doesn't exist."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | Yes | — | File path |
| `text` | `str` | Yes | — | Text to append |

**Return:** `"ok"`

**Annotations:** `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False`

#### 5.8 `fs_patch`

```
Tool: fs_patch
Description: "Apply a unified diff patch to a file. Accepts standard unified diff format."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | Yes | — | File to patch |
| `patch` | `str` | Yes | — | Unified diff content |
| `reverse` | `bool` | No | `False` | Apply patch in reverse |

**Return:** `{"success": bool, "message": str}`

**Annotations:** `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False`

#### 5.9 `fs_search`

```
Tool: fs_search
Description: "Search file contents using a regex or literal pattern (like grep)."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `pattern` | `str` | Yes | — | Search pattern (regex) |
| `path` | `str` | No | `"."` | Directory to search in |
| `glob` | `str` | No | `None` | File glob filter (e.g., `"*.py"`) |
| `max_results` | `int` | No | `100` | Maximum matches to return |
| `case_sensitive` | `bool` | No | `True` | Case-sensitive matching |
| `context_lines` | `int` | No | `0` | Lines of context around each match |

**Return schema:**

```json
{
  "matches": [
    {
      "file": "string",
      "line_number": "number",
      "line": "string",
      "context_before": ["string"],
      "context_after": ["string"]
    }
  ],
  "total_matches": "number",
  "truncated": "boolean"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **Move existing tools** from `app.py` into `octoprox/tools/filesystem.py` as part of the AD-1 refactoring.

2. **Implement `fs_stat`:**
   - Use `pathlib.Path.stat()` for size, timestamps.
   - Use `stat.filemode()` for permissions string.
   - Format timestamps as ISO 8601.

3. **Implement `fs_move`:**
   - Validate both source and destination with `_resolve_path`.
   - If `not overwrite` and destination exists, raise error.
   - Use `shutil.move()`.

4. **Implement `fs_copy`:**
   - Validate both paths.
   - If directory: `shutil.copytree(src, dst)`.
   - If file: `shutil.copy2(src, dst)`.

5. **Implement `fs_glob`:**
   - Use `pathlib.Path.glob(pattern)`.
   - Convert to relative paths.
   - Sort results.
   - Limit to `max_results`.

6. **Implement `fs_tree`:**
   - Recursive directory walk with depth limit.
   - Format with tree-drawing characters (`├──`, `└──`, `│`).
   - Skip hidden files unless `include_hidden`.

7. **Implement `fs_read_bytes`:**
   - Read file as bytes.
   - Truncate to `max_bytes`.
   - Base64 encode.

8. **Implement `fs_append`:**
   - Validate path.
   - Open file in append mode.
   - Write text.

9. **Implement `fs_patch`:**
   - Parse unified diff format.
   - Use Python's `difflib` or subprocess `patch` command.
   - Recommended approach: subprocess `patch -p0` since it handles edge cases better.
   - Validate the patch file doesn't reference paths outside workspace.

10. **Implement `fs_search`:**
    - Walk directory tree.
    - Apply glob filter if provided.
    - Compile regex from pattern.
    - Search each file line by line.
    - Collect matches with context lines.
    - Stop at `max_results`.
    - Use binary-file detection (skip files with null bytes).

11. **Update existing `fs_list` to support optional parameters:**
    - Add `include_hidden: bool = True` parameter.
    - Add `long_format: bool = False` parameter (includes size, modified date).

12. **Add tests for all new filesystem tools.**

---

## Capability 6: Git (Expand Existing)

**File:** `octoprox/tools/git.py`

### Overview

The existing `git` tool provides a whitelisted command interface. Expand the whitelist and add convenience tools for common operations that LLMs frequently need.

### New Tools to Add

#### 6.1 `git_status`

```
Tool: git_status
Description: "Get a structured git status showing staged, unstaged, and untracked files."
```

**Parameters:** None.

**Return schema:**

```json
{
  "branch": "string",
  "ahead": "number",
  "behind": "number",
  "staged": [{"path": "string", "status": "string"}],
  "unstaged": [{"path": "string", "status": "string"}],
  "untracked": ["string"]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 6.2 `git_diff_structured`

```
Tool: git_diff_structured
Description: "Get a structured git diff with per-file hunks. More useful than raw diff text
             for LLM analysis."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `ref` | `str` | No | `None` | Commit/branch to diff against (defaults to working tree) |
| `staged` | `bool` | No | `False` | Show staged changes only |
| `paths` | `list[str]` | No | `None` | Limit diff to specific paths |

**Return schema:**

```json
{
  "files": [
    {
      "path": "string",
      "status": "string (added|modified|deleted|renamed)",
      "additions": "number",
      "deletions": "number",
      "hunks": [
        {
          "header": "string",
          "lines": ["string"]
        }
      ]
    }
  ],
  "stats": {"files_changed": "number", "insertions": "number", "deletions": "number"}
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 6.3 `git_log_structured`

```
Tool: git_log_structured
Description: "Get structured git log entries with commit metadata."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `max_count` | `int` | No | `20` | Maximum commits to return |
| `since` | `str` | No | `None` | Only commits after this date (ISO 8601) |
| `author` | `str` | No | `None` | Filter by author |
| `path` | `str` | No | `None` | Filter by file path |
| `ref` | `str` | No | `"HEAD"` | Starting ref |

**Return schema:**

```json
{
  "commits": [
    {
      "hash": "string",
      "short_hash": "string",
      "author": "string",
      "date": "string (ISO 8601)",
      "message": "string",
      "files_changed": "number"
    }
  ]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 6.4 `git_blame`

```
Tool: git_blame
Description: "Show who last modified each line of a file (git blame)."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `path` | `str` | Yes | — | File path |
| `start_line` | `int` | No | `None` | Start line number |
| `end_line` | `int` | No | `None` | End line number |

**Return schema:**

```json
{
  "lines": [
    {
      "line_number": "number",
      "commit": "string",
      "author": "string",
      "date": "string",
      "content": "string"
    }
  ]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Existing Whitelist Expansions

Add these subcommands to `ALLOWED_GIT_COMMANDS`:

```python
'stash': {
    'max_args': 5,
    'allowed_prefixes': ['list', 'show', 'pop', 'apply', 'drop', 'clear',
                         '--include-untracked', '-u', '-m', '--message='],
},
'tag': {
    'max_args': 10,
    'allowed_prefixes': ['-l', '--list', '-a', '-m', '--message=', '-d', '--delete',
                         '-n', '--sort=', '--contains='],
},
'merge': {
    'max_args': 5,
    'allowed_prefixes': ['--no-ff', '--ff-only', '--squash', '--abort', '--continue',
                         '-m', '--message=', '--no-edit'],
},
'rebase': {
    'max_args': 5,
    'allowed_prefixes': ['--abort', '--continue', '--skip', '--onto',
                         '--interactive', '-i'],
},
'cherry-pick': {
    'max_args': 5,
    'allowed_prefixes': ['--abort', '--continue', '--skip', '--no-commit', '-n',
                         '-x', '--edit', '-e'],
},
'rev-parse': {
    'max_args': 5,
    'allowed_prefixes': ['--short', '--verify', '--abbrev-ref', 'HEAD',
                         '--show-toplevel', '--git-dir'],
},
```

### Implementation Steps

1. **Move existing git tool** into `octoprox/tools/git.py`.

2. **Add the new whitelist entries** listed above.

3. **Implement `git_status`:**
   - Run `git status --porcelain=v2 --branch`.
   - Parse the v2 porcelain format to extract branch, ahead/behind, file statuses.
   - Categorize files into staged, unstaged, untracked.

4. **Implement `git_diff_structured`:**
   - Run `git diff --numstat` and `git diff` (or `git diff --cached` if staged).
   - Parse numstat output for additions/deletions per file.
   - Parse unified diff output for hunks.
   - Assemble structured response.

5. **Implement `git_log_structured`:**
   - Run `git log --format="%H%n%h%n%an%n%aI%n%s%n---"` with appropriate filters.
   - Parse the custom format into structured entries.

6. **Implement `git_blame`:**
   - Run `git blame --porcelain` on the file.
   - If `start_line`/`end_line` given, add `-L start,end`.
   - Parse porcelain blame format.

7. **Add tests for each new tool**, mocking subprocess calls.

---

## Capability 7: Command Execution

**File:** `octoprox/tools/shell.py`

### Overview

Provides controlled shell command execution within the workspace container. This is the most security-sensitive capability and is disabled by default. When enabled, it allows running arbitrary CLI tools (curl, ffmpeg, terraform, test runners, linters, etc.).

### Tools to Implement

#### 7.1 `shell_exec`

```
Tool: shell_exec
Description: "Execute a shell command in the workspace. Returns stdout, stderr, and exit
             code. Use for running CLI tools, build commands, test suites, or any command
             not covered by dedicated tools. Disabled by default; requires OCTOPROX_ENABLE_SHELL=true."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `command` | `str` | Yes | — | Command to execute (passed to shell) |
| `cwd` | `str` | No | `"."` | Working directory (relative to workspace root) |
| `env` | `dict[str, str]` | No | `None` | Additional environment variables |
| `timeout_s` | `int` | No | `120` | Execution timeout (max 600) |
| `max_output_bytes` | `int` | No | `500000` | Max bytes of stdout+stderr to return |

**Return schema:**

```json
{
  "exit_code": "number",
  "stdout": "string",
  "stderr": "string",
  "truncated": "boolean",
  "timed_out": "boolean",
  "duration_ms": "number"
}
```

**Annotations:**
```python
readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
```

#### 7.2 `shell_which`

```
Tool: shell_which
Description: "Check if a command is available on the system PATH."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `command` | `str` | Yes | — | Command name to look up |

**Return:** `{"found": bool, "path": str | null}`

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **Create `octoprox/tools/shell.py`:**
   - Check `ENABLE_SHELL` feature flag. Skip registration if disabled.

2. **Add configurable safeguards:**
   ```python
   # octoprox/config.py additions
   SHELL_ALLOWED_COMMANDS = os.getenv("OCTOPROX_SHELL_ALLOWED_COMMANDS", "").split(",")
   # Empty list = all commands allowed (when shell is enabled)
   SHELL_BLOCKED_COMMANDS = os.getenv(
       "OCTOPROX_SHELL_BLOCKED_COMMANDS",
       "rm -rf /,mkfs,dd,:(){ :|:& };:,shutdown,reboot,halt,poweroff"
   ).split(",")
   SHELL_MAX_TIMEOUT = int(os.getenv("OCTOPROX_SHELL_MAX_TIMEOUT", "600"))
   ```

3. **Implement command validation:**
   - If `SHELL_ALLOWED_COMMANDS` is non-empty, extract the base command (first word) and verify it's in the allow-list.
   - Check against `SHELL_BLOCKED_COMMANDS` patterns.
   - Reject commands containing obvious shell bombs (fork bombs, etc.).
   - **Note:** Since the workspace runs in an isolated Docker container, the blast radius is limited. The primary defense is container isolation, not command filtering.

4. **Implement `shell_exec`:**
   ```python
   @mcp.tool(name="shell_exec", description="...")
   def shell_exec(
       command: str,
       cwd: str = ".",
       env: dict[str, str] | None = None,
       timeout_s: int = 120,
       max_output_bytes: int = 500000,
   ) -> dict[str, Any]:
       _require_owner()
       # Validate timeout
       timeout_s = min(timeout_s, SHELL_MAX_TIMEOUT)

       # Resolve working directory
       work_dir = _resolve_path(cwd)
       if not work_dir.is_dir():
           raise ValueError(f"Working directory does not exist: {cwd}")

       # Build environment
       run_env = os.environ.copy()
       run_env["HOME"] = str(WORKSPACE_ROOT)
       if env:
           run_env.update(env)

       # Execute
       start = time.monotonic()
       timed_out = False
       try:
           result = subprocess.run(
               command,
               shell=True,
               cwd=str(work_dir),
               capture_output=True,
               timeout=timeout_s,
               env=run_env,
           )
           exit_code = result.returncode
           stdout = result.stdout
           stderr = result.stderr
       except subprocess.TimeoutExpired as e:
           timed_out = True
           exit_code = -1
           stdout = e.stdout or b""
           stderr = e.stderr or b""
       duration_ms = int((time.monotonic() - start) * 1000)

       # Truncate output
       truncated = len(stdout) + len(stderr) > max_output_bytes
       stdout = stdout[:max_output_bytes]
       stderr = stderr[:max(0, max_output_bytes - len(stdout))]

       return {
           "exit_code": exit_code,
           "stdout": stdout.decode("utf-8", errors="replace"),
           "stderr": stderr.decode("utf-8", errors="replace"),
           "truncated": truncated,
           "timed_out": timed_out,
           "duration_ms": duration_ms,
       }
   ```

5. **Implement `shell_which`:**
   - Use `shutil.which(command)`.
   - Return path if found, None otherwise.

6. **Add tests:**
   - Test command execution with mock subprocess.
   - Test timeout handling.
   - Test output truncation.
   - Test working directory resolution.
   - Test `shell_which` with available/unavailable commands.

---

## Capability 8: SQL Database (PostgreSQL)

**File:** `octoprox/tools/database.py`

### Overview

Provides SQL database access. PostgreSQL is the baseline, but the implementation should use `asyncpg` for Postgres and be designed to support other databases in the future. The connection string is provided via environment variable.

### Tools to Implement

#### 8.1 `db_query`

```
Tool: db_query
Description: "Execute a read-only SQL query and return results. Use for SELECT, EXPLAIN,
             and other non-mutating queries."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `sql` | `str` | Yes | — | SQL query to execute |
| `params` | `list[Any]` | No | `None` | Positional query parameters ($1, $2, ...) |
| `max_rows` | `int` | No | `100` | Maximum rows to return |
| `timeout_s` | `int` | No | `30` | Query timeout |
| `connection_name` | `str` | No | `"default"` | Named connection to use |

**Return schema:**

```json
{
  "columns": ["string"],
  "rows": [["any"]],
  "row_count": "number",
  "truncated": "boolean",
  "duration_ms": "number"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True`

#### 8.2 `db_execute`

```
Tool: db_execute
Description: "Execute a mutating SQL statement (INSERT, UPDATE, DELETE, CREATE, ALTER, DROP).
             Returns affected row count."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `sql` | `str` | Yes | — | SQL statement to execute |
| `params` | `list[Any]` | No | `None` | Positional query parameters |
| `timeout_s` | `int` | No | `30` | Statement timeout |
| `connection_name` | `str` | No | `"default"` | Named connection to use |

**Return schema:**

```json
{
  "affected_rows": "number",
  "duration_ms": "number"
}
```

**Annotations:** `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True`

#### 8.3 `db_schema`

```
Tool: db_schema
Description: "List database schemas, tables, columns, and their types. Use for understanding
             database structure before writing queries."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `schema` | `str` | No | `"public"` | Schema name to inspect |
| `table` | `str` | No | `None` | Specific table to inspect (all tables if omitted) |
| `connection_name` | `str` | No | `"default"` | Named connection to use |

**Return schema:**

```json
{
  "schema": "string",
  "tables": [
    {
      "name": "string",
      "columns": [
        {
          "name": "string",
          "type": "string",
          "nullable": "boolean",
          "default": "string | null",
          "primary_key": "boolean"
        }
      ],
      "row_count_estimate": "number",
      "indexes": [{"name": "string", "columns": ["string"], "unique": "boolean"}]
    }
  ]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True`

#### 8.4 `db_explain`

```
Tool: db_explain
Description: "Run EXPLAIN ANALYZE on a query and return the execution plan."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `sql` | `str` | Yes | — | SQL query to explain |
| `params` | `list[Any]` | No | `None` | Query parameters |
| `analyze` | `bool` | No | `True` | Run EXPLAIN ANALYZE (actually executes) vs just EXPLAIN |
| `format` | `str` | No | `"text"` | Output format: `"text"`, `"json"`, `"yaml"` |
| `connection_name` | `str` | No | `"default"` | Named connection to use |

**Return:** `{"plan": str | dict, "duration_ms": number}`

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=True`

#### 8.5 `db_connections`

```
Tool: db_connections
Description: "List configured database connections and their status."
```

**Parameters:** None.

**Return schema:**

```json
{
  "connections": [
    {
      "name": "string",
      "database": "string",
      "host": "string",
      "connected": "boolean",
      "read_only": "boolean"
    }
  ]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **Add dependency to `requirements.txt`:**
   ```
   asyncpg==0.30.0
   ```

2. **Add environment variables to `octoprox/config.py`:**
   ```python
   # Connection strings: comma-separated "name=dsn" pairs
   # Example: "default=postgresql://user:pass@host:5432/db,analytics=postgresql://..."
   DATABASE_CONNECTIONS = os.getenv("OCTOPROX_DATABASE_CONNECTIONS", "")
   DATABASE_READ_ONLY = os.getenv("OCTOPROX_DATABASE_READ_ONLY", "false").lower() == "true"
   ```

3. **Create `octoprox/tools/database.py`:**
   - Parse `DATABASE_CONNECTIONS` into a dict of `{name: dsn}`.
   - Check `ENABLE_DATABASE` AND at least one connection is configured.

4. **Implement connection pool management:**
   ```python
   import asyncpg

   _pools: dict[str, asyncpg.Pool] = {}

   async def _get_pool(connection_name: str = "default") -> asyncpg.Pool:
       if connection_name not in _pools:
           dsn = _connections.get(connection_name)
           if not dsn:
               raise ValueError(f"Unknown connection: {connection_name}")
           _pools[connection_name] = await asyncpg.create_pool(
               dsn,
               min_size=1,
               max_size=5,
               command_timeout=60,
           )
       return _pools[connection_name]
   ```

5. **Implement `db_query`:**
   - Acquire connection from pool.
   - Set `statement_timeout` to `timeout_s * 1000` ms.
   - If `DATABASE_READ_ONLY`, wrap in a read-only transaction.
   - Execute query with params.
   - Fetch up to `max_rows + 1` rows (to detect truncation).
   - Convert `asyncpg.Record` objects to plain lists.
   - Extract column names from the first record or from `statement.get_attributes()`.

6. **Implement `db_execute`:**
   - If `DATABASE_READ_ONLY`, raise error.
   - Execute statement with params.
   - Return status string (contains affected row count).

7. **Implement `db_schema`:**
   - Query `information_schema.tables` for table list.
   - Query `information_schema.columns` for column details.
   - Query `pg_indexes` for index info.
   - Query `pg_stat_user_tables` for row count estimates.

8. **Implement `db_explain`:**
   - If `analyze`: `EXPLAIN (ANALYZE, FORMAT {format}) {sql}`.
   - Else: `EXPLAIN (FORMAT {format}) {sql}`.
   - Use params.

9. **Implement `db_connections`:**
   - List all configured connections.
   - Check pool status for each.

10. **Security considerations:**
    - SQL injection is mitigated by using parameterized queries (`$1, $2` placeholders).
    - The `db_query` tool should set the transaction to read-only mode.
    - `db_execute` should be disabled when `DATABASE_READ_ONLY=true`.
    - Connection strings contain credentials — never log or return them.
    - The `db_schema` tool only returns structure, not data.
    - Consider wrapping `db_execute` mutations in explicit transactions with confirmation.

11. **Add tests:**
    - Mock `asyncpg` to test query building and result parsing.
    - Test connection string parsing.
    - Test read-only mode enforcement.
    - Test row truncation.
    - Test parameter passing.

---

## Capability 9: Memory

**File:** `octoprox/tools/memory.py`

### Overview

Provides a persistent knowledge graph for the LLM to store and retrieve entities, relations, and notes across conversation turns. Data is stored as a JSON file in the workspace for simplicity and persistence.

### Data Model

```
Entity {
  name: str (unique identifier)
  type: str (e.g., "person", "project", "concept", "task")
  observations: list[str] (facts/notes about the entity)
  created_at: str (ISO 8601)
  updated_at: str (ISO 8601)
}

Relation {
  source: str (entity name)
  relation: str (e.g., "works_on", "depends_on", "related_to")
  target: str (entity name)
}
```

### Tools to Implement

#### 9.1 `memory_upsert_entities`

```
Tool: memory_upsert_entities
Description: "Create or update entities in the memory knowledge graph. Each entity has a
             name, type, and list of observations (facts). If an entity already exists,
             new observations are appended."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `entities` | `list[dict]` | Yes | — | List of `{name, type, observations: [str]}` |

**Return:** `{"created": number, "updated": number}`

**Annotations:** `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False`

#### 9.2 `memory_add_relations`

```
Tool: memory_add_relations
Description: "Add relations between entities in the memory graph."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `relations` | `list[dict]` | Yes | — | List of `{source, relation, target}` |

**Return:** `{"added": number, "skipped": number}`

**Annotations:** `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 9.3 `memory_query`

```
Tool: memory_query
Description: "Search the memory graph by entity name, type, or observation content."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | `str` | No | `None` | Text to search in entity names, types, and observations |
| `entity_name` | `str` | No | `None` | Exact entity name lookup |
| `entity_type` | `str` | No | `None` | Filter by entity type |
| `include_relations` | `bool` | No | `True` | Include related entities |
| `max_results` | `int` | No | `20` | Maximum entities to return |

**Return schema:**

```json
{
  "entities": [
    {
      "name": "string",
      "type": "string",
      "observations": ["string"],
      "relations": [{"relation": "string", "target": "string", "direction": "out|in"}]
    }
  ],
  "total": "number"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 9.4 `memory_delete`

```
Tool: memory_delete
Description: "Delete entities and their relations from the memory graph."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `entity_names` | `list[str]` | Yes | — | Names of entities to delete |

**Return:** `{"deleted": number}`

**Annotations:** `readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False`

#### 9.5 `memory_list`

```
Tool: memory_list
Description: "List all entities in memory, optionally filtered by type."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `entity_type` | `str` | No | `None` | Filter by type |
| `limit` | `int` | No | `50` | Maximum entities to return |
| `offset` | `int` | No | `0` | Pagination offset |

**Return schema:**

```json
{
  "entities": [{"name": "string", "type": "string", "observation_count": "number"}],
  "total": "number"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **No new dependencies needed** — uses JSON file storage with `pathlib` and `json`.

2. **Create `octoprox/tools/memory.py`:**
   - Define the storage path: `WORKSPACE_ROOT / ".octoprox" / "memory.json"`.
   - On first access, create the directory and initialize empty graph if file doesn't exist.

3. **Implement storage layer:**
   ```python
   MEMORY_FILE = WORKSPACE_ROOT / ".octoprox" / "memory.json"

   def _load_graph() -> dict:
       if not MEMORY_FILE.exists():
           return {"entities": {}, "relations": []}
       return json.loads(MEMORY_FILE.read_text())

   def _save_graph(graph: dict) -> None:
       MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
       _atomic_write(MEMORY_FILE, json.dumps(graph, indent=2))
   ```

4. **Implement `memory_upsert_entities`:**
   - Load graph.
   - For each entity in input:
     - If entity name exists → append new observations (dedup).
     - If new → create entity with timestamps.
   - Save graph.
   - Return counts.

5. **Implement `memory_add_relations`:**
   - Load graph.
   - For each relation:
     - Check source and target entities exist (create stub entities if not).
     - Check for duplicate relation (skip if exists).
     - Add to relations list.
   - Save graph.

6. **Implement `memory_query`:**
   - Load graph.
   - If `entity_name`: exact lookup.
   - If `query`: fuzzy match against name, type, and observations (case-insensitive substring).
   - If `entity_type`: filter by type.
   - If `include_relations`: find all relations where entity is source or target.
   - Limit to `max_results`.

7. **Implement `memory_delete`:**
   - Load graph.
   - Remove named entities.
   - Remove all relations referencing deleted entities.
   - Save graph.

8. **Implement `memory_list`:**
   - Load graph.
   - Optional type filter.
   - Return paginated summary (name, type, observation count).

9. **Thread safety:** Use `threading.Lock()` around load/save operations to prevent corruption from concurrent tool calls.

10. **Add tests:**
    - Test CRUD operations.
    - Test query/search.
    - Test relation management.
    - Test persistence (write and re-read).
    - Test deduplication.
    - Test concurrent access (simulated).

---

## Capability 10: Time

**File:** `octoprox/tools/time.py`

### Overview

Provides time-related utilities: current time in any timezone, timezone conversions, date parsing, and formatting. Simple but essential for any LLM that needs to reason about time.

### Tools to Implement

#### 10.1 `time_now`

```
Tool: time_now
Description: "Get the current date and time in a specified timezone."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `timezone` | `str` | No | `"UTC"` | IANA timezone name (e.g., `"America/New_York"`, `"Europe/London"`) |

**Return schema:**

```json
{
  "iso": "string (ISO 8601 with timezone)",
  "unix": "number (Unix timestamp)",
  "timezone": "string",
  "utc_offset": "string (e.g., '-05:00')",
  "human": "string (e.g., 'Thursday, February 6, 2025 at 3:45 PM EST')"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False`

#### 10.2 `time_convert`

```
Tool: time_convert
Description: "Convert a datetime from one timezone to another."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `datetime` | `str` | Yes | — | ISO 8601 datetime string |
| `from_timezone` | `str` | No | `"UTC"` | Source timezone |
| `to_timezone` | `str` | Yes | — | Target timezone |

**Return schema:**

```json
{
  "original": "string (ISO 8601)",
  "converted": "string (ISO 8601)",
  "from_timezone": "string",
  "to_timezone": "string"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 10.3 `time_parse`

```
Tool: time_parse
Description: "Parse a date/time string in various formats and return a structured representation."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `text` | `str` | Yes | — | Date/time string to parse |
| `timezone` | `str` | No | `"UTC"` | Assume this timezone if none specified in the input |

**Return schema:**

```json
{
  "iso": "string",
  "unix": "number",
  "year": "number",
  "month": "number",
  "day": "number",
  "hour": "number",
  "minute": "number",
  "second": "number",
  "timezone": "string",
  "day_of_week": "string"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 10.4 `time_diff`

```
Tool: time_diff
Description: "Calculate the difference between two dates/times."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `start` | `str` | Yes | — | Start datetime (ISO 8601) |
| `end` | `str` | Yes | — | End datetime (ISO 8601) |

**Return schema:**

```json
{
  "days": "number",
  "hours": "number",
  "minutes": "number",
  "seconds": "number",
  "total_seconds": "number",
  "human": "string (e.g., '2 days, 3 hours, 15 minutes')"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 10.5 `time_list_timezones`

```
Tool: time_list_timezones
Description: "List available IANA timezone names, optionally filtered by region."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `region` | `str` | No | `None` | Filter by region (e.g., `"America"`, `"Europe"`, `"Asia"`) |

**Return:** `list[str]`

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **Add dependency to `requirements.txt`:**
   ```
   python-dateutil==2.9.0
   ```
   The `python-dateutil` library handles flexible date parsing. `zoneinfo` (stdlib in 3.9+) handles timezone conversions.

2. **Create `octoprox/tools/time.py`:**
   - Import `zoneinfo.ZoneInfo` (stdlib).
   - Import `dateutil.parser` for flexible parsing.
   - Import `datetime` from stdlib.

3. **Implement `time_now`:**
   ```python
   from zoneinfo import ZoneInfo
   from datetime import datetime

   def time_now(timezone: str = "UTC") -> dict:
       tz = ZoneInfo(timezone)
       now = datetime.now(tz)
       return {
           "iso": now.isoformat(),
           "unix": now.timestamp(),
           "timezone": timezone,
           "utc_offset": now.strftime("%z"),
           "human": now.strftime("%A, %B %-d, %Y at %-I:%M %p %Z"),
       }
   ```

4. **Implement `time_convert`:**
   - Parse input datetime.
   - Localize to `from_timezone`.
   - Convert to `to_timezone` using `.astimezone()`.

5. **Implement `time_parse`:**
   - Use `dateutil.parser.parse(text)` for flexible parsing.
   - If no timezone in input, apply the `timezone` parameter.
   - Return structured fields.

6. **Implement `time_diff`:**
   - Parse both datetimes.
   - Compute `timedelta`.
   - Decompose into days, hours, minutes, seconds.
   - Generate human-readable string.

7. **Implement `time_list_timezones`:**
   - Use `zoneinfo.available_timezones()`.
   - Sort and optionally filter by region prefix.

8. **Validate timezone names:** Wrap `ZoneInfo(tz)` in try/except to give clear error on invalid timezone.

9. **Add tests:**
   - Test `time_now` returns correct format.
   - Test `time_convert` with known conversions.
   - Test `time_parse` with various formats (ISO, RFC 2822, natural date strings).
   - Test `time_diff` with known intervals.
   - Test timezone listing and filtering.

---

## Capability 11: OpenAPI-to-MCP Adapter

**File:** `octoprox/tools/openapi.py`

### Overview

A generic adapter that loads any OpenAPI (Swagger) specification and exposes its endpoints as MCP tools. This generalizes the existing GitLab OpenAPI tools to work with any API. The LLM can discover, inspect, and call any API endpoint described by an OpenAPI spec.

### Tools to Implement

#### 11.1 `openapi_load`

```
Tool: openapi_load
Description: "Load an OpenAPI specification from a URL or inline JSON/YAML. The spec is
             cached and used by subsequent openapi_* tools. Multiple specs can be loaded
             under different names."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | Name for this API (used to reference it later) |
| `spec_url` | `str` | No | `None` | URL to fetch the OpenAPI spec from |
| `spec_content` | `str` | No | `None` | Inline OpenAPI spec (JSON or YAML) |
| `auth_header` | `str` | No | `None` | Auth header to use when calling the API (e.g., `"Bearer token123"`) |
| `auth_header_name` | `str` | No | `"Authorization"` | Header name for auth |
| `base_url_override` | `str` | No | `None` | Override the base URL in the spec |

**Return:** `{"name": str, "title": str, "version": str, "endpoint_count": int}`

**Annotations:** `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True`

#### 11.2 `openapi_list_endpoints`

```
Tool: openapi_list_endpoints
Description: "List available API endpoints from a loaded OpenAPI spec, with optional filtering."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | API name (from openapi_load) |
| `filter` | `str` | No | `None` | Filter by path/method/summary |
| `tag` | `str` | No | `None` | Filter by OpenAPI tag |
| `limit` | `int` | No | `50` | Max results |
| `offset` | `int` | No | `0` | Pagination offset |

**Return schema:**

```json
{
  "endpoints": [
    {
      "path": "string",
      "method": "string",
      "operation_id": "string | null",
      "summary": "string",
      "tags": ["string"]
    }
  ],
  "total": "number"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 11.3 `openapi_get_operation`

```
Tool: openapi_get_operation
Description: "Get the full schema details for a specific API operation, including parameters,
             request body, and response schemas."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | API name |
| `path` | `str` | Yes | — | API path |
| `method` | `str` | Yes | — | HTTP method |

**Return schema:**

```json
{
  "path": "string",
  "method": "string",
  "summary": "string",
  "description": "string | null",
  "operation_id": "string | null",
  "parameters": [
    {
      "name": "string",
      "in": "string (path|query|header|cookie)",
      "required": "boolean",
      "schema": "object",
      "description": "string | null"
    }
  ],
  "request_body": "object | null",
  "responses": "object"
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

#### 11.4 `openapi_call`

```
Tool: openapi_call
Description: "Call an API endpoint defined in a loaded OpenAPI spec. Automatically handles
             path parameters, query parameters, request body, and authentication."
```

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `name` | `str` | Yes | — | API name |
| `path` | `str` | Yes | — | API path (with `{param}` placeholders) |
| `method` | `str` | Yes | — | HTTP method |
| `path_params` | `dict[str, str]` | No | `None` | Path parameter values |
| `query_params` | `dict[str, Any]` | No | `None` | Query parameters |
| `headers` | `dict[str, str]` | No | `None` | Additional headers |
| `body` | `Any` | No | `None` | Request body (JSON-serializable) |
| `timeout_s` | `int` | No | `30` | Request timeout |
| `max_response_bytes` | `int` | No | `200000` | Max response bytes |

**Return schema:**

```json
{
  "status_code": "number",
  "headers": "object",
  "body": "any (parsed JSON or text)",
  "truncated": "boolean"
}
```

**Annotations:** `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True`

#### 11.5 `openapi_list_apis`

```
Tool: openapi_list_apis
Description: "List all currently loaded API specifications."
```

**Parameters:** None.

**Return schema:**

```json
{
  "apis": [
    {
      "name": "string",
      "title": "string",
      "version": "string",
      "base_url": "string",
      "endpoint_count": "number"
    }
  ]
}
```

**Annotations:** `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### Implementation Steps

1. **No new dependencies needed** — uses `httpx`, `yaml`, `json` already available.

2. **Create `octoprox/tools/openapi.py`:**

3. **Implement API spec storage:**
   ```python
   from cachetools import TTLCache

   @dataclasses.dataclass
   class LoadedAPI:
       name: str
       spec: dict[str, Any]
       base_url: str
       auth_header_name: str
       auth_header_value: str | None
       title: str
       version: str

   _loaded_apis: dict[str, LoadedAPI] = {}
   ```

4. **Implement `openapi_load`:**
   - If `spec_url`: fetch with httpx (validate URL, SSRF protection).
   - If `spec_content`: parse as YAML or JSON.
   - Extract title from `spec.get("info", {}).get("title", "")`.
   - Extract version from `spec.get("info", {}).get("version", "")`.
   - Determine base URL:
     - If `base_url_override`: use that.
     - Else extract from `spec.get("servers", [{}])[0].get("url", "")`.
   - Count endpoints (iterate paths × methods).
   - Store in `_loaded_apis[name]`.

5. **Implement `$ref` resolution:**
   ```python
   def _resolve_ref(spec: dict, ref: str) -> dict:
       """Resolve a $ref pointer within the OpenAPI spec."""
       parts = ref.lstrip("#/").split("/")
       current = spec
       for part in parts:
           current = current[part]
       return current

   def _deep_resolve(spec: dict, obj: Any) -> Any:
       """Recursively resolve all $ref pointers in an object."""
       if isinstance(obj, dict):
           if "$ref" in obj:
               return _deep_resolve(spec, _resolve_ref(spec, obj["$ref"]))
           return {k: _deep_resolve(spec, v) for k, v in obj.items()}
       if isinstance(obj, list):
           return [_deep_resolve(spec, item) for item in obj]
       return obj
   ```

6. **Implement `openapi_list_endpoints`:**
   - Get `_loaded_apis[name]`.
   - Iterate `spec["paths"]` items.
   - Apply filters (text search, tag filter).
   - Paginate.

7. **Implement `openapi_get_operation`:**
   - Look up path and method in the spec.
   - Resolve `$ref` pointers for parameters, requestBody, responses.
   - Return structured data.

8. **Implement `openapi_call`:**
   - Look up the API spec.
   - Build the URL: `base_url + path` with path params substituted.
   - Set query params.
   - Set auth header from loaded API config.
   - Set additional headers.
   - Make HTTP request with httpx.
   - Parse response (JSON if content-type matches, else text).
   - Truncate if needed.

9. **Implement `openapi_list_apis`:**
   - Return summary of all loaded APIs.

10. **Refactor existing GitLab tools:**
    - The existing GitLab OpenAPI tools (`gitlab_openapi_spec`, `gitlab_openapi_paths`, `gitlab_openapi_operation`) become a special case of the generic OpenAPI adapter.
    - Keep GitLab-specific tools for backwards compatibility, but internally they can delegate to the generic adapter.
    - The `gitlab_request` tool remains separate because it has GitLab-specific auth logic (PRIVATE-TOKEN vs Bearer).

11. **Add tests:**
    - Test spec loading from URL and inline content.
    - Test `$ref` resolution.
    - Test endpoint listing and filtering.
    - Test operation detail extraction.
    - Test API call construction.
    - Test auth header injection.
    - Test base URL override.

---

## Implementation Order

The capabilities should be implemented in this order, based on dependencies and value:

### Phase 0: Foundation (prerequisite for all)
1. **AD-1: Modular refactoring** — Split `app.py` into package structure.
2. **AD-2: Feature flags** — Implement `octoprox/config.py`.

### Phase 1: Core Enhancements (high value, low risk)
3. **Capability 5: Filesystem expansion** — Adds missing tools to existing capability.
4. **Capability 6: Git expansion** — Adds missing tools to existing capability.
5. **Capability 10: Time** — Simple, no external deps beyond `python-dateutil`, zero risk.

### Phase 2: Web Retrieval (most requested by LLMs)
6. **Capability 1: HTTP Fetch** — Foundation for web retrieval.
7. **Capability 3: Readability** — Lightweight page extraction built on fetch.
8. **Capability 4: Search** — Depends on SearxNG, but the tool itself is simple.

### Phase 3: Data & Memory
9. **Capability 9: Memory** — No external deps, useful for long-running agents.
10. **Capability 8: SQL Database** — Requires `asyncpg`, external PostgreSQL.

### Phase 4: Advanced
11. **Capability 11: OpenAPI Adapter** — Generalizes existing GitLab tools.
12. **Capability 7: Command Execution** — Security-sensitive, disabled by default.
13. **Capability 2: Playwright Browser** — Largest footprint, optional install.

---

## Environment Variables Summary

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOPROX_ENABLE_FETCH` | `true` | Enable HTTP fetch tools |
| `OCTOPROX_ENABLE_BROWSER` | `false` | Enable Playwright browser tools |
| `OCTOPROX_ENABLE_READABILITY` | `true` | Enable readability extraction |
| `OCTOPROX_ENABLE_SEARCH` | `true` | Enable web search |
| `OCTOPROX_ENABLE_SHELL` | `false` | Enable shell command execution |
| `OCTOPROX_ENABLE_DATABASE` | `false` | Enable SQL database tools |
| `OCTOPROX_ENABLE_MEMORY` | `true` | Enable memory/knowledge graph |
| `OCTOPROX_ENABLE_TIME` | `true` | Enable time tools |
| `OCTOPROX_ENABLE_OPENAPI` | `true` | Enable generic OpenAPI adapter |
| `OCTOPROX_ENABLE_GITLAB` | `true` | Enable GitLab-specific tools |
| `OCTOPROX_SEARXNG_URL` | `""` | SearxNG instance URL for web search |
| `OCTOPROX_DATABASE_CONNECTIONS` | `""` | Comma-separated `name=dsn` pairs |
| `OCTOPROX_DATABASE_READ_ONLY` | `false` | Restrict DB to read-only queries |
| `OCTOPROX_SHELL_ALLOWED_COMMANDS` | `""` | Comma-separated allowed shell commands (empty = all) |
| `OCTOPROX_SHELL_BLOCKED_COMMANDS` | `"rm -rf /,..."` | Comma-separated blocked patterns |
| `OCTOPROX_SHELL_MAX_TIMEOUT` | `600` | Max shell command timeout seconds |

## New Dependencies Summary

Add to `requirements.txt`:

```
# Existing
mcp==1.26.0
httpx==0.28.1
uvicorn==0.40.0
PyYAML==6.0.3
cachetools==5.5.0

# Capability 1 & 3: HTTP Fetch + Readability
beautifulsoup4==4.13.3
markdownify==0.14.1
readability-lxml==0.8.4.1
lxml==5.3.1

# Capability 8: SQL Database
asyncpg==0.30.0

# Capability 10: Time
python-dateutil==2.9.0
```

Separate `requirements-browser.txt` (optional):
```
playwright==1.49.1
```

## Dockerfile Changes

```dockerfile
FROM python:3.12-slim

ARG INSTALL_PLAYWRIGHT=false

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client patch \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Optional: Playwright
RUN if [ "$INSTALL_PLAYWRIGHT" = "true" ]; then \
      pip install --no-cache-dir playwright==1.49.1 && \
      playwright install --with-deps chromium; \
    fi

# Application code
COPY octoprox/ /app/octoprox/
COPY app.py /app/app.py

EXPOSE 7000
CMD ["sh", "-c", "uvicorn app:app --host ${MCP_BIND_HOST:-0.0.0.0} --port ${MCP_PORT:-7000}"]
```

## Testing Strategy

Each capability gets its own test file under `workspace-mcp/tests/`:

```
workspace-mcp/tests/
├── conftest.py            # Shared fixtures (mock auth, workspace root)
├── test_filesystem.py     # Capability 5
├── test_git.py            # Capability 6
├── test_fetch.py          # Capability 1
├── test_browser.py        # Capability 2
├── test_readability.py    # Capability 3
├── test_search.py         # Capability 4
├── test_shell.py          # Capability 7
├── test_database.py       # Capability 8
├── test_memory.py         # Capability 9
├── test_time.py           # Capability 10
├── test_openapi.py        # Capability 11
└── test_config.py         # Feature flags
```

All tests use mocking for external services (no network calls, no database, no Docker).

Run all tests: `cd workspace-mcp && pytest`

## Full Tool Inventory (v1.0)

| # | Tool | Capability | Type |
|---|------|-----------|------|
| 1 | `fetch_url` | 1: HTTP Fetch | Read |
| 2 | `browser_navigate` | 2: Browser | Read |
| 3 | `browser_click` | 2: Browser | Write |
| 4 | `browser_type` | 2: Browser | Write |
| 5 | `browser_screenshot` | 2: Browser | Read |
| 6 | `browser_get_content` | 2: Browser | Read |
| 7 | `browser_execute_js` | 2: Browser | Write |
| 8 | `browser_close` | 2: Browser | Write |
| 9 | `read_page` | 3: Readability | Read |
| 10 | `web_search` | 4: Search | Read |
| 11 | `fs_list` | 5: Filesystem | Read |
| 12 | `fs_read_text` | 5: Filesystem | Read |
| 13 | `fs_read_bytes` | 5: Filesystem | Read |
| 14 | `fs_write_text` | 5: Filesystem | Write |
| 15 | `fs_append` | 5: Filesystem | Write |
| 16 | `fs_delete` | 5: Filesystem | Write |
| 17 | `fs_move` | 5: Filesystem | Write |
| 18 | `fs_copy` | 5: Filesystem | Write |
| 19 | `fs_stat` | 5: Filesystem | Read |
| 20 | `fs_glob` | 5: Filesystem | Read |
| 21 | `fs_tree` | 5: Filesystem | Read |
| 22 | `fs_search` | 5: Filesystem | Read |
| 23 | `fs_patch` | 5: Filesystem | Write |
| 24 | `git` | 6: Git | Read/Write |
| 25 | `git_status` | 6: Git | Read |
| 26 | `git_diff_structured` | 6: Git | Read |
| 27 | `git_log_structured` | 6: Git | Read |
| 28 | `git_blame` | 6: Git | Read |
| 29 | `shell_exec` | 7: Shell | Write |
| 30 | `shell_which` | 7: Shell | Read |
| 31 | `db_query` | 8: Database | Read |
| 32 | `db_execute` | 8: Database | Write |
| 33 | `db_schema` | 8: Database | Read |
| 34 | `db_explain` | 8: Database | Read |
| 35 | `db_connections` | 8: Database | Read |
| 36 | `memory_upsert_entities` | 9: Memory | Write |
| 37 | `memory_add_relations` | 9: Memory | Write |
| 38 | `memory_query` | 9: Memory | Read |
| 39 | `memory_delete` | 9: Memory | Write |
| 40 | `memory_list` | 9: Memory | Read |
| 41 | `time_now` | 10: Time | Read |
| 42 | `time_convert` | 10: Time | Read |
| 43 | `time_parse` | 10: Time | Read |
| 44 | `time_diff` | 10: Time | Read |
| 45 | `time_list_timezones` | 10: Time | Read |
| 46 | `openapi_load` | 11: OpenAPI | Write |
| 47 | `openapi_list_endpoints` | 11: OpenAPI | Read |
| 48 | `openapi_get_operation` | 11: OpenAPI | Read |
| 49 | `openapi_call` | 11: OpenAPI | Write |
| 50 | `openapi_list_apis` | 11: OpenAPI | Read |
| 51 | `ssh_public_key` | SSH | Read |
| 52 | `gitlab_request` | GitLab | Write |
| 53 | `gitlab_openapi_spec` | GitLab | Read |
| 54 | `gitlab_openapi_paths` | GitLab | Read |
| 55 | `gitlab_openapi_operation` | GitLab | Read |
| 56 | `gitlab_tool_help` | GitLab | Read |

**Total: 56 tools across 13 domains.**
