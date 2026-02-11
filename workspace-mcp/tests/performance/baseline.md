# MCP Endpoints Performance Baseline & SLOs

## Executive Summary

This document defines the performance baselines, Service Level Objectives (SLOs), and error rate thresholds for the Octoprox MCP server. These targets are derived from:
- Tool complexity analysis
- External dependency requirements
- Resource constraints
- User experience expectations

---

## 1. Service Level Objectives (SLOs)

### Overall System SLOs

| Metric | Target | Measurement Window | Compliance Target |
|--------|--------|-------------------|-------------------|
| **Availability** | 99.9% | 30 days | 99.9% of requests succeed |
| **Error Rate** | < 0.1% | 5 minutes | 99.9% of requests return 2xx |
| **P50 Latency** | < 100ms | 1 hour | 50% of requests under 100ms |
| **P95 Latency** | < 500ms | 1 hour | 95% of requests under 500ms |
| **P99 Latency** | < 2000ms | 1 hour | 99% of requests under 2s |

### SLO Rationale

```
┌────────────────────────────────────────────────────────────────────┐
│  Latency Budget Analysis                                           │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Target P95: 500ms                                                  │
│  ═══════════════════════════════════════════════════════════════   │
│                                                                    │
│  Component Breakdown:                                               │
│  ├─ Network RTT (localhost)                    ~ 1ms               │
│  ├─ FastMCP framework overhead                 ~ 5-10ms            │
│  ├─ Authentication (cached token)              ~ 5-15ms            │
│  ├─ Tool execution (Tier 1 - simple)           ~ 20-50ms           │
│  ├─ Tool execution (Tier 2 - medium)           ~ 50-200ms          │
│  └─ Tool execution (Tier 3 - complex)          ~ 200-400ms         │
│                                                                    │
│  Headroom for degradation                      ~ 50-100ms          │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Tool-Specific Performance Baselines

### Tier 1: Fast/Local Operations (< 50ms target)

These tools perform simple, local operations with no external dependencies.

| Tool | p50 Target | p95 Target | p99 Target | Notes |
|------|------------|------------|------------|-------|
| `fs_list` | 10ms | 25ms | 50ms | Directory listing, cached by OS |
| `fs_read_text` (small) | 15ms | 35ms | 75ms | < 10KB files, filesystem cache |
| `ssh_public_key` | 2ms | 5ms | 10ms | Static file read |
| `openapi_list_apis` | 5ms | 10ms | 25ms | In-memory dictionary lookup |

**Load Assumptions:**
- Filesystem operations assume warm OS cache
- Target assumes workspace with < 1000 files
- No concurrent modifications during read

### Tier 2: Medium/IO Bound Operations (50-200ms target)

These tools involve moderate I/O or processing.

| Tool | p50 Target | p95 Target | p99 Target | Notes |
|------|------------|------------|------------|-------|
| `fs_read_text` (large) | 50ms | 150ms | 300ms | Up to 200KB default limit |
| `fs_write_text` | 30ms | 100ms | 200ms | Atomic write via temp file |
| `fs_delete` | 20ms | 50ms | 100ms | File or directory removal |
| `git status` | 80ms | 200ms | 400ms | Depends on repo state |
| `git log` | 50ms | 150ms | 300ms | `--max-count` limits impact |
| `git diff` | 60ms | 180ms | 350ms | Depends on change size |
| `openapi_list_endpoints` | 40ms | 100ms | 200ms | Spec parsing + filtering |
| `gitlab_openapi_paths` | 30ms | 80ms | 150ms | Cached spec access |

**Load Assumptions:**
- Git operations assume repos < 100MB
- Git status assumes < 1000 modified files
- OpenAPI specs assume < 10MB YAML

### Tier 3: Slow/External Operations (200ms-5s target)

These tools depend on external resources and have variable latency.

| Tool | p50 Target | p95 Target | p99 Target | Notes |
|------|------------|------------|------------|-------|
| `git clone` | 2000ms | 5000ms | 10000ms | Network + disk bound |
| `git pull` | 1500ms | 4000ms | 8000ms | Network dependent |
| `git fetch` | 1000ms | 3000ms | 6000ms | Network dependent |
| `gitlab_request` | 500ms | 1500ms | 3000ms | GitLab API latency |
| `gitlab_openapi_spec` | 300ms | 800ms | 1500ms | Cache miss = fetch |
| `openapi_load` (URL) | 500ms | 1500ms | 3000ms | Network fetch |
| `gitlab_openapi_operation` | 50ms | 150ms | 300ms | After spec cached |

**Load Assumptions:**
- Network latency to git remotes: < 100ms
- GitLab API response time: < 500ms p95
- OpenAPI spec download: < 2MB specs

### Tier 4: Variable/Context-Dependent

| Tool | p50 Target | p95 Target | Notes |
|------|------------|------------|-------|
| `git add` | 30ms | 100ms | Depends on file count |
| `git commit` | 100ms | 300ms | Depends on commit size |
| `git push` | 1000ms | 3000ms | Network + repo size |
| `git checkout` | 200ms | 800ms | Depends on file changes |

---

## 3. Throughput Targets

### Sustained Throughput

| Metric | Target | Conditions |
|--------|--------|------------|
| **Requests/Second (Total)** | 100 RPS | Mixed workload, 10 concurrent users |
| **Requests/Second (Peak)** | 250 RPS | Burst capacity, < 30s duration |
| **Read Operations/Second** | 150 RPS | 80% of total traffic |
| **Write Operations/Second** | 30 RPS | 20% of total traffic |
| **Git Operations/Second** | 20 RPS | Includes network latency |

### Concurrent User Capacity

| Metric | Target | Notes |
|--------|--------|-------|
| **Active Workspaces** | 50 | Concurrently active |
| **Requests/Minute/User** | 600 | 10 req/s average per user |
| **Connection Pool Size** | 100 | HTTP client connections |
| **Token Cache Entries** | 1000 | 60s TTL per entry |

### Throughput Calculation

```
┌─────────────────────────────────────────────────────────────────────┐
│  Capacity Planning Model                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Assumptions:                                                        │
│  • Average response time: 150ms                                      │
│  • Target concurrency: 50 users                                      │
│  • Each user: 10 req/s average                                       │
│                                                                      │
│  Required Capacity:                                                  │
│  • 50 users × 10 req/s = 500 req/s theoretical max                  │
│                                                                      │
│  Practical Limits:                                                   │
│  • Token introspection: 1000 cache entries, 60s TTL                 │
│  • HTTP client pool: 100 connections                                │
│  • File descriptor limit: 1024 (default)                            │
│                                                                      │
│  Recommended Target:                                                 │
│  • Sustained: 100 RPS (conservative, 2x headroom)                   │
│  • Burst: 250 RPS (short duration)                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Error Rate Thresholds

### HTTP Status Code Targets

| Status Code Range | Target Rate | Action Threshold |
|-------------------|-------------|------------------|
| 2xx (Success) | > 99.9% | - |
| 4xx (Client Error) | < 0.05% | > 0.1% alert |
| 401/403 (Auth Error) | < 0.01% | > 0.05% critical |
| 5xx (Server Error) | < 0.01% | > 0.05% critical |
| Timeout | < 0.05% | > 0.1% alert |

### Tool-Specific Error Thresholds

| Tool Category | Expected Error Rate | Notes |
|---------------|---------------------|-------|
| Filesystem (read) | < 0.01% | File not found = expected |
| Filesystem (write) | < 0.1% | Permission errors possible |
| Git (local) | < 0.1% | Invalid commands, repo issues |
| Git (network) | < 1% | Network failures, auth issues |
| GitLab API | < 2% | External service dependency |
| OpenAPI | < 0.5% | Invalid specs, network issues |

### Error Budget

```
Monthly Error Budget (99.9% availability):
├── Total Requests: ~260M (100 RPS × 30 days)
├── Allowed Errors: ~260,000 requests
├── Daily Budget: ~8,700 errors
└── Burst Allowance: 50% of daily budget

Alerting Thresholds:
├── Warning: 50% of daily budget consumed
├── Critical: 80% of daily budget consumed
└── Emergency: 100% of daily budget consumed
```

---

## 5. Resource Utilization Targets

### CPU Usage

| Metric | Warning | Critical | Max Acceptable |
|--------|---------|----------|----------------|
| Average CPU | > 60% | > 80% | < 90% |
| Peak CPU (burst) | > 80% | > 95% | < 100% |
| CPU per 100 RPS | - | - | < 50% |

### Memory Usage

| Metric | Warning | Critical | Max Acceptable |
|--------|---------|----------|----------------|
| RSS Memory | > 1GB | > 1.5GB | < 2GB |
| Memory Growth (4h) | > 10% | > 25% | < 50% |
| Per-Workspace Overhead | - | - | < 50MB |

### Network & Connections

| Metric | Warning | Critical | Max Acceptable |
|--------|---------|----------|----------------|
| Open File Descriptors | > 800 | > 950 | < 1024 |
| HTTP Client Connections | > 80 | > 95 | < 100 |
| Network RX/TX | > 10MB/s | > 50MB/s | < 100MB/s |

### Token Cache Performance

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| Cache Hit Rate | > 95% | < 90% | < 80% |
| Cache Eviction Rate | < 1/min | > 5/min | > 10/min |
| Avg Token Lookup | < 5ms | > 10ms | > 50ms |

---

## 6. Test Environment Specifications

### Baseline Test Environment

```yaml
Hardware:
  CPU: 2 cores (shared)
  RAM: 2GB
  Disk: SSD with 1000 IOPS
  Network: Localhost/Internal (< 1ms RTT)

Software:
  Python: 3.11+
  FastMCP: Latest
  uvicorn: 1 worker process
  
Test Data:
  Workspace Size: 100MB
  File Count: 1000 files
  Git Commits: 100 commits
  OpenAPI Spec: 1MB YAML
```

### Production Reference Environment

```yaml
Recommended Production:
  CPU: 4 cores dedicated
  RAM: 4GB
  Disk: SSD with 3000+ IOPS
  Network: < 10ms RTT to workspace-manager
  
Scaling:
  Horizontal: Multiple MCP instances behind load balancer
  Vertical: Increase CPU/RAM per instance
  Sharding: Workspaces distributed across instances
```

---

## 7. Performance Regression Thresholds

### Regression Detection

| Metric | Warning | Critical | Block Release |
|--------|---------|----------|---------------|
| p50 Latency | > 20% increase | > 50% increase | > 100% increase |
| p95 Latency | > 30% increase | > 75% increase | > 150% increase |
| Error Rate | > 2x baseline | > 5x baseline | > 10x baseline |
| Throughput | > 10% decrease | > 25% decrease | > 50% decrease |
| Memory Usage | > 20% increase | > 50% increase | > 100% increase |

### Benchmark History

| Date | Version | p50 (fs_list) | p95 (fs_list) | RPS | Notes |
|------|---------|---------------|---------------|-----|-------|
| TBD | v1.0.0 | - | - | - | Initial baseline |

---

## 8. Monitoring & Alerting

### Key Metrics to Monitor

```python
# Application Metrics (from MCP server)
MCP_REQUEST_DURATION_SECONDS  # Histogram by tool name
MCP_REQUESTS_TOTAL            # Counter by status code
MCP_ACTIVE_CONNECTIONS        # Gauge
MCP_TOKEN_CACHE_HITS          # Counter
MCP_TOKEN_CACHE_MISSES        # Counter
MCP_GIT_COMMAND_DURATION      # Histogram by command

# System Metrics (from host)
CPU_USAGE_PERCENT
MEMORY_USAGE_BYTES
FILE_DESCRIPTORS_OPEN
NETWORK_CONNECTIONS_ACTIVE
HTTP_CLIENT_POOL_WAIT_TIME
```

### Recommended Alert Rules

```yaml
# Critical Alerts
groups:
  - name: mcp_critical
    rules:
      - alert: MCPHighErrorRate
        expr: rate(mcp_requests_total{status=~"4xx|5xx"}[5m]) > 0.001
        for: 2m
        severity: critical
        
      - alert: MCPHighLatency
        expr: histogram_quantile(0.95, mcp_request_duration_seconds) > 0.5
        for: 5m
        severity: warning
        
      - alert: MCPTokenCacheLowHitRate
        expr: mcp_token_cache_hits / (mcp_token_cache_hits + mcp_token_cache_misses) < 0.9
        for: 10m
        severity: warning
        
      - alert: MCPHighMemoryUsage
        expr: process_resident_memory_bytes > 1.5e9  # 1.5GB
        for: 5m
        severity: critical
```

---

## 9. Tuning Recommendations

### For 100 RPS Target

```python
# Token cache settings
TOKEN_CACHE_TTL = 60  # seconds (current)
TOKEN_CACHE_MAXSIZE = 1000  # entries (current)

# HTTP client settings
HTTP_CLIENT_TIMEOUT = 30  # seconds
HTTP_CLIENT_MAX_CONNECTIONS = 100
HTTP_CLIENT_KEEPALIVE = 20

# Uvicorn settings
UVICORN_WORKERS = 1  # Increase if CPU bound
UVICORN_TIMEOUT = 30  # seconds
```

### Scaling Guidelines

| Target RPS | Workers | RAM | Notes |
|------------|---------|-----|-------|
| 100 | 1 | 2GB | Baseline |
| 200 | 2 | 4GB | CPU bound |
| 500 | 4 | 8GB | Load balancer needed |
| 1000+ | 8+ | 16GB+ | Horizontal scaling |

---

## 10. Related Documentation

- [Performance Testing Plan](./README.md) - Test methodology
- [k6 Load Test Script](./load_test.js) - Test implementation
- [TOOLS.md](../../docs/TOOLS.md) - Complete tool reference
- [SECURITY.md](../../docs/SECURITY.md) - Authentication details

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | TBD | TBD | Initial baseline definition |
