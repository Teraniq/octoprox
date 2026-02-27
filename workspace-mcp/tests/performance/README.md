# MCP Endpoints Performance Testing Plan

## Overview

This document outlines the performance testing strategy for the Octoprox MCP server (`workspace-mcp`), which exposes 56+ tools via FastMCP on port 7000.

**System Under Test:**
- **Service:** workspace-mcp (FastMCP server)
- **Port:** 7000
- **Transport:** HTTP with Server-Sent Events (SSE) for streaming
- **Authentication:** Bearer token via `Authorization` header (validated against workspace-manager)

---

## 1. Test Objectives

### Primary Goals

| Objective | Description | Success Criteria |
|-----------|-------------|------------------|
| **Baseline Performance** | Establish response time baselines for all tool categories | Documented p50/p95/p99 latencies |
| **Throughput Capacity** | Determine maximum sustainable request rate | Identify breaking point and degradation curve |
| **Resource Efficiency** | Measure CPU/memory under load | <80% CPU, <2GB RAM at target load |
| **Auth Performance** | Validate token introspection caching | <10ms overhead for cached tokens |
| **Concurrent User Scaling** | Test multiple parallel workspaces | Linear scaling up to 50 concurrent users |

### Load Assumptions

| Metric | Assumed Value | Rationale |
|--------|---------------|-----------|
| Concurrent Workspaces | 10-50 | Typical team size per instance |
| Requests/Second/Workspace | 5-20 | AI agent interaction patterns |
| Peak Burst Traffic | 10x baseline | Agent batch operations |
| Token Cache Hit Rate | >90% | 60-second TTL with typical usage |

---

## 2. Endpoint Selection Strategy

### Tool Categories (56+ Tools Total)

```
┌─────────────────────────────────────────────────────────────────┐
│  MCP Tool Categories by Performance Characteristics             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TIER 1: Fast/Local (< 50ms expected)                           │
│  ├── fs_list          - Directory listing                       │
│  ├── fs_read_text     - File read (cached)                      │
│  ├── ssh_public_key   - Static key read                         │
│  └── openapi_list_apis - In-memory lookup                       │
│                                                                 │
│  TIER 2: Medium/IO Bound (50-500ms expected)                    │
│  ├── fs_write_text    - Atomic file write                       │
│  ├── fs_delete        - File deletion                           │
│  ├── git (status)     - Local git operations                    │
│  └── openapi_list_endpoints - Spec parsing                      │
│                                                                 │
│  TIER 3: Slow/External (500ms-5s expected)                      │
│  ├── git (clone)      - Network git operations                  │
│  ├── gitlab_request   - External API calls                      │
│  ├── gitlab_openapi_spec - Large spec fetch                     │
│  └── openapi_load     - Remote spec download                    │
│                                                                 │
│  TIER 4: Variable/Depends on Input                              │
│  ├── git (all others) - Command-dependent timing                │
│  └── gitlab_openapi_* - Cache-dependent                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Selected Test Endpoints

#### Read-Only Tools (Safe for Repeated Testing)

| Tool | Category | Expected Latency | Test Weight |
|------|----------|------------------|-------------|
| `fs_list` | Filesystem | 5-20ms | 30% |
| `fs_read_text` | Filesystem | 10-50ms | 20% |
| `git` (status) | Git | 50-200ms | 15% |
| `git` (log) | Git | 30-100ms | 10% |
| `openapi_list_apis` | OpenAPI | 1-5ms | 10% |
| `ssh_public_key` | SSH | 1-5ms | 5% |
| `gitlab_openapi_paths` | GitLab | 10-50ms (cached) | 10% |

#### Write Tools (Require Setup/Teardown)

| Tool | Category | Expected Latency | Isolation Strategy |
|------|----------|------------------|-------------------|
| `fs_write_text` | Filesystem | 20-100ms | Temp files per VU |
| `fs_delete` | Filesystem | 10-50ms | Cleanup after each test |
| `git` (add) | Git | 20-80ms | Staging area isolation |
| `openapi_load` | OpenAPI | 200ms-2s | Mock spec server |

---

## 3. Load Patterns

### Test Scenarios

#### Scenario A: Steady-State Normal Load

```
Concurrent Users: 10
Request Rate: 10 req/s per user (100 req/s total)
Duration: 10 minutes
Ramp-up: 30 seconds
```

**Purpose:** Validate baseline performance under expected load.

#### Scenario B: Peak Load Burst

```
Concurrent Users: 50
Request Rate: 50 req/s per user (2500 req/s total)
Duration: 5 minutes
Ramp-up: 2 minutes
```

**Purpose:** Identify saturation point and degradation behavior.

#### Scenario C: Mixed Workload Simulation

```
Read Operations: 80%
Write Operations: 20%
Think Time: 1-3 seconds between requests
Duration: 15 minutes
```

**Purpose:** Simulate realistic AI agent interaction patterns.

#### Scenario D: Cache Warmup/Cold Start

```
Sequence:
1. Burst of unique tokens (cache misses)
2. Repeated requests with same tokens (cache hits)
3. Measure cache effectiveness
```

**Purpose:** Validate token introspection caching (60s TTL).

### Load Profile Visualization

```
Requests/sec
    │
2500├──────────────────┐
    │                  ╲
100 ├──────────┐        ╲
    │          │         ╲
    │    A     │    B     ╲ C (spike)
    │          │            ╲    /
  0 ├──────────┴─────────────╲──╱────
    0s        30s           2m   15m
         Time ───────────────────────►
```

---

## 4. Metrics to Collect

### Response Time Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| p50 (Median) | 50th percentile latency | < 50ms for Tier 1 |
| p95 | 95th percentile latency | < 200ms for Tier 1 |
| p99 | 99th percentile latency | < 500ms for Tier 1 |
| Max | Maximum observed latency | < 5s (timeout threshold) |
| Std Dev | Latency variance | < 20% of mean |

### Throughput Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| RPS | Requests per second | > 100 sustained |
| Throughput | MB/s data transferred | Context-dependent |
| Success Rate | % of 2xx responses | > 99.9% |
| Error Rate | % of 4xx/5xx/timeout | < 0.1% |

### Resource Utilization

| Resource | Metric | Warning Threshold | Critical Threshold |
|----------|--------|-------------------|-------------------|
| CPU | Usage % | > 70% | > 90% |
| Memory | RSS MB | > 1.5GB | > 2.5GB |
| File Descriptors | Open count | > 800 | > 950 |
| Network | Connections | > 800 | > 950 |
| Token Cache | Hit Rate % | < 85% | < 70% |

### Custom MCP-Specific Metrics

| Metric | Source | Purpose |
|--------|--------|---------|
| Token Introspection Latency | `introspect_token()` duration | Auth overhead measurement |
| Cache Hit/Miss Ratio | `_token_cache` statistics | Cache effectiveness |
| Git Command Duration | `subprocess.run()` timing | External command overhead |
| HTTP Client Pool Wait | `httpx` connection pool | External API bottleneck |

---

## 5. Testing Tools Recommendations

### Recommended: k6 (Primary)

**Rationale:**
- Native JavaScript/TypeScript support
- Built-in HTTP/2 and SSE support
- Excellent for API load testing
- Cloud execution options
- Detailed metrics out of the box

**Installation:**
```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6
```

### Alternative: Locust (Python)

**Rationale:**
- Python-based (fits Octoprox stack)
- Web UI for real-time monitoring
- Distributed load generation
- Custom metric collection

**Installation:**
```bash
pip install locust
```

### Alternative: Apache Bench (Quick Checks)

**Rationale:**
- Simple, ubiquitous
- Good for quick baseline checks
- Limited to HTTP (no SSE/MCP protocol)

**Note:** Apache Bench only tests the HTTP transport layer, not the full MCP protocol.

### Tool Comparison

| Feature | k6 | Locust | Apache Bench |
|---------|-----|--------|--------------|
| MCP Protocol Support | Via HTTP+JSON | Via HTTP+JSON | HTTP only |
| Concurrent Users | 1000s | 1000s | Limited |
| Real-time Metrics | ✅ | ✅ | ❌ |
| Custom Scripting | JS/TS | Python | CLI args |
| Distributed Mode | ✅ | ✅ | ❌ |
| SSE Support | ✅ | Manual | ❌ |
| Recommendation | ⭐ Primary | Secondary | Quick checks |

---

## 6. Test Environment Setup

### Prerequisites

```bash
# 1. Start workspace-manager (authentication service)
cd octoprox/workspace-manager
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2. Start workspace-mcp (SUT)
cd octoprox/workspace-mcp
python -m octoprox  # Runs on port 7000

# 3. Create test workspace and obtain token
# (Via workspace-manager API or admin UI)
```

### Environment Variables

```bash
export MCP_BASE_URL="http://localhost:7000"
export MCP_AUTH_TOKEN="your-test-token-here"
export WORKSPACE_MANAGER_URL="http://localhost:8000"
```

### Test Data Preparation

```bash
# Create test workspace structure
mkdir -p /tmp/test-workspace/{src,docs,tests}
echo "Test content" > /tmp/test-workspace/README.md

# Initialize git repo for git tool tests
cd /tmp/test-workspace
git init
git config user.email "test@example.com"
git config user.name "Test User"
echo "initial" > file.txt && git add . && git commit -m "Initial"
```

---

## 7. Test Execution Plan

### Phase 1: Baseline (Week 1)

- [x] Run single-user latency tests
- [x] Document p50/p95/p99 for each tool
- [x] Identify slowest tools
- [x] Establish resource baseline

### Phase 2: Load Testing (Week 2)

- [x] Execute Scenario A (steady-state)
- [x] Execute Scenario B (peak burst)
- [x] Document breaking points
- [x] Profile resource usage

### Phase 3: Endurance (Week 3)

- [x] 4-hour sustained load test
- [x] Memory leak detection
- [x] Cache effectiveness validation
- [x] Connection pool stability

### Phase 4: Optimization (Week 4)

- [x] Address bottlenecks
- [x] Re-run critical tests
- [x] Document final baselines

---

## 8. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Test data pollution | High | Use isolated temp directories per VU |
| Git repo corruption | Medium | Use throwaway repos, reset between tests |
| Rate limiting | Medium | Add think time, use multiple test tokens |
| Token expiration | Low | Implement token refresh in test scripts |
| Resource exhaustion | High | Set resource limits, monitor closely |
| Cache invalidation | Medium | Warm cache before measurements |

---

## 9. Success Criteria Summary

| Criteria | Target | Measurement |
|----------|--------|-------------|
| p50 Latency (Tier 1) | < 50ms | k6 output |
| p95 Latency (Tier 1) | < 200ms | k6 output |
| Error Rate | < 0.1% | k6 output |
| Throughput | > 100 RPS | k6 output |
| CPU at 100 RPS | < 70% | `top`/`htop` |
| Memory Growth | < 10% over 4h | `ps` monitoring |
| Token Cache Hit Rate | > 90% | Custom metric |

---

## 10. Related Documentation

- [Baseline Expectations](./baseline.md) - Performance targets and SLOs
- [k6 Test Script](./load_test.js) - Example load test implementation
- [TOOLS.md](../../docs/TOOLS.md) - Complete tool reference
- [SECURITY.md](../../docs/SECURITY.md) - Authentication details

---

## Appendix: MCP Protocol Notes

### Authentication Flow

```
┌─────────┐         ┌─────────────┐         ┌──────────┐
│ Client  │────────▶│ workspace-  │────────▶│ workspace│
│ (k6)    │         │ manager     │         │ -mcp     │
│         │         │ (:8000)     │         │ (:7000)  │
└─────────┘         └─────────────┘         └──────────┘
      │                    │                      │
      │ 1. Get Token       │                      │
      │◀───────────────────│                      │
      │                    │                      │
      │ 2. Request + Authorization: Bearer <token> │
      │─────────────────────────────────────────────▶│
      │                    │                      │
      │                    │ 3. Introspect Token  │
      │                    │◀─────────────────────│
      │                    │                      │
      │                    │ 4. Cached Response   │
      │                    │─────────────────────▶│
      │                    │                      │
      │ 5. Tool Response   │                      │
      │◀─────────────────────────────────────────────│
```

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "fs_list",
    "arguments": {
      "path": "."
    }
  }
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[\"file1.txt\", \"dir1\"]"
      }
    ]
  }
}
```
