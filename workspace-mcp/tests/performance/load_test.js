/**
 * Octoprox MCP Server Load Test
 * 
 * This k6 script tests the performance of MCP endpoints exposed by workspace-mcp.
 * Tests include read-only tools, write tools, and authentication handling.
 * 
 * Usage:
 *   k6 run --env MCP_TOKEN=your_token load_test.js
 *   k6 run --env MCP_TOKEN=your_token --env BASE_URL=http://localhost:7000 load_test.js
 * 
 * For distributed testing:
 *   k6 cloud load_test.js
 * 
 * For different load scenarios, use stages or thresholds.
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const BASE_URL = __ENV.BASE_URL || 'http://localhost:7000';
const MCP_TOKEN = __ENV.MCP_TOKEN || '';
const WORKSPACE_ID = __ENV.WORKSPACE_ID || 'test-workspace';

// Test phases configuration
const RAMP_UP_DURATION = __ENV.RAMP_UP_DURATION || '30s';
const STEADY_STATE_DURATION = __ENV.STEADY_STATE_DURATION || '5m';
const RAMP_DOWN_DURATION = __ENV.RAMP_DOWN_DURATION || '30s';

// Load levels
const VU_COUNT = parseInt(__ENV.VU_COUNT || '10');
const MAX_VUS = parseInt(__ENV.MAX_VUS || '50');

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM METRICS
// ═══════════════════════════════════════════════════════════════════════════════

// Response time trends by tool category
const fsListTrend = new Trend('mcp_fs_list_duration');
const fsReadTrend = new Trend('mcp_fs_read_duration');
const fsWriteTrend = new Trend('mcp_fs_write_duration');
const gitStatusTrend = new Trend('mcp_git_status_duration');
const gitLogTrend = new Trend('mcp_git_log_duration');
const openapiListTrend = new Trend('mcp_openapi_list_duration');
const sshKeyTrend = new Trend('mcp_ssh_key_duration');
const gitlabPathsTrend = new Trend('mcp_gitlab_paths_duration');

// Error rates
const errorRate = new Rate('mcp_errors');
const authErrorRate = new Rate('mcp_auth_errors');
const timeoutRate = new Rate('mcp_timeouts');

// Throughput counters
const requestCount = new Counter('mcp_requests_total');
const readRequestCount = new Counter('mcp_read_requests');
const writeRequestCount = new Counter('mcp_write_requests');

// Cache effectiveness (based on response time differences)
const cacheHitTrend = new Trend('mcp_cache_hit_duration');
const cacheMissTrend = new Trend('mcp_cache_miss_duration');

// ═══════════════════════════════════════════════════════════════════════════════
// K6 OPTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export const options = {
  // Test stages: ramp-up, steady-state, ramp-down
  stages: [
    { duration: RAMP_UP_DURATION, target: VU_COUNT },           // Ramp up
    { duration: STEADY_STATE_DURATION, target: VU_COUNT },      // Steady state
    { duration: '1m', target: MAX_VUS },                        // Spike test
    { duration: '2m', target: MAX_VUS },                        // Sustained spike
    { duration: RAMP_DOWN_DURATION, target: 0 },                // Ramp down
  ],

  // Thresholds for pass/fail criteria
  thresholds: {
    // Response time thresholds
    'mcp_fs_list_duration': ['p(50)<50', 'p(95)<200', 'p(99)<500'],
    'mcp_fs_read_duration': ['p(50)<100', 'p(95)<300'],
    'mcp_git_status_duration': ['p(50)<200', 'p(95)<500'],
    
    // Error rate threshold
    'mcp_errors': ['rate<0.001'],  // Less than 0.1% errors
    
    // Overall HTTP request thresholds
    'http_req_duration': ['p(95)<1000'],
    'http_req_failed': ['rate<0.001'],
    
    // Test-wide threshold
    'checks': ['rate>0.99'],  // 99% of checks must pass
  },

  // Keep-alive connections for efficiency
  batch: 10,
  batchPerHost: 10,

  // Timeouts
  timeout: '30s',
};

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build MCP JSON-RPC request
 */
function buildMCPRequest(toolName, args, requestId) {
  return {
    jsonrpc: '2.0',
    id: requestId || randomIntBetween(1, 1000000),
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: args || {},
    },
  };
}

/**
 * Execute MCP tool call
 */
function callMCPTool(toolName, args, tag) {
  const url = `${BASE_URL}/mcp/v1/tools/call`;
  const payload = JSON.stringify(buildMCPRequest(toolName, args));
  
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${MCP_TOKEN}`,
      'X-Workspace-ID': WORKSPACE_ID,
    },
    tags: { tool: tag || toolName },
  };

  const response = http.post(url, payload, params);
  requestCount.add(1);
  
  return response;
}

/**
 * Check MCP response for errors
 */
function checkMCPResponse(response, expectedTool) {
  const checks = {
    'status is 200': (r) => r.status === 200,
    'response is valid JSON': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch (e) {
        return false;
      }
    },
    'no JSON-RPC error': (r) => {
      const body = JSON.parse(r.body);
      return !body.error;
    },
    'has result content': (r) => {
      const body = JSON.parse(r.body);
      return body.result && body.result.content;
    },
  };

  const result = check(response, checks);
  
  if (!result) {
    errorRate.add(1);
    console.error(`Error calling tool: ${expectedTool}`);
    console.error(`Status: ${response.status}, Body: ${response.body}`);
  }
  
  return result;
}

/**
 * Record timing metric for a specific tool
 */
function recordToolTiming(toolName, duration) {
  switch (toolName) {
    case 'fs_list':
      fsListTrend.add(duration);
      break;
    case 'fs_read_text':
      fsReadTrend.add(duration);
      break;
    case 'fs_write_text':
      fsWriteTrend.add(duration);
      break;
    case 'git_status':
      gitStatusTrend.add(duration);
      break;
    case 'git_log':
      gitLogTrend.add(duration);
      break;
    case 'openapi_list_apis':
      openapiListTrend.add(duration);
      break;
    case 'ssh_public_key':
      sshKeyTrend.add(duration);
      break;
    case 'gitlab_openapi_paths':
      gitlabPathsTrend.add(duration);
      break;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SETUP / TEARDOWN
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Setup function runs once per VU before iterations begin
 */
export function setup() {
  // Verify authentication
  const url = `${BASE_URL}/mcp/v1/tools/list`;
  const response = http.get(url, {
    headers: {
      'Authorization': `Bearer ${MCP_TOKEN}`,
    },
  });

  if (response.status !== 200) {
    console.error('Authentication failed or server not reachable');
    console.error(`Status: ${response.status}`);
    console.error(`Response: ${response.body}`);
    throw new Error('Setup failed: Cannot connect to MCP server');
  }

  console.log('✓ MCP server connection verified');
  console.log(`✓ Base URL: ${BASE_URL}`);
  console.log(`✓ Workspace ID: ${WORKSPACE_ID}`);
  
  // Return data for VUs
  return {
    testRunId: uuidv4(),
    startTime: new Date().toISOString(),
  };
}

/**
 * Teardown function runs once after all iterations complete
 */
export function teardown(data) {
  console.log(`\nTest run ${data.testRunId} completed`);
  console.log(`Started: ${data.startTime}`);
  console.log(`Ended: ${new Date().toISOString()}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Scenario 1: Read-Only File Operations
 * Tests fs_list and fs_read_text tools
 */
function testReadFileOperations() {
  group('Read File Operations', () => {
    // Test fs_list - list root directory
    let startTime = Date.now();
    let response = callMCPTool('fs_list', { path: '.' }, 'fs_list_root');
    let duration = Date.now() - startTime;
    fsListTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'fs_list');
    
    // Test fs_read_text - read a file
    startTime = Date.now();
    response = callMCPTool('fs_read_text', { 
      path: 'README.md',
      max_bytes: 10000 
    }, 'fs_read_text');
    duration = Date.now() - startTime;
    fsReadTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'fs_read_text');
  });
}

/**
 * Scenario 2: Write File Operations
 * Tests fs_write_text and fs_delete tools
 */
function testWriteFileOperations() {
  group('Write File Operations', () => {
    const uniqueId = uuidv4();
    const testFilePath = `test-${uniqueId}.txt`;
    const testContent = `Test content generated by k6 load test at ${new Date().toISOString()}`;
    
    // Test fs_write_text - create a file
    let startTime = Date.now();
    let response = callMCPTool('fs_write_text', {
      path: testFilePath,
      text: testContent,
      mkdirs: true,
    }, 'fs_write_text');
    let duration = Date.now() - startTime;
    fsWriteTrend.add(duration);
    writeRequestCount.add(1);
    
    checkMCPResponse(response, 'fs_write_text');
    
    // Test fs_read_text - verify write
    response = callMCPTool('fs_read_text', { path: testFilePath }, 'fs_read_verify');
    readRequestCount.add(1);
    checkMCPResponse(response, 'fs_read_text');
    
    // Cleanup - delete test file
    response = callMCPTool('fs_delete', { path: testFilePath }, 'fs_delete');
    writeRequestCount.add(1);
    checkMCPResponse(response, 'fs_delete');
  });
}

/**
 * Scenario 3: Git Operations
 * Tests git status and git log commands
 */
function testGitOperations() {
  group('Git Operations', () => {
    // Test git status
    let startTime = Date.now();
    let response = callMCPTool('git', {
      args: ['status', '--short', '--branch'],
      timeout_s: 30,
    }, 'git_status');
    let duration = Date.now() - startTime;
    gitStatusTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'git');
    
    // Test git log
    startTime = Date.now();
    response = callMCPTool('git', {
      args: ['log', '--oneline', '--max-count=10'],
      timeout_s: 30,
    }, 'git_log');
    duration = Date.now() - startTime;
    gitLogTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'git');
  });
}

/**
 * Scenario 4: OpenAPI Tools
 * Tests openapi_list_apis tool
 */
function testOpenAPITools() {
  group('OpenAPI Tools', () => {
    let startTime = Date.now();
    let response = callMCPTool('openapi_list_apis', {}, 'openapi_list_apis');
    let duration = Date.now() - startTime;
    openapiListTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'openapi_list_apis');
  });
}

/**
 * Scenario 5: SSH Tools
 * Tests ssh_public_key tool
 */
function testSSHTools() {
  group('SSH Tools', () => {
    let startTime = Date.now();
    let response = callMCPTool('ssh_public_key', {}, 'ssh_public_key');
    let duration = Date.now() - startTime;
    sshKeyTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'ssh_public_key');
  });
}

/**
 * Scenario 6: GitLab Tools
 * Tests gitlab_openapi_paths tool (cached)
 */
function testGitLabTools() {
  group('GitLab Tools', () => {
    let startTime = Date.now();
    let response = callMCPTool('gitlab_openapi_paths', {
      filter_text: 'projects',
      limit: 20,
    }, 'gitlab_openapi_paths');
    let duration = Date.now() - startTime;
    gitlabPathsTrend.add(duration);
    readRequestCount.add(1);
    
    checkMCPResponse(response, 'gitlab_openapi_paths');
  });
}

/**
 * Scenario 7: Cache Effectiveness Test
 * Makes repeated calls to measure cache performance
 */
function testCacheEffectiveness() {
  group('Cache Effectiveness', () => {
    const toolName = 'gitlab_openapi_paths';
    const args = { limit: 5 };
    
    // First call - potential cache miss
    let startTime = Date.now();
    let response = callMCPTool(toolName, args, 'cache_test');
    let duration1 = Date.now() - startTime;
    
    checkMCPResponse(response, toolName);
    
    // Small delay to simulate processing
    sleep(0.1);
    
    // Second call - should be cache hit
    startTime = Date.now();
    response = callMCPTool(toolName, args, 'cache_test');
    let duration2 = Date.now() - startTime;
    
    checkMCPResponse(response, toolName);
    
    // Record cache metrics
    cacheMissTrend.add(duration1);
    cacheHitTrend.add(duration2);
    
    // Cache should make second call faster
    if (duration2 < duration1 * 0.8) {
      // Likely cache hit
    }
  });
}

/**
 * Scenario 8: Authentication Stress
 * Tests token validation under load
 */
function testAuthenticationStress() {
  group('Authentication Stress', () => {
    // Make multiple rapid calls to test token cache
    for (let i = 0; i < 5; i++) {
      const response = callMCPTool('fs_list', { path: '.' }, 'auth_stress');
      readRequestCount.add(1);
      
      const isValid = check(response, {
        'auth: status is 200': (r) => r.status === 200,
        'auth: not 401': (r) => r.status !== 401,
        'auth: not 403': (r) => r.status !== 403,
      });
      
      if (!isValid) {
        authErrorRate.add(1);
      }
      
      // Minimal delay between rapid calls
      sleep(0.05);
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN TEST FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default exported function - executed by each VU
 * Implements a weighted random selection of test scenarios
 * to simulate realistic mixed workloads.
 */
export default function (data) {
  // Weighted random selection of test scenarios
  // These weights should match expected production usage patterns
  const rand = Math.random();
  
  if (rand < 0.30) {
    // 30% - Read file operations (most common)
    testReadFileOperations();
  } else if (rand < 0.50) {
    // 20% - Git operations
    testGitOperations();
  } else if (rand < 0.65) {
    // 15% - Write file operations
    testWriteFileOperations();
  } else if (rand < 0.80) {
    // 15% - OpenAPI tools
    testOpenAPITools();
  } else if (rand < 0.90) {
    // 10% - GitLab tools
    testGitLabTools();
  } else if (rand < 0.95) {
    // 5% - SSH tools
    testSSHTools();
  } else if (rand < 0.98) {
    // 3% - Cache effectiveness
    testCacheEffectiveness();
  } else {
    // 2% - Authentication stress
    testAuthenticationStress();
  }
  
  // Think time between requests (simulates AI agent processing)
  // Random sleep between 500ms and 2000ms
  sleep(randomIntBetween(0.5, 2));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL TEST CONFIGURATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Scenario: Read-Only Load Test
 * Export as: k6 run --env K6_SCENARIO=readonly load_test.js
 */
export function readonlyTest() {
  testReadFileOperations();
  testGitOperations();
  testOpenAPITools();
  testSSHTools();
  sleep(randomIntBetween(0.2, 1));
}

/**
 * Scenario: Write-Heavy Load Test
 * Export as: k6 run --env K6_SCENARIO=writeheavy load_test.js
 */
export function writeHeavyTest() {
  testWriteFileOperations();
  testGitOperations();
  sleep(randomIntBetween(0.5, 1.5));
}

/**
 * Scenario: Cache Performance Test
 * Export as: k6 run --env K6_SCENARIO=cache load_test.js
 */
export function cacheTest() {
  testCacheEffectiveness();
  sleep(0.5);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOCAL TESTING & DEBUG
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * For local debugging - single iteration test
 * Run with: k6 run --iterations 1 --vus 1 load_test.js
 */
if (__ENV.K6_DEBUG === 'true') {
  console.log('Debug mode enabled');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Token present: ${MCP_TOKEN ? 'Yes' : 'No'}`);
  console.log(`VU Count: ${VU_COUNT}`);
}
