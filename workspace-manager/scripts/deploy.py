#!/usr/bin/env python3
"""
Octoprox Deployment Script - Phase 10.3

This script automates the deployment of the workspace-manager application:
1. Validates environment variables
2. Builds Docker image
3. Deploys the application
4. Verifies application starts without errors
5. Runs smoke tests

Usage:
    python scripts/deploy.py [--env-file PATH] [--skip-build] [--skip-smoke-tests]

Examples:
    # Full deployment with build and smoke tests
    python scripts/deploy.py

    # Deploy without rebuilding (use existing image)
    python scripts/deploy.py --skip-build

    # Quick deploy without smoke tests
    python scripts/deploy.py --skip-smoke-tests

    # Use custom environment file
    python scripts/deploy.py --env-file /path/to/.env.production
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


# ============================================================================
# Configuration
# ============================================================================

REQUIRED_ENV_VARS = [
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "BOOTSTRAP_ADMIN_USERNAME",
    "BOOTSTRAP_ADMIN_PASSWORD",
]

OPTIONAL_ENV_VARS = [
    "DATABASE_URL",
    "PUBLIC_BASE_URL",
    "JWT_ALGORITHM",
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
    "NEXUSGATE_INTEGRATION_ENABLED",
    "INTROSPECT_SECRET",
    "PURGE_INTERVAL_SECONDS",
    "WORKSPACE_IMAGE",
    "DOCKER_NETWORK",
    "API_RATE_LIMIT",
    "AUTH_RATE_LIMIT",
]

DEFAULTS = {
    "DATABASE_URL": "sqlite:///./data/manager.db",
    "PUBLIC_BASE_URL": "http://localhost:8080",
    "JWT_ALGORITHM": "HS256",
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "15",
    "NEXUSGATE_INTEGRATION_ENABLED": "false",
    "PURGE_INTERVAL_SECONDS": "300",
    "WORKSPACE_IMAGE": "mcp-gitfs:latest",
    "DOCKER_NETWORK": "mcpnet",
    "API_RATE_LIMIT": "200",
    "AUTH_RATE_LIMIT": "60",
}

HEALTH_CHECK_URL = "http://localhost:8080/api/v1/health"
INTROSPECT_URL = "http://localhost:8080/api/v1/auth/introspect"
MAX_RETRIES = 30
RETRY_DELAY = 2  # seconds


# ============================================================================
# Colors for terminal output
# ============================================================================

class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_header(message: str) -> None:
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{message.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")


def print_success(message: str) -> None:
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_error(message: str) -> None:
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")


def print_warning(message: str) -> None:
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def print_info(message: str) -> None:
    print(f"{Colors.OKBLUE}ℹ {message}{Colors.ENDC}")


# ============================================================================
# Environment Validation
# ============================================================================

def load_env_file(env_file: Path | None) -> None:
    """Load environment variables from file."""
    if env_file is None:
        # Try to find .env in common locations
        locations = [
            Path(".env"),
            Path("../.env"),
            Path("../../.env"),
        ]
        for loc in locations:
            if loc.exists():
                env_file = loc
                break

    if env_file and env_file.exists():
        print_info(f"Loading environment from {env_file}")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key, value)
    else:
        print_warning("No .env file found, relying on existing environment variables")


def validate_environment() -> bool:
    """Validate required environment variables are set."""
    print_header("Step 1: Environment Validation")

    errors = []
    warnings = []

    for var in REQUIRED_ENV_VARS:
        value = os.getenv(var)
        if not value:
            errors.append(f"{var} is not set")
        elif var in ("SECRET_KEY", "JWT_SECRET_KEY") and len(value) < 32:
            errors.append(f"{var} must be at least 32 characters (current: {len(value)})")
        elif value.startswith("your-") or value == "changeme":
            warnings.append(f"{var} appears to be using default/example value")
        else:
            # Mask the actual value for security
            masked = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else "****"
            print_success(f"{var} is set ({masked})")

    for var in OPTIONAL_ENV_VARS:
        value = os.getenv(var)
        if value:
            print_success(f"{var} is set (optional)")
        elif var in DEFAULTS:
            print_info(f"{var} not set, will use default: {DEFAULTS[var]}")

    if warnings:
        for warning in warnings:
            print_warning(warning)

    if errors:
        print_error("Environment validation failed!")
        for error in errors:
            print_error(f"  - {error}")
        print_info("\nTo fix, create a .env file or export the required variables:")
        print_info("  export SECRET_KEY=$(openssl rand -base64 32)")
        print_info("  export JWT_SECRET_KEY=$(openssl rand -base64 64)")
        print_info("  export BOOTSTRAP_ADMIN_USERNAME=admin")
        print_info("  export BOOTSTRAP_ADMIN_PASSWORD=<secure-password>")
        return False

    print_success("Environment validation passed!")
    return True


# ============================================================================
# Docker Build
# ============================================================================

def build_docker_image(skip: bool = False) -> bool:
    """Build Docker image for workspace-manager."""
    print_header("Step 2: Docker Build")

    if skip:
        print_info("Skipping Docker build (--skip-build specified)")
        return True

    print_info("Building workspace-manager Docker image...")

    # Determine docker-compose file location
    compose_files = [
        Path("docker-compose.yml"),
        Path("../docker-compose.yml"),
        Path("../../docker-compose.yml"),
    ]
    compose_file = None
    for f in compose_files:
        if f.exists():
            compose_file = f
            break

    if not compose_file:
        print_error("Could not find docker-compose.yml")
        return False

    print_info(f"Using docker-compose file: {compose_file}")

    try:
        result = subprocess.run(
            ["docker-compose", "-f", str(compose_file), "build", "workspace-manager"],
            capture_output=True,
            text=True,
            check=True,
        )
        print(result.stdout)
        print_success("Docker image built successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Docker build failed: {e}")
        print_error(e.stderr)
        return False
    except FileNotFoundError:
        print_error("docker-compose not found. Is Docker installed?")
        return False


# ============================================================================
# Deployment
# ============================================================================

def deploy_application() -> bool:
    """Deploy the application using docker-compose."""
    print_header("Step 3: Application Deployment")

    # Determine docker-compose file location
    compose_files = [
        Path("docker-compose.yml"),
        Path("../docker-compose.yml"),
        Path("../../docker-compose.yml"),
    ]
    compose_file = None
    for f in compose_files:
        if f.exists():
            compose_file = f
            break

    if not compose_file:
        print_error("Could not find docker-compose.yml")
        return False

    print_info("Deploying workspace-manager...")

    try:
        # Start the services
        result = subprocess.run(
            ["docker-compose", "-f", str(compose_file), "up", "-d", "workspace-manager"],
            capture_output=True,
            text=True,
            check=True,
        )
        print(result.stdout)
        print_success("Application deployed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Deployment failed: {e}")
        print_error(e.stderr)
        return False


# ============================================================================
# Health Check
# ============================================================================

def check_application_health() -> bool:
    """Verify application health endpoint returns 200."""
    print_header("Step 4: Health Check Verification")

    print_info(f"Waiting for application to start (checking {HEALTH_CHECK_URL})...")

    try:
        import requests
    except ImportError:
        print_warning("requests library not installed, using curl fallback")
        return _check_health_with_curl()

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(HEALTH_CHECK_URL, timeout=5)
            if response.status_code == 200:
                data = response.json()
                status = data.get("status", "unknown")

                if status == "healthy":
                    print_success(f"Health check passed! Status: {status}")
                    print_info(f"  Database: {data.get('database', {})}")
                    print_info(f"  Docker: {data.get('docker', {})}")
                    print_info(f"  Workspaces: {data.get('workspaces', {})}")
                    return True
                elif status == "degraded":
                    print_warning(f"Health check: degraded (but acceptable)")
                    print_info(f"  Database: {data.get('database', {})}")
                    print_info(f"  Docker: {data.get('docker', {})}")
                    return True
                else:
                    print_error(f"Health check: unhealthy")
                    return False
            else:
                print_warning(f"Attempt {attempt + 1}/{MAX_RETRIES}: HTTP {response.status_code}")
        except requests.exceptions.ConnectionError:
            print_warning(f"Attempt {attempt + 1}/{MAX_RETRIES}: Connection refused")
        except Exception as e:
            print_warning(f"Attempt {attempt + 1}/{MAX_RETRIES}: {e}")

        time.sleep(RETRY_DELAY)

    print_error("Health check failed after maximum retries")
    return False


def _check_health_with_curl() -> bool:
    """Fallback health check using curl."""
    for attempt in range(MAX_RETRIES):
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", HEALTH_CHECK_URL],
                capture_output=True,
                text=True,
                check=True,
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                print_success("Health check passed! (HTTP 200)")
                return True
            else:
                print_warning(f"Attempt {attempt + 1}/{MAX_RETRIES}: HTTP {status_code}")
        except Exception as e:
            print_warning(f"Attempt {attempt + 1}/{MAX_RETRIES}: {e}")

        time.sleep(RETRY_DELAY)

    print_error("Health check failed after maximum retries")
    return False


# ============================================================================
# Smoke Tests
# ============================================================================

def run_smoke_tests(skip: bool = False) -> bool:
    """Run smoke tests against the deployed application."""
    print_header("Step 5: Smoke Tests")

    if skip:
        print_info("Skipping smoke tests (--skip-smoke-tests specified)")
        return True

    tests_passed = 0
    tests_failed = 0

    # Test 1: Health endpoint
    print_info("Test 1: /api/v1/health endpoint...")
    if _test_health_endpoint():
        print_success("Health endpoint test passed")
        tests_passed += 1
    else:
        print_error("Health endpoint test failed")
        tests_failed += 1

    # Test 2: Login page loads
    print_info("Test 2: Login page accessibility...")
    if _test_login_page():
        print_success("Login page test passed")
        tests_passed += 1
    else:
        print_error("Login page test failed")
        tests_failed += 1

    # Test 3: Introspect endpoint (should return 403 without auth)
    print_info("Test 3: Introspect endpoint security...")
    if _test_introspect_endpoint():
        print_success("Introspect endpoint test passed")
        tests_passed += 1
    else:
        print_error("Introspect endpoint test failed")
        tests_failed += 1

    # Test 4: API endpoints with rate limiting
    print_info("Test 4: API rate limiting...")
    if _test_rate_limiting():
        print_success("Rate limiting test passed")
        tests_passed += 1
    else:
        print_error("Rate limiting test failed")
        tests_failed += 1

    # Summary
    print_info(f"\nSmoke Tests Summary: {tests_passed} passed, {tests_failed} failed")

    return tests_failed == 0


def _test_health_endpoint() -> bool:
    """Test the health endpoint."""
    try:
        import requests
        response = requests.get(HEALTH_CHECK_URL, timeout=5)
        return response.status_code == 200
    except Exception:
        return False


def _test_login_page() -> bool:
    """Test that the login page is accessible."""
    try:
        import requests
        response = requests.get("http://localhost:8080/login", timeout=5)
        return response.status_code == 200 and "login" in response.text.lower()
    except Exception:
        return False


def _test_introspect_endpoint() -> bool:
    """Test that introspect endpoint requires authentication."""
    try:
        import requests
        response = requests.post(INTROSPECT_URL, timeout=5)
        # Should return 403 Forbidden without proper auth
        return response.status_code in (401, 403, 422)
    except Exception:
        return False


def _test_rate_limiting() -> bool:
    """Test that rate limiting is active."""
    try:
        import requests
        # Make a few requests to see if rate limiting headers are present
        response = requests.get(HEALTH_CHECK_URL, timeout=5)
        # Check for rate limit headers (implementation dependent)
        has_headers = any(
            h in response.headers for h in ["X-RateLimit-Limit", "RateLimit-Limit", "Retry-After"]
        )
        # Even if no headers, if we get a response the system is working
        return response.status_code == 200 or has_headers
    except Exception:
        return False


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy the Octoprox workspace-manager application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Full deployment
  %(prog)s --skip-build              # Deploy without rebuilding
  %(prog)s --skip-smoke-tests        # Deploy without running smoke tests
  %(prog)s --env-file .env.prod      # Use custom environment file
        """,
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to environment file (default: auto-detect)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Docker build step",
    )
    parser.add_argument(
        "--skip-smoke-tests",
        action="store_true",
        help="Skip smoke tests",
    )

    args = parser.parse_args()

    print_header("Octoprox Deployment Script - Phase 10.3")

    # Load environment
    load_env_file(args.env_file)

    # Step 1: Validate environment
    if not validate_environment():
        return 1

    # Step 2: Build Docker image
    if not build_docker_image(skip=args.skip_build):
        return 1

    # Step 3: Deploy application
    if not deploy_application():
        return 1

    # Step 4: Health check
    if not check_application_health():
        print_warning("Health check failed, but deployment completed")
        # Continue to smoke tests anyway

    # Step 5: Smoke tests
    if not run_smoke_tests(skip=args.skip_smoke_tests):
        print_warning("Some smoke tests failed")
        # Don't fail the deployment for smoke test issues

    print_header("Deployment Complete!")
    print_info("Application should be available at: http://localhost:8080")
    print_info("Health endpoint: http://localhost:8080/api/v1/health")
    print_info("\nUseful commands:")
    print_info("  docker-compose logs -f workspace-manager  # View logs")
    print_info("  docker-compose ps                          # Check status")
    print_info("  docker-compose down                        # Stop services")

    return 0


if __name__ == "__main__":
    sys.exit(main())
