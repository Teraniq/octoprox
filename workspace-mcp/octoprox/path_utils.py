"""Path utilities for secure filesystem operations."""
from __future__ import annotations

import os
import pathlib
import tempfile
from typing import Any

# Workspace root path
WORKSPACE_ROOT = pathlib.Path("/workspace").resolve()


def _resolve_path(path: str) -> pathlib.Path:
    """Resolve and validate a path within the workspace root.

    Security: Uses proper path comparison (not string-based) to prevent path traversal.
    Handles symlink attacks and validates path length and content.
    """
    # Validate path length to prevent DoS
    if not path:
        raise ValueError("Path cannot be empty")
    if len(path) > 4096:
        raise ValueError("Path exceeds maximum length of 4096 characters")

    # Check for null bytes which could cause issues
    if '\x00' in path:
        raise ValueError("Path contains null bytes")

    # Check for control characters
    if any(ord(c) < 32 for c in path):
        raise ValueError("Path contains control characters")

    # Resolve the path (follows symlinks)
    try:
        target = (WORKSPACE_ROOT / path).resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {e}")

    # Use proper path comparison (not string-based) to prevent traversal
    try:
        target.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise ValueError("Path escapes workspace root")

    # Additional check: ensure resolved path is still under WORKSPACE_ROOT
    # This catches symlink-based attacks where a symlink points outside
    if WORKSPACE_ROOT not in target.parents and target != WORKSPACE_ROOT:
        # Check if target is exactly WORKSPACE_ROOT or a subdirectory
        try:
            # On some systems, relative_to might behave differently
            resolved_relative = target.relative_to(WORKSPACE_ROOT)
            if str(resolved_relative).startswith('..'):
                raise ValueError("Path escapes workspace root via symlink")
        except ValueError:
            raise ValueError("Path escapes workspace root")

    return target


def _atomic_write(target: pathlib.Path, text: str) -> None:
    """Write text to a file atomically using a temporary file."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=target.parent) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name
    os.replace(temp_name, target)


__all__ = [
    "WORKSPACE_ROOT",
    "_resolve_path",
    "_atomic_write",
]