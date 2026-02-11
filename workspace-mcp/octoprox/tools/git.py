"""Git tools for version control operations."""
from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Any

from ..auth import _require_owner
from ..path_utils import WORKSPACE_ROOT

if TYPE_CHECKING:
    from .. import OctoproxMCP


# Whitelist of allowed git commands and their permitted arguments
ALLOWED_GIT_COMMANDS: dict[str, dict[str, Any]] = {
    'clone': {
        'max_args': 10,
        'allowed_prefixes': ['--depth=', '--branch=', '--single-branch', '--no-single-branch',
                             '--shallow-submodules', '--recurse-submodules', '--jobs=',
                             '--origin=', '--config=', '--'],
    },
    'pull': {
        'max_args': 5,
        'allowed_prefixes': ['--ff-only', '--no-rebase', '--rebase', '--autostash',
                             '--no-autostash', '--depth=', '--unshallow'],
    },
    'fetch': {
        'max_args': 10,
        'allowed_prefixes': ['--all', '--prune', '--prune-tags', '--depth=', '--unshallow',
                             '--force', '--tags', '--no-tags'],
    },
    'status': {
        'max_args': 5,
        'allowed_prefixes': ['--short', '--branch', '--porcelain', '--untracked-files=',
                             '--ignored'],
    },
    'log': {
        'max_args': 10,
        'allowed_prefixes': ['--oneline', '--max-count=', '--since=', '--until=',
                             '--author=', '--grep=', '--all', '--graph', '--decorate'],
    },
    'diff': {
        'max_args': 10,
        'allowed_prefixes': ['--cached', '--staged', '--stat', '--numstat', '--name-only',
                             '--name-status', '--check'],
    },
    'show': {
        'max_args': 5,
        'allowed_prefixes': ['--stat', '--name-only', '--format=', '--quiet'],
    },
    'branch': {
        'max_args': 10,
        'allowed_prefixes': ['--list', '--all', '--remote', '--merged', '--no-merged',
                             '--contains=', '--format=', '-d', '-D', '-m', '-M'],
    },
    'checkout': {
        'max_args': 5,
        'allowed_prefixes': ['-b', '-B', '--track', '--no-track', '--orphan',
                             '--ours', '--theirs', '--merge', '-f', '--force'],
    },
    'add': {
        'max_args': 50,
        'allowed_prefixes': ['-A', '--all', '-u', '--update', '-f', '--force', '-n', '--dry-run'],
    },
    'reset': {
        'max_args': 5,
        'allowed_prefixes': ['--soft', '--mixed', '--hard', '--keep', '--merge',
                             '--', 'HEAD', 'HEAD~'],
    },
    'commit': {
        'max_args': 10,
        'allowed_prefixes': ['-m', '--message=', '--amend', '--no-edit', '--all', '-a',
                             '--signoff', '--no-verify'],
    },
    'push': {
        'max_args': 10,
        'allowed_prefixes': ['--all', '--tags', '--force', '-f', '--force-with-lease',
                             '--set-upstream', '-u', '--delete', '-d'],
    },
    'remote': {
        'max_args': 10,
        'allowed_prefixes': ['-v', '--verbose', 'add', 'remove', 'rm', 'rename',
                             'set-url', 'get-url', 'show', 'prune'],
    },
    'config': {
        'max_args': 5,
        'allowed_prefixes': ['--global', '--local', '--system', '--list', '--get',
                             '--add', '--unset', 'user.name', 'user.email', 'core.',
                             'remote.', 'branch.', 'credential.'],
    },
    'init': {
        'max_args': 5,
        'allowed_prefixes': ['--bare', '--quiet', '-q', '--initial-branch=', '--shared'],
    },
}

# Characters that could be used for shell injection
SHELL_INJECTION_CHARS = set(';|&$`\n\r<>!{}[]')


def _validate_git_args(command: str, args: list[str]) -> None:
    """Validate git command arguments against whitelist.

    Raises ValueError if any argument is not allowed.
    """
    if command not in ALLOWED_GIT_COMMANDS:
        raise ValueError(f"Git command '{command}' is not in the allowed whitelist. "
                        f"Allowed commands: {list(ALLOWED_GIT_COMMANDS.keys())}")

    config = ALLOWED_GIT_COMMANDS[command]
    max_args = config['max_args']
    allowed_prefixes = config['allowed_prefixes']

    if len(args) > max_args:
        raise ValueError(f"Too many arguments for '{command}': {len(args)} > {max_args}")

    for arg in args:
        # Check for shell injection characters
        if any(c in arg for c in SHELL_INJECTION_CHARS):
            raise ValueError(f"Argument contains invalid characters: {arg[:50]}")

        # Check for command substitution attempts
        if '$(' in arg or '`' in arg:
            raise ValueError(f"Argument contains command substitution: {arg[:50]}")

        # Check argument against allowed prefixes
        # Special case: file paths (anything not starting with -)
        if not arg.startswith('-'):
            # This is likely a file path or ref name - allow it
            # but still check for injection patterns
            if '..' in arg and '...' not in arg:
                # Could be path traversal - check it's not trying to escape
                if '../' in arg or '..\\' in arg:
                    raise ValueError(f"Path traversal detected in argument: {arg[:50]}")
            continue

        # Check if argument starts with any allowed prefix
        is_allowed = any(
            arg == prefix or arg.startswith(prefix)
            for prefix in allowed_prefixes
        )
        if not is_allowed:
            raise ValueError(f"Argument not allowed for '{command}': {arg[:50]}. "
                           f"Allowed prefixes: {allowed_prefixes}")


def register_git_tools(mcp: "OctoproxMCP") -> None:
    """Register git tools with the MCP server."""

    @mcp.tool()
    def git(args: list[str], timeout_s: int = 120) -> dict[str, Any]:
        """Execute git commands within the workspace.

        Only whitelisted commands are allowed. Arguments are validated to prevent
        command injection attacks.
        """
        _require_owner()

        # Validate timeout
        if not isinstance(timeout_s, int) or timeout_s < 1 or timeout_s > 300:
            raise ValueError("timeout_s must be an integer between 1 and 300")

        # Extract command and validate
        if not args:
            raise ValueError("No git command provided")

        command = args[0]
        command_args = args[1:] if len(args) > 1 else []

        # Validate arguments against whitelist
        _validate_git_args(command, command_args)

        # Build command (safe - no shell=True)
        cmd = ["git", "-C", str(WORKSPACE_ROOT), command] + command_args
        env = os.environ.copy()
        env["HOME"] = str(WORKSPACE_ROOT / ".home")
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + str(WORKSPACE_ROOT / ".ssh" / "known_hosts")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_s,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }