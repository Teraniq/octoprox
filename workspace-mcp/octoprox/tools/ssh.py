"""SSH tools for key management."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

from ..auth import _require_owner
from ..path_utils import WORKSPACE_ROOT

if TYPE_CHECKING:
    from .. import OctoproxMCP


def _ensure_ssh_key() -> None:
    """Ensure SSH key pair exists in the workspace."""
    ssh_dir = WORKSPACE_ROOT / ".ssh"
    private_key = ssh_dir / "id_ed25519"
    public_key = ssh_dir / "id_ed25519.pub"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    if not private_key.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(private_key), "-N", ""],
            check=False,
        )
    known_hosts = ssh_dir / "known_hosts"
    if shutil.which("ssh-keyscan"):
        result = subprocess.run(
            ["ssh-keyscan", "-t", "rsa", "gitlab.com"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.stdout:
            known_hosts.write_text(result.stdout)


def register_ssh_tools(mcp: "OctoproxMCP") -> None:
    """Register SSH tools with the MCP server."""

    @mcp.tool()
    def ssh_public_key() -> str:
        """Get the SSH public key for this workspace."""
        _require_owner()
        public_key = WORKSPACE_ROOT / ".ssh" / "id_ed25519.pub"
        if not public_key.exists():
            return ""
        return public_key.read_text()


# Initialize SSH keys on module load
_ensure_ssh_key()