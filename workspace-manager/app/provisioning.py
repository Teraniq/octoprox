from __future__ import annotations

import logging

import docker

from .models import Workspace
from .settings import settings

logger = logging.getLogger(__name__)


class WorkspaceProvisioner:
    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self.docker = docker_client or docker.from_env()

    def _container_name(self, workspace: Workspace) -> str:
        return f"ws_{workspace.name}"

    def _volume_name(self, workspace: Workspace) -> str:
        return f"ws_{workspace.name}"

    def create_workspace(self, workspace: Workspace) -> None:
        volume_name = self._volume_name(workspace)
        try:
            self.docker.volumes.get(volume_name)
        except docker.errors.NotFound:
            self.docker.volumes.create(name=volume_name)

        container_name = self._container_name(workspace)
        labels = {
            "traefik.enable": "true",
            f"traefik.http.routers.{container_name}.rule": f"PathPrefix(`/ws/{workspace.name}`)",
            f"traefik.http.routers.{container_name}.entrypoints": "web",
            f"traefik.http.routers.{container_name}.middlewares": f"{container_name}-stripprefix",
            f"traefik.http.middlewares.{container_name}-stripprefix.stripprefix.prefixes": f"/ws/{workspace.name}",
            f"traefik.http.services.{container_name}.loadbalancer.server.port": "7000",
        }

        self.docker.containers.run(
            settings.workspace_image,
            name=container_name,
            detach=True,
            network=settings.docker_network,
            labels=labels,
            environment={
                "WORKSPACE_NAME": workspace.name,
                "WORKSPACE_OWNER_USER_ID": str(workspace.user_id),
                "MANAGER_INTROSPECT_URL": "http://workspace-manager:8000/internal/auth/introspect",
                "MCP_BIND_HOST": "0.0.0.0",
                "MCP_PORT": "7000",
            },
            volumes={volume_name: {"bind": "/workspace", "mode": "rw"}},
        )

    def delete_workspace(self, workspace: Workspace) -> None:
        container_name = self._container_name(workspace)
        try:
            container = self.docker.containers.get(container_name)
        except docker.errors.NotFound:
            return
        try:
            container.stop(timeout=10)
        finally:
            container.remove(v=True, force=True)

    def purge_workspace(self, workspace: Workspace) -> None:
        self.delete_workspace(workspace)
        self.purge_by_name(workspace.name)

    def purge_by_name(self, name: str) -> None:
        volume_name = f"ws_{name}"
        try:
            volume = self.docker.volumes.get(volume_name)
        except docker.errors.NotFound:
            return
        try:
            volume.remove(force=True)
        except docker.errors.APIError as exc:
            logger.warning("Failed to remove volume %s: %s", volume_name, exc)
