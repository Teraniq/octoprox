from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .. import OctoproxMCP


@dataclass(frozen=True)
class ToolCatalogEntry:
    tool_id: str
    provider: str
    tool_class: str
    operations: tuple[str, ...]
    risk_class: str
    required_claims: tuple[str, ...]
    supports_readonly: bool
    evidence_kind: str
    description: str | None = None


_TOOL_CATALOG: dict[str, ToolCatalogEntry] = {}


def catalog_tool(
    mcp: "OctoproxMCP",
    *,
    tool_id: str,
    provider: str,
    tool_class: str,
    operations: Sequence[str],
    risk_class: str,
    required_claims: Sequence[str] | None = None,
    supports_readonly: bool,
    evidence_kind: str,
    name: str | None = None,
    description: str | None = None,
    **tool_kwargs: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    normalized_claims = tuple(required_claims or ("workspace.owner_or_admin",))
    normalized_operations = tuple(
        str(item).strip() for item in operations if str(item).strip()
    )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        resolved_name = name or fn.__name__
        _TOOL_CATALOG[resolved_name] = ToolCatalogEntry(
            tool_id=tool_id,
            provider=provider,
            tool_class=tool_class,
            operations=normalized_operations,
            risk_class=risk_class,
            required_claims=normalized_claims,
            supports_readonly=supports_readonly,
            evidence_kind=evidence_kind,
            description=description or fn.__doc__,
        )
        return mcp.tool(name=resolved_name, description=description, **tool_kwargs)(fn)

    return decorator


def get_tool_catalog() -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for tool_name in sorted(_TOOL_CATALOG):
        entry = _TOOL_CATALOG[tool_name]
        payload = asdict(entry)
        payload["operations"] = list(entry.operations)
        payload["required_claims"] = list(entry.required_claims)
        catalog.append(payload)
    return catalog


__all__ = ["ToolCatalogEntry", "catalog_tool", "get_tool_catalog"]
