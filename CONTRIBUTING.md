# Contributing to Workspace MCP Hub

Thank you for your interest in contributing to Workspace MCP Hub! This document provides guidelines and instructions for development.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Architecture Decisions](#architecture-decisions)

## Development Setup

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- Git

### Local Development Environment

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd workspace-mcp-hub
   ```

2. **Set up Python virtual environment (for testing)**
   ```bash
   cd workspace-manager
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   cd ..
   ```

3. **Build Docker images**
   ```bash
   docker compose --profile build build
   ```

4. **Run the stack locally**
   ```bash
   export BOOTSTRAP_ADMIN_USERNAME=admin
   export BOOTSTRAP_ADMIN_PASSWORD=admin
   export SECRET_KEY=dev-secret-key-change-in-production
   export PUBLIC_BASE_URL=http://localhost:8080
   docker compose up -d
   ```

5. **Access the application**
   - UI: http://localhost:8080/app
   - Login with bootstrap credentials

### Development Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me` | Session signing key (change in production!) |
| `DATABASE_URL` | `sqlite:///./data/manager.db` | Database connection string |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | External URL for generated links |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | Initial admin username |
| `BOOTSTRAP_ADMIN_PASSWORD` | `admin` | Initial admin password |
| `WORKSPACE_IMAGE` | `mcp-gitfs:latest` | Docker image for workspace containers |
| `DOCKER_NETWORK` | `mcpnet` | Docker network for workspaces |
| `PURGE_INTERVAL_SECONDS` | `300` | Interval for cleanup jobs |

## Project Structure

```
workspace-mcp-hub/
├── docker-compose.yml          # Production orchestration
├── README.md                   # User documentation
├── CONTRIBUTING.md            # This file
├── .cursorrules               # Cursor IDE rules
├── .kilocode/rules            # Kilo Code AI assistant rules
├── workspace-manager/         # Main FastAPI application
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py           # HTTP routes and handlers
│   │   ├── models.py         # SQLAlchemy database models
│   │   ├── auth.py           # Authentication utilities
│   │   ├── db.py             # Database configuration
│   │   ├── services.py       # Business logic layer
│   │   ├── provisioning.py   # Docker container management
│   │   ├── settings.py       # Configuration management
│   │   ├── static/           # CSS, images
│   │   └── templates/        # Jinja2 HTML templates
│   ├── tests/                # pytest test suite
│   ├── Dockerfile
│   └── requirements.txt
├── workspace-mcp/            # MCP server implementation
│   ├── app.py               # FastMCP tools and server
│   ├── Dockerfile
│   └── requirements.txt
└── client/                   # Example client implementations
    ├── mcp_client.py        # Streamable HTTP MCP client
    └── temporal_activities.py # Temporal workflow activities
```

## Running Tests

### Unit Tests

The project uses pytest for testing. Tests use an in-memory SQLite database and fake provisioners to avoid Docker dependencies.

```bash
cd workspace-manager
pytest
```

### Test Coverage

To run tests with coverage:

```bash
cd workspace-manager
pytest --cov=app --cov-report=term-missing
```

### Writing Tests

Tests are located in `workspace-manager/tests/`. Use the following patterns:

```python
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app import auth, services
from app.db import Base
from app.models import User, Workspace


class FakeProvisioner:
    """Mock provisioner for testing without Docker."""
    
    def __init__(self) -> None:
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.purged: list[str] = []

    def create_workspace(self, workspace: Workspace) -> None:
        self.created.append(workspace.name)

    def delete_workspace(self, workspace: Workspace) -> None:
        self.deleted.append(workspace.name)

    def purge_workspace(self, workspace: Workspace) -> None:
        self.purged.append(workspace.name)


def build_session() -> Session:
    """Create an in-memory database session for testing."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, future=True)()


def test_feature() -> None:
    db = build_session()
    # Create test data
    user = User(username="test", password_hash=auth.hash_password("pass"), role="user")
    db.add(user)
    db.commit()
    
    # Test functionality
    provisioner = FakeProvisioner()
    result = services.create_workspace(db, provisioner, user, "test-ws")
    
    # Assert expectations
    assert result.name == "test-ws"
    assert "test-ws" in provisioner.created
```

### Integration Tests

For tests requiring Docker, mark them explicitly:

```python
import pytest

@pytest.mark.integration
def test_docker_provisioning():
    # This test requires Docker daemon
    pass
```

Run integration tests separately:

```bash
pytest -m integration
```

## Code Style Guidelines

### Python Style

- **Python 3.12+** is required
- Use `from __future__ import annotations` at the top of every Python file
- Follow PEP 8 with these additions:
  - Line length: 100 characters maximum
  - Use double quotes for strings

### Type Hints

All functions must have type hints:

```python
from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session

def create_workspace(
    db: Session,
    provisioner: WorkspaceProvisioner,
    user: User,
    name: str,
) -> Workspace:
    """Create a new workspace for the user."""
    pass
```

### SQLAlchemy 2.0 Patterns

Use the new SQLAlchemy 2.0 style:

```python
from sqlalchemy import select
from sqlalchemy.orm import Mapped, mapped_column

# Model definition
class User(Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)

# Query style
result = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
```

### Import Ordering

1. `from __future__ import annotations`
2. Standard library imports
3. Third-party imports
4. Local application imports

Example:

```python
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from fastapi import FastAPI
from sqlalchemy import select

from . import auth
from .db import SessionLocal
```

### Naming Conventions

- **Functions/Methods**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: `_leading_underscore`
- **Variables**: Descriptive names, avoid abbreviations

### Documentation

- All public functions should have docstrings
- Use Google-style docstrings:

```python
def validate_workspace_name(db: Session, name: str) -> tuple[bool, str]:
    """Validate a workspace name.
    
    Args:
        db: Database session
        name: Proposed workspace name
        
    Returns:
        Tuple of (is_valid, message)
    """
    pass
```

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following style guidelines
   - Add tests for new functionality
   - Update documentation if needed

3. **Run tests locally**
   ```bash
   cd workspace-manager
   pytest
   ```

4. **Commit your changes**
   - Use clear, descriptive commit messages
   - Reference issues if applicable

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **PR Requirements**
   - All tests must pass
   - Code review approval required
   - No merge conflicts
   - Documentation updated if needed

### PR Checklist

Before submitting:

- [ ] Tests added for new functionality
- [ ] All tests pass (`pytest`)
- [ ] Type hints on all functions
- [ ] `from __future__ import annotations` included
- [ ] No hardcoded secrets or credentials
- [ ] Error handling implemented
- [ ] Docstrings added for public functions
- [ ] Code follows project style guidelines

## Architecture Decisions

### Why FastAPI?

FastAPI was chosen for:
- Native async support
- Automatic OpenAPI documentation
- Type hint validation
- HTMX-friendly (server-rendered HTML)
- Performance

### Why SQLAlchemy 2.0?

SQLAlchemy 2.0 provides:
- Modern type-safe ORM
- Better async support
- Cleaner query syntax
- Mapped column types

### Why Docker per Workspace?

Each workspace runs in its own container for:
- **Isolation**: Workspaces cannot access each other's files
- **Resource limits**: Can apply CPU/memory constraints per workspace
- **Security**: Container boundaries provide defense in depth
- **Scalability**: Easy to distribute across hosts

### Why Traefik?

Traefik handles:
- Dynamic routing based on container labels
- Automatic service discovery
- Path prefix stripping
- Future TLS termination support

### Why Session-based Auth for UI?

- Simple and secure for browser-based UI
- No token management needed for HTML endpoints
- Works well with HTMX partial updates

### Why Bearer Tokens for MCP?

- Stateless authentication
- Works with MCP protocol
- Easy to configure in client applications
- Tokens can be revoked independently

### Soft Delete Pattern

Workspaces use soft delete for:
- Recovery from accidental deletion
- Audit trail preservation
- Graceful cleanup with purge job

The purge job runs every 5 minutes (configurable) to permanently delete workspaces marked for deletion 24+ hours ago.

### User Deactivation vs Deletion

Users are deactivated, not deleted:
- Preserves audit trail
- Allows account recovery
- Prevents username reuse attacks
- Stops all workspaces on deactivation

## Security Considerations

### API Key Handling

- Keys are shown only once at creation
- Only prefix and hash stored in database
- Argon2 hashing for verification
- Keys invalidated when user is deactivated

### Path Traversal Protection

All filesystem operations use `_resolve_path()`:

```python
def _resolve_path(path: str) -> pathlib.Path:
    target = (WORKSPACE_ROOT / path).resolve()
    if not str(target).startswith(str(WORKSPACE_ROOT)):
        raise ValueError("Path escapes workspace")
    return target
```

### Container Isolation

- Each workspace has its own volume
- Containers run on isolated Docker network
- No host filesystem access except workspace volume
- Workspace name validation prevents injection

## Getting Help

- Review [README.md](README.md) for usage instructions
- Check [.cursorrules](.cursorrules) for coding patterns
- Check [.kilocode/rules](.kilocode/rules) for AI assistant guidance
- Open an issue for bugs or feature requests

## License

[Add your license information here]
