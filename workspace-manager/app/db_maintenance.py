from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

from .settings import settings

logger = logging.getLogger(__name__)

# Expected database schema definition
EXPECTED_SCHEMA: dict[str, list[str]] = {
    "users": [
        "id",
        "username",
        "password_hash",
        "role",
        "status",
        "created_at",
        "updated_at",
        "nexusgate_user_id",
        "nexusgate_role",
        "last_synced_at",
    ],
    "api_keys": [
        "id",
        "user_id",
        "key_prefix",
        "key_hash",
        "created_at",
        "last_used_at",
        "nexusgate_token_id",
        "name",
        "expires_at",
    ],
    "workspaces": [
        "id",
        "user_id",
        "name",
        "status",
        "created_at",
        "deleted_at",
        "purge_after",
        "updated_at",
        "metadata",
        "nexusgate_service_id",
        "container_id",
        "container_status",
    ],
}


def _extract_sqlite_path(database_url: str) -> Path | None:
    """Extract the SQLite file path from a database URL.

    Args:
        database_url: SQLAlchemy database URL (e.g., sqlite:///./data/manager.db)

    Returns:
        Path to the SQLite file, or None if not a SQLite URL
    """
    if not database_url.startswith("sqlite:///"):
        return None

    # Handle both absolute (sqlite:////) and relative (sqlite:///./) paths
    if database_url.startswith("sqlite:////"):
        # Absolute path
        path_str = database_url[10:]
    else:
        # Relative path (sqlite:///./data/manager.db)
        path_str = database_url[10:]

    return Path(path_str).resolve()


def backup_database(
    database_path: str | None = None,
    backup_dir: str | Path | None = None,
) -> Path:
    """Create a timestamped backup of the SQLite database.

    Args:
        database_path: Path to the database file. If None, uses settings.database_url.
        backup_dir: Directory to store backups. If None, uses same directory as database.

    Returns:
        Path to the created backup file

    Raises:
        ValueError: If database_path is not a SQLite database
        FileNotFoundError: If source database file doesn't exist
    """
    # Determine source database path
    if database_path is None:
        db_path = _extract_sqlite_path(settings.database_url)
        if db_path is None:
            raise ValueError(
                f"Cannot backup non-SQLite database: {settings.database_url}"
            )
    else:
        db_path = Path(database_path).resolve()

    if not db_path.exists():
        raise FileNotFoundError(f"Database file not found: {db_path}")

    # Determine backup directory
    if backup_dir is None:
        backup_path = db_path.parent
    else:
        backup_path = Path(backup_dir).resolve()
        backup_path.mkdir(parents=True, exist_ok=True)

    # Generate timestamped backup filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{db_path.name}.backup.{timestamp}"
    backup_file = backup_path / backup_filename

    # Copy the database file
    shutil.copy2(db_path, backup_file)

    logger.info(
        "Database backup created",
        extra={
            "source": str(db_path),
            "backup": str(backup_file),
            "timestamp": timestamp,
        },
    )

    return backup_file


def verify_database_schema(
    database_url: str | None = None,
) -> dict[str, Any]:
    """Verify that the database schema matches expected structure.

    Args:
        database_url: Database URL to check. If None, uses settings.database_url.

    Returns:
        Dictionary with validation results:
        - valid: bool - Whether schema is valid
        - issues: list[str] - List of any issues found
        - tables_checked: list[str] - List of tables that were checked
        - tables_found: list[str] - List of tables found in database
    """
    if database_url is None:
        database_url = settings.database_url

    issues: list[str] = []
    tables_checked: list[str] = []

    try:
        engine = create_engine(database_url)
        inspector = inspect(engine)

        # Get all tables in the database
        tables_found = inspector.get_table_names()

        # Check each expected table
        for table_name, expected_columns in EXPECTED_SCHEMA.items():
            tables_checked.append(table_name)

            if table_name not in tables_found:
                issues.append(f"Missing table: {table_name}")
                continue

            # Get actual columns for this table
            actual_columns = [col["name"] for col in inspector.get_columns(table_name)]

            # Check for missing columns
            for column in expected_columns:
                if column not in actual_columns:
                    issues.append(f"Missing column: {table_name}.{column}")

            # Check for unexpected columns (optional - just log)
            unexpected = set(actual_columns) - set(expected_columns)
            if unexpected:
                logger.debug(
                    "Unexpected columns found in %s: %s",
                    table_name,
                    ", ".join(unexpected),
                )

        engine.dispose()

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "tables_checked": tables_checked,
            "tables_found": tables_found,
        }

    except Exception as e:
        logger.exception("Error verifying database schema")
        return {
            "valid": False,
            "issues": [f"Error during verification: {e!s}"],
            "tables_checked": tables_checked,
            "tables_found": [],
        }


def test_database_connectivity(
    database_url: str | None = None,
) -> dict[str, Any]:
    """Test database connectivity and measure response time.

    Args:
        database_url: Database URL to test. If None, uses settings.database_url.

    Returns:
        Dictionary with connectivity results:
        - connected: bool - Whether connection succeeded
        - response_time_ms: float - Response time in milliseconds
        - error: str | None - Error message if connection failed
    """
    if database_url is None:
        database_url = settings.database_url

    import time

    start_time = time.perf_counter()

    try:
        engine = create_engine(database_url)

        # Try to connect and execute a simple query
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.scalar()

        end_time = time.perf_counter()
        response_time_ms = (end_time - start_time) * 1000

        engine.dispose()

        logger.debug(
            "Database connectivity test passed",
            extra={"response_time_ms": response_time_ms},
        )

        return {
            "connected": True,
            "response_time_ms": round(response_time_ms, 2),
            "error": None,
        }

    except Exception as e:
        end_time = time.perf_counter()
        response_time_ms = (end_time - start_time) * 1000

        logger.exception("Database connectivity test failed")

        return {
            "connected": False,
            "response_time_ms": round(response_time_ms, 2),
            "error": str(e),
        }
