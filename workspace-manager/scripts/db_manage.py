#!/usr/bin/env python3
"""Database management CLI script for workspace-manager.

This script provides commands for database maintenance:
- backup: Create a timestamped backup of the database
- verify: Verify database schema integrity
- health: Check database connectivity and health

Usage:
    python scripts/db_manage.py backup
    python scripts/db_manage.py verify
    python scripts/db_manage.py health
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path to allow importing app modules
script_dir = Path(__file__).parent.resolve()
project_dir = script_dir.parent
sys.path.insert(0, str(project_dir))

from app.db_maintenance import (
    backup_database,
    test_database_connectivity,
    verify_database_schema,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("db_manage")


def cmd_backup(args: argparse.Namespace) -> int:
    """Create a database backup.
    
    Args:
        args: Command line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        database_path = args.database
        backup_dir = args.backup_dir
        
        logger.info("Creating database backup...")
        backup_path = backup_database(
            database_path=database_path,
            backup_dir=backup_dir,
        )
        
        print(f"✓ Backup created successfully")
        print(f"  Backup path: {backup_path}")
        
        # Get file size
        size_bytes = backup_path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        print(f"  Size: {size_mb:.2f} MB")
        
        return 0
        
    except FileNotFoundError as e:
        logger.error("Database file not found: %s", e)
        print(f"✗ Error: Database file not found - {e}")
        return 1
    except ValueError as e:
        logger.error("Invalid database URL: %s", e)
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        logger.exception("Failed to create backup")
        print(f"✗ Error: Failed to create backup - {e}")
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify database schema integrity.
    
    Args:
        args: Command line arguments
        
    Returns:
        Exit code (0 for valid, 1 for invalid/error)
    """
    try:
        logger.info("Verifying database schema...")
        result = verify_database_schema(database_url=args.database)
        
        print(f"\nDatabase Schema Verification")
        print(f"{'=' * 40}")
        print(f"Valid: {'✓ Yes' if result['valid'] else '✗ No'}")
        print(f"Tables checked: {', '.join(result['tables_checked'])}")
        print(f"Tables found: {', '.join(result['tables_found'])}")
        
        if result['issues']:
            print(f"\nIssues found ({len(result['issues'])}):")
            for issue in result['issues']:
                print(f"  - {issue}")
        else:
            print("\nNo issues found!")
        
        return 0 if result['valid'] else 1
        
    except Exception as e:
        logger.exception("Failed to verify schema")
        print(f"✗ Error: Failed to verify schema - {e}")
        return 1


def cmd_health(args: argparse.Namespace) -> int:
    """Check database connectivity and health.
    
    Args:
        args: Command line arguments
        
    Returns:
        Exit code (0 for connected, 1 for error)
    """
    try:
        logger.info("Testing database connectivity...")
        result = test_database_connectivity(database_url=args.database)
        
        print(f"\nDatabase Health Check")
        print(f"{'=' * 40}")
        print(f"Connected: {'✓ Yes' if result['connected'] else '✗ No'}")
        print(f"Response time: {result['response_time_ms']:.2f} ms")
        
        if result['error']:
            print(f"\nError: {result['error']}")
        
        return 0 if result['connected'] else 1
        
    except Exception as e:
        logger.exception("Failed to check health")
        print(f"✗ Error: Failed to check health - {e}")
        return 1


def main() -> int:
    """Main entry point for the CLI.
    
    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description="Database management utility for workspace-manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s backup                    # Create a backup using default settings
  %(prog)s backup --database ./data/manager.db  # Backup specific database
  %(prog)s verify                    # Verify schema integrity
  %(prog)s health                    # Check database connectivity
        """,
    )
    
    parser.add_argument(
        "--database",
        help="Database URL or path (default: from settings)",
        default=None,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Backup command
    backup_parser = subparsers.add_parser(
        "backup",
        help="Create a timestamped backup of the database",
    )
    backup_parser.add_argument(
        "--backup-dir",
        help="Directory to store backups (default: same as database)",
        default=None,
    )
    backup_parser.set_defaults(func=cmd_backup)
    
    # Verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify database schema integrity",
    )
    verify_parser.set_defaults(func=cmd_verify)
    
    # Health command
    health_parser = subparsers.add_parser(
        "health",
        help="Check database connectivity and health",
    )
    health_parser.set_defaults(func=cmd_health)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
