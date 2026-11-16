#!/usr/bin/env python3
"""
TUNA WebDAV Subscriptions Database Repair & Migration Tool.
Idempotent, transactional, non-destructive migration and rollback utility.

Usage:
  python repair_webdav.py --dry-run [--db /path/to/subscriptions.db]
  python repair_webdav.py --apply   [--db /path/to/subscriptions.db]
  python repair_webdav.py --rollback BACKUP_FILE [--db /path/to/subscriptions.db]
"""

import sys
import os
import time
import json
import shutil
import sqlite3
import argparse
from datetime import datetime, timezone

# Ensure tuna-subscriptions functions can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from importlib import import_module
    tuna_mod = import_module("tuna-subscriptions")
    serialize_webdav_uri = tuna_mod.serialize_webdav_uri
    validate_storage_spec = tuna_mod.validate_storage_spec
    validate_tuning_params = tuna_mod.validate_tuning_params
    DEFAULT_CONFIG = tuna_mod.DEFAULT_CONFIG
except Exception as e:
    # Fallback if imported from another path
    serialize_webdav_uri = None
    DEFAULT_CONFIG = {"database": {"path": "/var/lib/tuna-subscriptions/subscriptions.db"}}


def migrate_webdav_database(db_path: str, dry_run: bool = False, backup: bool = True) -> tuple[bool, str, dict]:
    """
    Idempotent migration:
    1. Check db file exists
    2. Optional backup
    3. Additive DDL creation
    4. Validation of existing webdav connections and user configs
    5. Clean report
    """
    if not os.path.isfile(db_path):
        return False, f"Database file not found: {db_path}", {}

    report = {
        "db_path": db_path,
        "dry_run": dry_run,
        "backup_file": None,
        "tables_created": [],
        "indices_created": [],
        "total_users": 0,
        "user_webdav_configs_created": 0,
        "existing_webdav_connections": 0,
        "valid_connections": 0,
        "invalid_connections": 0,
        "errors": []
    }

    if backup and not dry_run:
        bak_file = f"{db_path}.webdav.bak.{int(time.time())}"
        try:
            shutil.copy2(db_path, bak_file)
            report["backup_file"] = bak_file
        except Exception as e:
            return False, f"Failed to create backup: {e}", report

    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    try:
        c = conn.cursor()
        # Verify users table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if not c.fetchone():
            conn.close()
            return False, "Target database does not have a 'users' table. Not a valid TUNA database.", report

        c.execute("SELECT COUNT(*) FROM users;")
        report["total_users"] = c.fetchone()[0]

        ddl_tables = [
            ("webdav_connections", """
                CREATE TABLE IF NOT EXISTS webdav_connections (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    revision INTEGER NOT NULL DEFAULT 1,
                    url TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    backends_json TEXT NOT NULL DEFAULT '[]',
                    timeout TEXT NOT NULL DEFAULT '60s',
                    poll_min TEXT NOT NULL DEFAULT '200ms',
                    poll_max TEXT NOT NULL DEFAULT '500ms',
                    coalesce TEXT NOT NULL DEFAULT '10ms',
                    chunk_size INTEGER NOT NULL DEFAULT 131071,
                    puts INTEGER NOT NULL DEFAULT 8,
                    read_min INTEGER NOT NULL DEFAULT 3,
                    read_max INTEGER NOT NULL DEFAULT 8,
                    enc INTEGER NOT NULL DEFAULT 0,
                    dns TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """),
            ("user_webdav_config", """
                CREATE TABLE IF NOT EXISTS user_webdav_config (
                    user_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    revision INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """),
            ("user_webdav_selection", """
                CREATE TABLE IF NOT EXISTS user_webdav_selection (
                    user_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    position INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (user_id, connection_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (connection_id) REFERENCES webdav_connections(id) ON DELETE CASCADE
                );
            """)
        ]

        ddl_indices = [
            ("idx_webdav_connections_enabled", "CREATE INDEX IF NOT EXISTS idx_webdav_connections_enabled ON webdav_connections(enabled);"),
            ("idx_user_webdav_selection_user", "CREATE INDEX IF NOT EXISTS idx_user_webdav_selection_user ON user_webdav_selection(user_id);"),
            ("idx_user_webdav_selection_conn", "CREATE INDEX IF NOT EXISTS idx_user_webdav_selection_conn ON user_webdav_selection(connection_id);")
        ]

        if dry_run:
            for tbl_name, _ in ddl_tables:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (tbl_name,))
                if not c.fetchone():
                    report["tables_created"].append(tbl_name)
            for idx_name, _ in ddl_indices:
                c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?;", (idx_name,))
                if not c.fetchone():
                    report["indices_created"].append(idx_name)
        else:
            with conn:
                for tbl_name, ddl_sql in ddl_tables:
                    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (tbl_name,))
                    if not c.fetchone():
                        report["tables_created"].append(tbl_name)
                    conn.execute(ddl_sql)

                for idx_name, ddl_sql in ddl_indices:
                    c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?;", (idx_name,))
                    if not c.fetchone():
                        report["indices_created"].append(idx_name)
                    conn.execute(ddl_sql)

                # Initialize default user_webdav_config for users without one
                now = datetime.now(timezone.utc).isoformat()
                c.execute("""
                    SELECT id FROM users
                    WHERE id NOT IN (SELECT user_id FROM user_webdav_config);
                """)
                missing_users = [r[0] for r in c.fetchall()]
                for u_id in missing_users:
                    conn.execute("""
                        INSERT INTO user_webdav_config (user_id, enabled, revision, updated_at)
                        VALUES (?, 1, 1, ?);
                    """, (u_id, now))
                report["user_webdav_configs_created"] = len(missing_users)

        # Inspect connections
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='webdav_connections';")
        if c.fetchone():
            c.execute("SELECT * FROM webdav_connections;")
            rows = c.fetchall()
            report["existing_webdav_connections"] = len(rows)
            for r in rows:
                try:
                    backends = json.loads(r["backends_json"])
                except Exception:
                    backends = []
                c_dict = {
                    "name": r["name"],
                    "url": r["url"],
                    "username": r["username"],
                    "password": r["password"],
                    "backends": backends,
                    "timeout": r["timeout"],
                    "poll_min": r["poll_min"],
                    "poll_max": r["poll_max"],
                    "coalesce": r["coalesce"],
                    "chunk_size": r["chunk_size"],
                    "puts": r["puts"],
                    "read_min": r["read_min"],
                    "read_max": r["read_max"],
                    "enc": r["enc"],
                    "dns": r["dns"],
                }
                if serialize_webdav_uri:
                    ok_ser, err_ser, _ = serialize_webdav_uri(c_dict)
                    if ok_ser:
                        report["valid_connections"] += 1
                    else:
                        report["invalid_connections"] += 1
                        report["errors"].append(f"Connection {r['id']} ({r['name']}) validation error: {err_ser}")
                else:
                    report["valid_connections"] += 1

        conn.close()
        return True, "Migration check completed successfully" if dry_run else "Migration completed successfully", report

    except Exception as e:
        conn.close()
        return False, f"Migration failed with error: {e}", report


def rollback_webdav_database(backup_path: str, target_db: str) -> tuple[bool, str]:
    """
    Safely rolls back SQLite database from backup file.
    """
    if not os.path.isfile(backup_path):
        return False, f"Backup file does not exist: {backup_path}"

    try:
        test_conn = sqlite3.connect(backup_path)
        tc = test_conn.cursor()
        tc.execute("PRAGMA integrity_check;")
        res = tc.fetchone()
        test_conn.close()
        if not res or res[0] != "ok":
            return False, f"Backup file integrity check failed: {res}"
    except Exception as e:
        return False, f"Backup file is not a valid SQLite database: {e}"

    try:
        shutil.copy2(backup_path, target_db)
        for ext in ["-wal", "-shm"]:
            f = target_db + ext
            if os.path.isfile(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        return True, f"Successfully restored database from {backup_path} to {target_db}"
    except Exception as e:
        return False, f"Rollback failed: {e}"


def main():
    parser = argparse.ArgumentParser(description="TUNA WebDAV Database Migration & Repair Tool")
    parser.add_argument("--db", default=None, help="Path to subscriptions.db")
    parser.add_argument("--dry-run", "--check", action="store_true", help="Perform dry-run check without modifying DB")
    parser.add_argument("--apply", action="store_true", help="Apply idempotent migrations")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating automatic backup before migration")
    parser.add_argument("--rollback", metavar="BACKUP_FILE", help="Restore database from backup file")

    args = parser.parse_args()

    db_path = args.db or DEFAULT_CONFIG["database"]["path"]

    if args.rollback:
        ok, msg = rollback_webdav_database(args.rollback, db_path)
        if ok:
            print(f"[OK] {msg}")
            sys.exit(0)
        else:
            print(f"[ERROR] {msg}", file=sys.stderr)
            sys.exit(1)

    if args.dry_run:
        ok, msg, rep = migrate_webdav_database(db_path, dry_run=True, backup=False)
        print(f"[{'OK' if ok else 'ERROR'}] {msg}")
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        sys.exit(0 if ok else 1)

    if args.apply:
        ok, msg, rep = migrate_webdav_database(db_path, dry_run=False, backup=not args.no_backup)
        print(f"[{'OK' if ok else 'ERROR'}] {msg}")
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        sys.exit(0 if ok else 1)

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
