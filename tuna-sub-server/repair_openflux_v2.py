#!/usr/bin/env python3
"""
Скрипт безопасного исправления и миграции базы данных OpenFlux v2 для TUNA 1.1.43-rc8.
Выполняет:
- Создание резервной копии SQLite БД (subscriptions.db.bak.<timestamp>)
- Разделение объединенных через запятую URL в таблице openflux_groups (urls_json) на массив строк
- Проверку корректности структуры URL и соответствия режимам classic / multistream
- Атомарное обновление ревизий только для затронутых пользователей
- Идемпотентность: повторный запуск не вносит изменений и не увеличивает revision
- Поддержку --dry-run (только отчет без записи)
- Поддержку отката --rollback <файл_бэкапа>
"""

import sys
import os
import re
import json
import uuid
import time
import shutil
import sqlite3
import argparse
import datetime
from urllib.parse import urlparse

# Импорт базовой логики валидации и восстановления из tuna-subscriptions, если доступно
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from tuna_subscriptions import (
        repair_openflux_v2_database,
        rollback_openflux_v2_database,
        validate_openflux_url,
        ALLOWED_OPENFLUX_MODES,
        ALLOWED_OPENFLUX_TRANSPORTS
    )
except ImportError:
    # Fallback импорт при именовании файла через дефис (tuna-subscriptions.py)
    import importlib.util
    sub_py = os.path.join(SCRIPT_DIR, "tuna-subscriptions.py")
    if os.path.isfile(sub_py):
        spec = importlib.util.spec_from_file_location("tuna_subscriptions", sub_py)
        tuna_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tuna_mod)
        repair_openflux_v2_database = tuna_mod.repair_openflux_v2_database
        rollback_openflux_v2_database = tuna_mod.rollback_openflux_v2_database
        validate_openflux_url = tuna_mod.validate_openflux_url
        ALLOWED_OPENFLUX_MODES = tuna_mod.ALLOWED_OPENFLUX_MODES
        ALLOWED_OPENFLUX_TRANSPORTS = tuna_mod.ALLOWED_OPENFLUX_TRANSPORTS
    else:
        repair_openflux_v2_database = None
        rollback_openflux_v2_database = None

DEFAULT_DB_PATHS = [
    "/var/lib/tuna-subscriptions/subscriptions.db",
    os.path.join(SCRIPT_DIR, "subscriptions.db"),
    "subscriptions.db"
]

def find_default_db() -> str:
    for p in DEFAULT_DB_PATHS:
        if os.path.isfile(p):
            return p
    return DEFAULT_DB_PATHS[0]

def run_dry_run_inspection(db_path: str):
    print(f"[*] Анализ базы данных (режим dry-run, без записи): {db_path}")
    if not os.path.isfile(db_path):
        print(f"[!] Файл базы данных не найден: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='openflux_groups';")
    if not c.fetchone():
        print("[!] Таблица openflux_groups отсутствует в базе данных.")
        conn.close()
        return

    c.execute("SELECT * FROM openflux_groups;")
    groups = c.fetchall()
    print(f"[*] Всего групп OpenFlux в каталоге: {len(groups)}")

    groups_needing_repair = []
    for g in groups:
        gid = g["id"]
        try:
            urls = json.loads(g["urls_json"])
        except Exception:
            urls = []
        needs_split = False
        parts_count = 0
        for item in urls:
            if isinstance(item, str) and "," in item:
                needs_split = True
                parts_count += len([p for p in item.split(",") if p.strip()])
            else:
                parts_count += 1
        if needs_split:
            groups_needing_repair.append({
                "id": gid,
                "name": g["name"],
                "mode": g["mode"],
                "transport": g["transport"],
                "current_count": len(urls),
                "after_split_count": parts_count
            })

    if not groups_needing_repair:
        print("[✓] Все группы OpenFlux имеют корректный разделенный формат URL. Исправление не требуется.")
    else:
        print(f"[!] Обнаружено групп со склеенными через запятую URL: {len(groups_needing_repair)}")
        for grp in groups_needing_repair:
            print(f"  - [{grp['id']}] {grp['name']} ({grp['mode']}, {grp['transport']}): "
                  f"текущих элементов: {grp['current_count']} -> после разделения: {grp['after_split_count']}")

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_metadata';")
    if c.fetchone():
        c.execute("SELECT value FROM server_metadata WHERE key = 'wire_format_v2_rc8_migrated';")
        m = c.fetchone()
        migrated = bool(m and m["value"] == "1")
        print(f"[*] Флаг миграции wire-формата v2 (tuna.openflux.bundle): {'Установлен' if migrated else 'Не установлен (требуется миграция)'}")

    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Утилита миграции и исправления базы данных OpenFlux v2 (TUNA 1.1.43-rc8)")
    parser.add_argument("--db", default=find_default_db(), help="Путь к файлу SQLite subscriptions.db")
    parser.add_argument("--dry-run", action="store_true", help="Проверить базу данных без внесения изменений")
    parser.add_argument("--no-backup", action="store_true", help="Не создавать резервную копию базы данных")
    parser.add_argument("--rollback", metavar="BACKUP_FILE", help="Откатить базу данных из указанной резервной копии")

    args = parser.parse_args()

    if args.rollback:
        if rollback_openflux_v2_database:
            ok, msg = rollback_openflux_v2_database(args.rollback, args.db)
            if ok:
                print(f"[OK] {msg}")
                sys.exit(0)
            else:
                print(f"[ERROR] {msg}", file=sys.stderr)
                sys.exit(1)
        else:
            try:
                shutil.copy2(args.rollback, args.db)
                print(f"[OK] База данных успешно восстановлена из {args.rollback}")
                sys.exit(0)
            except Exception as e:
                print(f"[ERROR] Ошибка восстановления: {e}", file=sys.stderr)
                sys.exit(1)

    if args.dry_run:
        run_dry_run_inspection(args.db)
        sys.exit(0)

    print(f"[*] Запуск процедуры исправления базы данных: {args.db}")
    if repair_openflux_v2_database:
        ok, msg, details = repair_openflux_v2_database(args.db, backup=not args.no_backup)
        if ok:
            print(f"[OK] {msg}")
            print(json.dumps(details, indent=2, ensure_ascii=False))
            sys.exit(0)
        else:
            print(f"[ERROR] {msg}", file=sys.stderr)
            print(json.dumps(details, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)
    else:
        print("[ERROR] Не удалось загрузить процедуру repair_openflux_v2_database из tuna-subscriptions", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
