#!/usr/bin/env python3
"""
TUNA Subscription Server (tuna-subscriptions)
Автономный, легковесный локальный HTTP-сервис подписок для панели TUNA.
Реализация на стандартной библиотеке Python 3 (Zero Dependencies).
"""

import sys
import os
import re
import json
import uuid
import base64
import hashlib
import secrets
import sqlite3
import datetime
import time
import shutil
import ipaddress
import tuna_connection_groups
from tuna_connection_groups import Store as ConnectionGroupStore
from tuna_connection_groups import Invalid as InvalidConnectionGroups, validate as validate_connection_groups, snapshot as connection_groups_snapshot
from tuna_connection_groups import GROUP_URI_PREFIX
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
from urllib.parse import urlparse, unquote, parse_qs, quote

# Поддержка tomllib (Python 3.11+) с fallback-парсером для более старых версий
try:
    import tomllib
except ImportError:
    tomllib = None

# Конфигурация по умолчанию
DEFAULT_CONFIG = {
    "server": {
        "bind_address": "0.0.0.0",
        "port": 22217,
        "public_host": "",
        "max_request_body_size": 2097152,  # 2 MiB
    },
    "database": {
        "path": "/var/lib/tuna-subscriptions/subscriptions.db",
    },
    "limits": {
        "max_nickname_length": 64,
        "max_uri_length": 4096,
        "max_users": 1000,
    },
    "logging": {
        "file": "/var/log/tuna-subscriptions/service.log",
        "level": "INFO",
    },
}

# Константы нормативного контракта OpenFlux v2 (TUNA 1.1.43-rc8)
OPENFLUX_SCHEMA_V2 = "tuna.openflux.bundle"
ALLOWED_OPENFLUX_TRANSPORTS = {"mailru", "boards", "cupsonline", "vyandex"}
ALLOWED_OPENFLUX_MODES = {"classic", "multistream"}
ALLOWED_OPENFLUX_CODECS = {"legacy", "batched"}
ALLOWED_BALANCER_STRATEGIES = {"roundRobin", "leastPing"}
OPENFLUX_V2_PREFIX = "openflux-bundle://v2/"
MAX_OPENFLUX_JSON_BYTES = 512 * 1024  # 512 KiB
MAX_OPENFLUX_URI_CHARS = 700000
MAX_OPENFLUX_NAME_CODEPOINTS = 120
MAX_OPENFLUX_URL_BYTES = 8192
MIN_ENCRYPTION_KEY_BYTES = 16
MAX_ENCRYPTION_KEY_BYTES = 4096
MAX_OPENFLUX_REVISION = 9007199254740991
MAX_BUNDLE_GROUPS = 8
MAX_BUNDLE_TOTAL_URLS = 32

# Константы для WebDAV (TUNA rc9)
MAX_WEBDAV_URI_BYTES = 131072
MAX_WEBDAV_STORAGE_URL_LEN = 8192
MAX_WEBDAV_LOGIN_LEN = 2048
MAX_WEBDAV_PASSWORD_LEN = 8192
MAX_WEBDAV_BACKENDS = 8
MAX_WEBDAV_CONNECTIONS = 8
MAX_SUBSCRIPTION_RESPONSE_BYTES = 2097152
ALLOWED_WEBDAV_QUERY_KEYS = {
    "timeout", "poll-min", "poll-max", "coalesce", "chunk-size",
    "puts", "read-min", "read-max", "enc", "dns", "backend"
}
SINGLE_VALUE_QUERY_KEYS = {
    "timeout", "poll-min", "poll-max", "coalesce", "chunk-size",
    "puts", "read-min", "read-max", "enc", "dns"
}

def load_config(config_path=None):
    """Загрузка конфигурации из TOML или использование значений по умолчанию."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if not config_path:
        for p in ["/etc/tuna-subscriptions/config.toml", "config.toml"]:
            if os.path.isfile(p):
                config_path = p
                break

    if config_path and not os.path.isfile(config_path):
        raise ValueError("Subscription configuration file does not exist")
    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path, "rb") as f:
                if tomllib:
                    loaded = tomllib.load(f)
                else:
                    # Простой построчный fallback парсер для базового toml
                    loaded = {}
                    current_sec = loaded
                    for line in f.read().decode("utf-8").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            sec = line[1:-1].strip()
                            current_sec = loaded.setdefault(sec, {})
                        elif "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if v.isdigit():
                                v = int(v)
                            elif v.lower() == "true":
                                v = True
                            elif v.lower() == "false":
                                v = False
                            current_sec[k] = v
                        else:
                            raise ValueError("Invalid TOML configuration line")
                for sec, vals in loaded.items():
                    if sec in cfg and isinstance(vals, dict):
                        cfg[sec].update(vals)
                    else:
                        cfg[sec] = vals
        except Exception as e:
            raise ValueError("Invalid subscription configuration; refusing to use defaults") from e
    port = cfg["server"]["port"]
    if not isinstance(port, int) or not 1 <= port <= 65535 or port in (443, 8443):
        raise ValueError("Invalid or forbidden subscription listener port")
    return cfg

def init_database(db_path):
    """Инициализация SQLite базы данных в режиме WAL с гарантией атомарности."""
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, mode=0o700, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA synchronous = NORMAL;")
    c.execute("PRAGMA foreign_keys = ON;")
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            nickname TEXT UNIQUE NOT NULL,
            csqtt_uri TEXT DEFAULT '',
            qwdtt_uri TEXT DEFAULT '',
            snell_uri TEXT DEFAULT '',
            mieru_uri TEXT DEFAULT '',
            masterdnsvpn_uri TEXT DEFAULT '',
            custom_uri TEXT DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            subscription_token TEXT DEFAULT '',
            subscription_token_hash TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    # Миграция схемы: добавление колонок если таблица создана старой версией
    c.execute("PRAGMA table_info(users);")
    existing_cols = [col[1] for col in c.fetchall()]
    if "custom_uri" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN custom_uri TEXT DEFAULT '';")
    if "subscription_token" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN subscription_token TEXT DEFAULT '';")

    # Автоматическое восстановление токенов для пользователей без токена
    c.execute("SELECT id FROM users WHERE subscription_token IS NULL OR subscription_token = '';")
    for missing in c.fetchall():
        gen_tok = secrets.token_urlsafe(32)
        gen_hash = hash_token(gen_tok)
        c.execute("UPDATE users SET subscription_token = ?, subscription_token_hash = ? WHERE id = ?;", (gen_tok, gen_hash, missing["id"]))

    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname ON users(nickname);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(subscription_token_hash);")

    # Аддитивная схема для OpenFlux v2
    c.execute("""
        CREATE TABLE IF NOT EXISTS server_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    c.execute("SELECT value FROM server_metadata WHERE key = 'issuer_id';")
    iss_row = c.fetchone()
    if not iss_row or not iss_row["value"]:
        c.execute("INSERT OR REPLACE INTO server_metadata (key, value) VALUES ('issuer_id', ?);", (str(uuid.uuid4()).lower(),))

    c.execute("""
        CREATE TABLE IF NOT EXISTS openflux_groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            mode TEXT NOT NULL,
            transport TEXT NOT NULL,
            urls_json TEXT NOT NULL,
            codec TEXT NOT NULL DEFAULT 'legacy',
            encryption_key TEXT NOT NULL DEFAULT '',
            source_slot INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_openflux_groups_name ON openflux_groups(name);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_openflux_groups_slot_mode ON openflux_groups(source_slot, mode);")

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_openflux_config (
            user_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            connection_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT 'TUNA-OpenFlux',
            mode TEXT NOT NULL DEFAULT 'classic',
            balancer_strategy TEXT NOT NULL DEFAULT 'roundRobin',
            revision INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_openflux_selection (
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            PRIMARY KEY(user_id, group_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(group_id) REFERENCES openflux_groups(id) ON DELETE CASCADE
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_of_sel_user ON user_openflux_selection(user_id, position);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_of_sel_group ON user_openflux_selection(group_id);")

    # Independent imported bundles never overwrite the local OpenFlux configuration.
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_openflux_imports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            source_issuer_id TEXT NOT NULL,
            source_connection_id TEXT NOT NULL,
            uri TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, source_issuer_id, source_connection_id)
        );
    """)

    # Аддитивная схема для WebDAV подключений (TUNA rc9)
    c.execute("""
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
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_webdav_conn_name ON webdav_connections(name);")

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_webdav_config (
            user_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            revision INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_webdav_selection (
            user_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(user_id, connection_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(connection_id) REFERENCES webdav_connections(id) ON DELETE CASCADE
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_wdav_sel_user ON user_webdav_selection(user_id, position);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_wdav_sel_conn ON user_webdav_selection(connection_id);")

    # Аддитивная миграция для отслеживания источника импорта и канонических отпечатков
    c.execute("PRAGMA table_info(openflux_groups);")
    of_grp_cols = [r["name"] for r in c.fetchall()]
    if "source_issuer_id" not in of_grp_cols:
        c.execute("ALTER TABLE openflux_groups ADD COLUMN source_issuer_id TEXT;")
    if "source_group_id" not in of_grp_cols:
        c.execute("ALTER TABLE openflux_groups ADD COLUMN source_group_id TEXT;")

    c.execute("PRAGMA table_info(user_openflux_config);")
    of_u_cols = [r["name"] for r in c.fetchall()]
    if "source_issuer_id" not in of_u_cols:
        c.execute("ALTER TABLE user_openflux_config ADD COLUMN source_issuer_id TEXT;")
    if "source_connection_id" not in of_u_cols:
        c.execute("ALTER TABLE user_openflux_config ADD COLUMN source_connection_id TEXT;")
    if "source_revision" not in of_u_cols:
        c.execute("ALTER TABLE user_openflux_config ADD COLUMN source_revision INTEGER;")

    c.execute("PRAGMA table_info(webdav_connections);")
    wd_cols = [r["name"] for r in c.fetchall()]
    if "fingerprint" not in wd_cols:
        c.execute("ALTER TABLE webdav_connections ADD COLUMN fingerprint TEXT;")
        c.execute("CREATE INDEX IF NOT EXISTS idx_webdav_fingerprint ON webdav_connections(fingerprint);")

    conn.commit()
    return conn

def is_canonical_uuid(val: str) -> bool:
    """Проверка валидности UUID в каноническом нижнем регистре (8-4-4-4-12)."""
    if not isinstance(val, str) or len(val) != 36:
        return False
    try:
        u = uuid.UUID(val)
        return str(u) == val and val == val.lower()
    except Exception:
        return False

def validate_openflux_url(val: str, transport: str = None) -> tuple[bool, str]:
    """
    Проверка одного HTTPS URL документа для группы OpenFlux.
    Контракт v2 (TUNA 1.1.43-rc8):
    - Строка non-empty, схема https://
    - Длина до 8192 байт UTF-8
    - Запрещены пробелы, переводы строк, символы управления
    - Категорически ЗАПРЕЩЕНЫ буквальные запятые (',')
    - Допустимые форматы комнат и доменов для транспортов mailru, boards, cupsonline
    """
    if not val or not isinstance(val, str):
        return False, "URL must be a non-empty string"
    s = val.strip()
    if not s:
        return False, "URL cannot be empty"
    if len(s.encode("utf-8")) > MAX_OPENFLUX_URL_BYTES:
        return False, f"URL exceeds max byte length of {MAX_OPENFLUX_URL_BYTES} bytes"
    if not s.startswith("https://"):
        return False, f"URL must start with 'https://' (got: {s[:30]})"
    if any(ch in s for ch in (" ", "\t", "\r", "\n")):
        return False, "URL cannot contain spaces or whitespace characters"
    if "," in s:
        return False, "URL cannot contain literal comma"
    for ch in s:
        if ord(ch) < 32 or ord(ch) == 127:
            return False, "URL contains invalid control characters"
    try:
        parsed = urlparse(s)
        if not parsed.scheme or not parsed.netloc:
            return False, "Malformed URL structure"
    except Exception:
        return False, "Failed to parse URL"

    netloc_lower = parsed.netloc.lower()
    if transport:
        tr = str(transport).strip().lower()
        if tr == "vyandex":
            try:
                if parsed.hostname not in ("disk.yandex.ru", "docs.yandex.ru") or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.path in ("", "/"):
                    return False, "Volga requires an HTTPS document on disk.yandex.ru or docs.yandex.ru"
            except ValueError:
                return False, "Invalid Volga document port"
        elif tr == "mailru":
            if not ("mail.ru" in netloc_lower or "example.com" in netloc_lower):
                return False, f"mailru URL host must be on mail.ru (got: {parsed.netloc})"
        elif tr == "boards":
            if not ("yandex.ru" in netloc_lower or "example.com" in netloc_lower):
                return False, f"boards URL host must be on yandex.ru (got: {parsed.netloc})"
        elif tr == "cupsonline":
            if not ("cups.online" in netloc_lower or "example.com" in netloc_lower):
                return False, f"cupsonline URL host must be on cups.online (got: {parsed.netloc})"
            if not parsed.path or parsed.path == "/":
                return False, "cupsonline URL must specify a room path (e.g. /live-coding/?room=...)"
    return True, ""

def validate_openflux_v2_payload(data: dict) -> tuple[bool, str]:
    """
    Строгая валидация проволочного контракта OpenFlux v2 (OPENFLUX_SUBSCRIPTION_V2_CONTRACT.md, TUNA 1.1.43-rc8).
    Проверяет точный набор корневых полей, запрет 'mode' в проволочных группах,
    уникальность URL внутри и между группами, лимиты длин и типов.
    """
    if not isinstance(data, dict):
        return False, "Bundle payload must be a JSON object"

    allowed_root_fields = {
        "schema", "version", "issuer_id", "id", "revision",
        "name", "mode", "balancer_strategy", "groups"
    }
    for k in data.keys():
        if k not in allowed_root_fields:
            return False, f"Unknown field '{k}' in root bundle payload"

    for req in allowed_root_fields:
        if req not in data:
            return False, f"Missing required root field '{req}'"

    if data["schema"] != OPENFLUX_SCHEMA_V2:
        return False, f"Invalid schema '{data['schema']}', expected '{OPENFLUX_SCHEMA_V2}'"

    if data["version"] != 2 or isinstance(data["version"], bool) or not isinstance(data["version"], int):
        return False, f"Invalid version '{data['version']}', expected integer 2"

    if not is_canonical_uuid(data["issuer_id"]):
        return False, f"Field 'issuer_id' must be a canonical lowercase UUID: '{data['issuer_id']}'"

    if not is_canonical_uuid(data["id"]):
        return False, f"Field 'id' must be a canonical lowercase UUID: '{data['id']}'"

    rev = data["revision"]
    if isinstance(rev, bool) or not isinstance(rev, int) or rev < 1 or rev > MAX_OPENFLUX_REVISION:
        return False, f"Field 'revision' must be an integer between 1 and {MAX_OPENFLUX_REVISION}"

    name = data["name"]
    if not isinstance(name, str) or len(name) < 1 or len(name) > MAX_OPENFLUX_NAME_CODEPOINTS:
        return False, f"Field 'name' must be between 1 and {MAX_OPENFLUX_NAME_CODEPOINTS} characters"

    if data["mode"] not in ALLOWED_OPENFLUX_MODES:
        return False, f"Invalid bundle mode '{data['mode']}'. Allowed: {sorted(ALLOWED_OPENFLUX_MODES)}"

    if data["balancer_strategy"] not in ALLOWED_BALANCER_STRATEGIES:
        return False, f"Invalid balancer_strategy '{data['balancer_strategy']}'. Allowed: {sorted(ALLOWED_BALANCER_STRATEGIES)}"

    groups = data["groups"]
    if not isinstance(groups, list) or len(groups) < 1 or len(groups) > MAX_BUNDLE_GROUPS:
        return False, f"Field 'groups' must contain between 1 and {MAX_BUNDLE_GROUPS} groups (got {len(groups) if isinstance(groups, list) else 'non-list'})"

    allowed_group_fields = {"id", "name", "transport", "urls", "codec", "encryption_key"}
    seen_group_ids = set()
    seen_bundle_urls = set()

    for idx, grp in enumerate(groups):
        if not isinstance(grp, dict):
            return False, f"Group at index {idx} must be an object"

        if "mode" in grp:
            return False, f"Group '{grp.get('id', idx)}' wire object must NOT contain 'mode'"

        for k in grp.keys():
            if k not in allowed_group_fields:
                return False, f"Group at index {idx} has unknown field '{k}'"

        for gf in allowed_group_fields:
            if gf not in grp:
                return False, f"Group at index {idx} is missing required field '{gf}'"

        gid = grp["id"]
        if not is_canonical_uuid(gid):
            return False, f"Group id '{gid}' must be a canonical lowercase UUID"
        if gid in seen_group_ids:
            return False, f"Duplicate group id '{gid}' in bundle"
        seen_group_ids.add(gid)

        gname = grp["name"]
        if not isinstance(gname, str) or len(gname) < 1 or len(gname) > MAX_OPENFLUX_NAME_CODEPOINTS:
            return False, f"Group '{gid}' name must be between 1 and {MAX_OPENFLUX_NAME_CODEPOINTS} characters"

        tr = grp["transport"]
        if tr not in ALLOWED_OPENFLUX_TRANSPORTS:
            return False, f"Group '{gid}' has forbidden transport '{tr}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}"

        cd = grp["codec"]
        if cd not in ALLOWED_OPENFLUX_CODECS:
            return False, f"Group '{gid}' has invalid codec '{cd}'. Allowed: {', '.join(sorted(ALLOWED_OPENFLUX_CODECS))}"

        key = grp["encryption_key"]
        if not isinstance(key, str):
            return False, f"Group '{gid}' encryption_key must be a string"
        if key:
            key_bytes = key.encode("utf-8")
            if not (MIN_ENCRYPTION_KEY_BYTES <= len(key_bytes) <= MAX_ENCRYPTION_KEY_BYTES):
                return False, f"Group '{gid}' encryption_key length must be between {MIN_ENCRYPTION_KEY_BYTES} and {MAX_ENCRYPTION_KEY_BYTES} bytes (got {len(key_bytes)})"

        urls = grp["urls"]
        if not isinstance(urls, list):
            return False, f"Group '{gid}' urls must be a list"

        if data["mode"] == "classic" and len(urls) != 1:
            return False, f"Group '{gid}' is in classic mode bundle but has {len(urls)} URLs (must be exactly 1)"
        if data["mode"] == "multistream" and not (1 <= len(urls) <= 4):
            return False, f"Group '{gid}' is in multistream mode bundle but has {len(urls)} URLs (must be 1 to 4)"

        seen_group_urls = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u, tr)
            if not ok_u:
                return False, f"Group '{gid}' contains invalid URL: {err_u}"
            if u in seen_group_urls:
                return False, f"Group '{gid}' contains duplicate URL: '{u}'"
            if u in seen_bundle_urls:
                return False, f"Duplicate URL across groups in bundle: '{u}'"
            seen_group_urls.add(u)
            seen_bundle_urls.add(u)

    total_urls = len(seen_bundle_urls)
    if total_urls > MAX_BUNDLE_TOTAL_URLS:
        return False, f"Total URLs across bundle exceeds {MAX_BUNDLE_TOTAL_URLS} (got {total_urls})"

    return True, ""

def build_openflux_v2_payload(
    issuer_id: str,
    connection_id: str,
    revision: int,
    name: str,
    mode: str,
    balancer_strategy: str,
    groups: list
) -> tuple[bool, str, dict]:
    """
    Единый канонический конструктор и валидатор payload OpenFlux v2 для TUNA rc8.
    Исключает поле 'mode' из групп проволочного формата (wire groups).
    """
    if not isinstance(groups, list) or len(groups) < 1 or len(groups) > MAX_BUNDLE_GROUPS:
        return False, f"Field 'groups' must contain between 1 and {MAX_BUNDLE_GROUPS} groups", {}

    mode = str(mode or "classic").strip().lower()
    balancer_strategy = str(balancer_strategy or "roundRobin").strip()

    wire_groups = []
    for idx, g in enumerate(groups):
        if not isinstance(g, dict):
            return False, f"Group at index {idx} must be a dictionary", {}
        grp_mode = g.get("mode")
        if grp_mode and grp_mode != mode:
            return False, f"Group '{g.get('id')}' mode '{grp_mode}' does not match root mode '{mode}'", {}

        raw_urls = g.get("urls")
        if raw_urls is None and "urls_json" in g:
            try:
                raw_urls = json.loads(g["urls_json"])
            except Exception:
                raw_urls = []
        if not isinstance(raw_urls, list):
            return False, f"Group at index {idx} urls must be a list", {}

        gid = str(g.get("id") or "").strip().lower()
        wire_g = {
            "id": gid,
            "name": str(g.get("name") or "").strip(),
            "transport": str(g.get("transport") or "").strip().lower(),
            "urls": [str(u).strip() for u in raw_urls],
            "codec": str(g.get("codec") or "legacy").strip().lower(),
            "encryption_key": str(g.get("encryption_key") or "").strip()
        }
        wire_groups.append(wire_g)

    payload = {
        "schema": OPENFLUX_SCHEMA_V2,
        "version": 2,
        "issuer_id": str(issuer_id).strip().lower(),
        "id": str(connection_id).strip().lower(),
        "revision": int(revision),
        "name": str(name).strip(),
        "mode": mode,
        "balancer_strategy": balancer_strategy,
        "groups": wire_groups
    }

    ok, err = validate_openflux_v2_payload(payload)
    if not ok:
        return False, err, {}
    return True, "", payload

def serialize_openflux_v2_bundle(payload: dict) -> tuple[bool, str, str]:
    """
    Каноническая сериализация JSON -> URL-Safe Base64 (без padding) -> openflux-bundle://v2/...
    Строго валидирует контракт TUNA 1.1.43-rc8 перед формированием строки.
    Возвращает: (is_valid, error_msg, full_uri)
    """
    ok, err = validate_openflux_v2_payload(payload)
    if not ok:
        return False, f"Validation error: {err}", ""
    try:
        json_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        json_bytes = json_str.encode("utf-8")
        if len(json_bytes) > MAX_OPENFLUX_JSON_BYTES:
            return False, f"Decoded bundle JSON payload exceeds 512 KiB limit ({len(json_bytes)} bytes)", ""
        b64_url = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")
        full_uri = f"{OPENFLUX_V2_PREFIX}{b64_url}"
        if len(full_uri) > MAX_OPENFLUX_URI_CHARS:
            return False, f"Bundle URI exceeds {MAX_OPENFLUX_URI_CHARS} characters limit ({len(full_uri)})", ""
        return True, "", full_uri
    except Exception as e:
        return False, f"Serialization error: {e}", ""

def deserialize_openflux_v2_bundle(bundle_uri: str) -> tuple[bool, str, dict]:
    """
    Десериализация и валидация строки openflux-bundle://v2/<base64url>.
    Возвращает: (is_valid, error_msg, payload_dict)
    """
    if not bundle_uri.startswith(OPENFLUX_V2_PREFIX):
        return False, f"URI does not start with '{OPENFLUX_V2_PREFIX}'", {}
    b64_str = bundle_uri[len(OPENFLUX_V2_PREFIX):].strip()
    if not b64_str:
        return False, "Empty base64url payload in bundle URI", {}
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)
    try:
        raw_bytes = base64.urlsafe_b64decode(b64_str.encode("ascii"))
    except Exception as e:
        return False, f"Invalid base64url encoding: {e}", {}
    if len(raw_bytes) > MAX_OPENFLUX_JSON_BYTES:
        return False, f"Decoded payload exceeds 512 KiB ({len(raw_bytes)} bytes)", {}
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return False, f"Invalid JSON payload: {e}", {}

    ok, err = validate_openflux_v2_payload(data)
    if not ok:
        return False, err, {}
    return True, "", data

def repair_openflux_v2_database(db_path: str, backup: bool = True) -> tuple[bool, str, dict]:
    """
    Идемпотентная процедура миграции и исправления базы данных OpenFlux v2:
    1. Резервное копирование subscriptions.db
    2. Разделение запятых в urls_json на канонические массивы отдельных строк
    3. Валидация всех групп
    4. Атомарное обновление revision пользователей и ETag
    5. Повторный запуск не вносит изменений и не увеличивает revision.
    """
    if not os.path.isfile(db_path):
        return False, f"Database file not found: {db_path}", {}

    bak_file = ""
    if backup:
        bak_file = f"{db_path}.bak.{int(time.time())}"
        try:
            shutil.copy2(db_path, bak_file)
        except Exception as e:
            return False, f"Failed to create backup: {e}", {}

    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    repaired_groups = []
    affected_users = set()

    try:
        with conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='openflux_groups';")
            if not c.fetchone():
                conn.close()
                return True, "Table openflux_groups does not exist, nothing to repair", {"backup": bak_file}

            c.execute("SELECT * FROM openflux_groups;")
            groups = c.fetchall()

            changed_group_ids = set()
            for g in groups:
                gid = g["id"]
                tr = g["transport"]
                mode = g["mode"]
                raw_urls_json = g["urls_json"]
                try:
                    urls = json.loads(raw_urls_json)
                except Exception:
                    urls = []

                needs_split = False
                new_urls = []
                for item in urls:
                    if isinstance(item, str) and "," in item:
                        needs_split = True
                        for part in item.split(","):
                            p = part.strip()
                            if p:
                                new_urls.append(p)
                    elif isinstance(item, str):
                        new_urls.append(item.strip())

                if needs_split:
                    for u in new_urls:
                        ok_u, err_u = validate_openflux_url(u, tr)
                        if not ok_u:
                            raise ValueError(f"Group '{gid}' contains invalid URL after split: {err_u}")
                    if len(new_urls) != len(set(new_urls)):
                        raise ValueError(f"Group '{gid}' contains duplicate URLs after split")
                    if mode == "classic" and len(new_urls) != 1:
                        raise ValueError(f"Group '{gid}' mode is classic but has {len(new_urls)} URLs after split")
                    if mode == "multistream" and not (1 <= len(new_urls) <= 4):
                        raise ValueError(f"Group '{gid}' mode is multistream but has {len(new_urls)} URLs after split")

                    c.execute("""
                        UPDATE openflux_groups
                        SET urls_json = ?, updated_at = ?
                        WHERE id = ?;
                    """, (json.dumps(new_urls), now, gid))
                    changed_group_ids.add(gid)
                    repaired_groups.append({
                        "id": gid,
                        "name": g["name"],
                        "before_count": len(urls),
                        "after_count": len(new_urls)
                    })

            # Проверка флага миграции wire-формата v2 (tuna.openflux.bundle)
            c.execute("SELECT value FROM server_metadata WHERE key = 'wire_format_v2_rc8_migrated';")
            mig_flag = c.fetchone()
            first_wire_migration = (mig_flag is None or mig_flag["value"] != "1")

            if changed_group_ids:
                q_placeholders = ",".join("?" for _ in changed_group_ids)
                c.execute(f"""
                    SELECT DISTINCT user_id FROM user_openflux_selection
                    WHERE group_id IN ({q_placeholders});
                """, list(changed_group_ids))
                for r in c.fetchall():
                    affected_users.add(r[0])

            if first_wire_migration:
                c.execute("""
                    SELECT DISTINCT u.user_id FROM user_openflux_config u
                    JOIN user_openflux_selection s ON u.user_id = s.user_id
                    WHERE u.enabled = 1;
                """)
                for r in c.fetchall():
                    affected_users.add(r[0])

            for uid in affected_users:
                c.execute("""
                    UPDATE user_openflux_config
                    SET revision = revision + 1, updated_at = ?
                    WHERE user_id = ?;
                """, (now, uid))
                c.execute("""
                    UPDATE users
                    SET revision = revision + 1, updated_at = ?
                    WHERE id = ?;
                """, (now, uid))

            if first_wire_migration:
                c.execute("INSERT OR REPLACE INTO server_metadata (key, value) VALUES ('wire_format_v2_rc8_migrated', '1');")

        conn.close()
        return True, "Database repaired successfully", {
            "backup": bak_file,
            "repaired_groups": repaired_groups,
            "repaired_groups_count": len(repaired_groups),
            "affected_users": list(affected_users),
            "affected_users_count": len(affected_users)
        }
    except Exception as e:
        conn.close()
        return False, f"Database repair failed: {e}", {"backup": bak_file}

def rollback_openflux_v2_database(backup_file: str, db_path: str) -> tuple[bool, str]:
    """Восстановление базы данных из резервной копии."""
    if not os.path.isfile(backup_file):
        return False, f"Backup file not found: {backup_file}"
    try:
        shutil.copy2(backup_file, db_path)
        return True, f"Database successfully restored from {backup_file}"
    except Exception as e:
        return False, f"Failed to restore database from backup: {e}"

def hash_token(token: str) -> str:
    """Криптографический SHA-256 хеш токена подписки."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

def validate_single_uri(val: str, max_len: int = 4096) -> tuple[bool, str]:
    """
    Валидация одиночного URI:
    - Запрещены управляющие символы, CR, LF.
    - Проверка базовой длины (для WebDAV отдельный лимит MAX_WEBDAV_URI_BYTES = 131072).
    - Обязательное наличие схемы (://).
    - Разрешены пустые значения.
    """
    if not val:
        return True, ""
    effective_max = MAX_WEBDAV_URI_BYTES if (val.startswith("webdav://") or val.startswith("webdavs://")) else max_len
    if len(val) > effective_max:
        return False, f"URI exceeds max length of {effective_max}"
    if "\r" in val or "\n" in val:
        return False, "URI contains newline or carriage return"
    if "://" not in val:
        return False, "URI must contain scheme (://)"
    # Проверка на управляющие символы ASCII (0x00-0x1F, 0x7F)
    for ch in val:
        if ord(ch) < 32 or ord(ch) == 127:
            return False, "URI contains invalid control characters"
    return True, ""

def normalize_and_validate_uris(raw_val, max_len: int = 4096) -> tuple[bool, str, str]:
    """
    Нормализует входящие URI (одиночная строка, многострочный текст или массив/список строк)
    в единую строку с разделителем '\n'. Валидирует каждую ссылку.
    Возвращает: (is_valid, error_message, normalized_string)
    """
    if raw_val is None:
        return True, "", ""

    items = []
    if isinstance(raw_val, (list, tuple)):
        for el in raw_val:
            if not isinstance(el, str):
                return False, "Each URI in array must be a string", ""
            for line in el.splitlines():
                s = line.strip()
                if s:
                    items.append(s)
    elif isinstance(raw_val, str):
        for line in raw_val.splitlines():
            s = line.strip()
            if s:
                items.append(s)
    else:
        return False, "URI field must be a string or array of strings", ""

    if not items:
        return True, "", ""

    for item in items:
        ok, err = validate_single_uri(item, max_len)
        if not ok:
            return False, err, ""

    return True, "", "\n".join(items)

def validate_uri(val, max_len: int = 4096) -> tuple[bool, str]:
    """Обратная совместимость: валидация одного или нескольких URI."""
    ok, err, _ = normalize_and_validate_uris(val, max_len)
    return ok, err

def validate_nickname(nick: str, max_len: int = 64) -> tuple[bool, str]:
    """Валидация никнейма: UTF-8, длина, отсутствие переносов строк."""
    if not nick or not nick.strip():
        return False, "Nickname is required"
    nick = nick.strip()
    if len(nick) > max_len:
        return False, f"Nickname exceeds max length of {max_len}"
    if "\r" in nick or "\n" in nick:
        return False, "Nickname contains newlines"
    return True, ""

# ============================================================================
# Нормативные функции WebDAV (TUNA rc9)
# ============================================================================

def parse_duration_ms(val: str) -> tuple[bool, str, int]:
    """Разбор строки длительности (50ms, 10s, 1m) в миллисекунды."""
    if not val or not isinstance(val, str):
        return False, "Duration must be a non-empty string", 0
    s = val.strip().lower()
    if s in ("0", "0ms", "0s"):
        return True, "", 0
    m = re.match(r"^(\d+)(ms|s|m)$", s)
    if not m:
        return False, f"Invalid duration format: '{val}' (expected e.g. 50ms, 10s, 1m)", 0
    num = int(m.group(1))
    unit = m.group(2)
    if unit == "ms":
        return True, "", num
    elif unit == "s":
        return True, "", num * 1000
    elif unit == "m":
        return True, "", num * 60000
    return False, f"Unknown unit: '{unit}'", 0

def validate_dns_spec(dns: str) -> tuple[bool, str]:
    """Валидация параметра dns (IP[:порт], udp://IP:порт, tcp://IP:порт)."""
    if not dns or not isinstance(dns, str):
        return True, ""
    s = dns.strip()
    if not s:
        return True, ""
    target = s
    if s.startswith("udp://"):
        target = s[6:]
    elif s.startswith("tcp://"):
        target = s[6:]
    elif "://" in s:
        return False, f"Unsupported DNS scheme in '{s}' (allowed: none, udp://, tcp://)"

    if target.startswith("["):
        idx = target.find("]")
        if idx == -1:
            return False, f"Malformed IPv6 address in DNS '{s}'"
        host = target[1:idx]
        rest = target[idx+1:]
        if rest:
            if not rest.startswith(":"):
                return False, f"Malformed port in DNS '{s}'"
            try:
                p = int(rest[1:])
                if not (1 <= p <= 65535):
                    return False, f"Port out of range in DNS '{s}'"
            except ValueError:
                return False, f"Invalid port in DNS '{s}'"
    else:
        parts = target.split(":")
        if len(parts) == 1:
            host = parts[0]
        elif len(parts) == 2:
            host = parts[0]
            try:
                p = int(parts[1])
                if not (1 <= p <= 65535):
                    return False, f"Port out of range in DNS '{s}'"
            except ValueError:
                return False, f"Invalid port in DNS '{s}'"
        else:
            host = target

    if not host:
        return False, f"Empty host in DNS '{s}'"
    return True, ""

def validate_tuning_params(params: dict) -> tuple[bool, str, dict]:
    """Валидация параметров тюнинга WebDAV по нормативу TUNA rc9."""
    cleaned = {}

    # timeout: 1s–10m; дефолт 60s
    timeout = str(params.get("timeout", "60s")).strip() or "60s"
    ok, err, t_ms = parse_duration_ms(timeout)
    if not ok:
        return False, f"Invalid timeout: {err}", {}
    if not (1000 <= t_ms <= 600000):
        return False, f"Timeout out of range (1s–10m): got {timeout} ({t_ms}ms)", {}
    cleaned["timeout"] = timeout

    # poll-min: 1ms–60s; дефолт 200ms
    poll_min = str(params.get("poll_min", params.get("poll-min", "200ms"))).strip() or "200ms"
    ok, err, pmin_ms = parse_duration_ms(poll_min)
    if not ok:
        return False, f"Invalid poll-min: {err}", {}
    if not (1 <= pmin_ms <= 60000):
        return False, f"poll-min out of range (1ms–60s): got {poll_min} ({pmin_ms}ms)", {}
    cleaned["poll_min"] = poll_min

    # poll-max: не меньше poll-min и не больше 60s; дефолт 500ms
    poll_max = str(params.get("poll_max", params.get("poll-max", "500ms"))).strip() or "500ms"
    ok, err, pmax_ms = parse_duration_ms(poll_max)
    if not ok:
        return False, f"Invalid poll-max: {err}", {}
    if not (1 <= pmax_ms <= 60000):
        return False, f"poll-max out of range (1ms–60s): got {poll_max} ({pmax_ms}ms)", {}
    if pmax_ms < pmin_ms:
        return False, f"poll-max ({poll_max}) cannot be less than poll-min ({poll_min})", {}
    cleaned["poll_max"] = poll_max

    # coalesce: 0–1s; дефолт 10ms
    coalesce = str(params.get("coalesce", "10ms")).strip() or "10ms"
    ok, err, c_ms = parse_duration_ms(coalesce)
    if not ok:
        return False, f"Invalid coalesce: {err}", {}
    if not (0 <= c_ms <= 1000):
        return False, f"coalesce out of range (0–1s): got {coalesce} ({c_ms}ms)", {}
    cleaned["coalesce"] = coalesce

    # chunk-size: целое 1024–4194304; дефолт 131071
    try:
        chunk_size = int(params.get("chunk_size", params.get("chunk-size", 131071)))
    except (ValueError, TypeError):
        return False, "chunk-size must be an integer", {}
    if not (1024 <= chunk_size <= 4194304):
        return False, f"chunk-size out of range (1024–4194304): got {chunk_size}", {}
    cleaned["chunk_size"] = chunk_size

    # puts: целое 1–32; дефолт 8
    try:
        puts = int(params.get("puts", 8))
    except (ValueError, TypeError):
        return False, "puts must be an integer", {}
    if not (1 <= puts <= 32):
        return False, f"puts out of range (1–32): got {puts}", {}
    cleaned["puts"] = puts

    # read-min: целое 1–32; дефолт 3
    try:
        read_min = int(params.get("read_min", params.get("read-min", 3)))
    except (ValueError, TypeError):
        return False, "read-min must be an integer", {}
    if not (1 <= read_min <= 32):
        return False, f"read-min out of range (1–32): got {read_min}", {}
    cleaned["read_min"] = read_min

    # read-max: целое 1–32, не меньше read-min; дефолт 8
    try:
        read_max = int(params.get("read_max", params.get("read-max", 8)))
    except (ValueError, TypeError):
        return False, "read-max must be an integer", {}
    if not (1 <= read_max <= 32):
        return False, f"read-max out of range (1–32): got {read_max}", {}
    if read_max < read_min:
        return False, f"read-max ({read_max}) cannot be less than read-min ({read_min})", {}
    cleaned["read_max"] = read_max

    # enc: только 0 или 1; отсутствие означает false
    raw_enc = params.get("enc", 0)
    if isinstance(raw_enc, bool):
        cleaned["enc"] = 1 if raw_enc else 0
    elif str(raw_enc).strip() in ("1", "true", "True"):
        cleaned["enc"] = 1
    elif str(raw_enc).strip() in ("0", "false", "False", ""):
        cleaned["enc"] = 0
    else:
        return False, f"enc must be 0 or 1 (got: '{raw_enc}')", {}

    # dns: bootstrap хранилища, опционален
    dns_val = str(params.get("dns", "")).strip()
    if dns_val:
        ok, err = validate_dns_spec(dns_val)
        if not ok:
            return False, err, {}
        cleaned["dns"] = dns_val
    else:
        cleaned["dns"] = ""

    return True, "", cleaned

def parse_storage_url(url_str: str) -> tuple[bool, str, dict]:
    """Разбор и валидация URL хранилища WebDAV."""
    if not url_str or not isinstance(url_str, str):
        return False, "Storage URL must be a non-empty string", {}
    s = url_str.strip()
    if len(s) > MAX_WEBDAV_STORAGE_URL_LEN:
        return False, f"Storage URL exceeds limit of {MAX_WEBDAV_STORAGE_URL_LEN} chars", {}

    if s.startswith("http://"):
        wire_scheme = "webdav"
        base_s = s
    elif s.startswith("https://"):
        wire_scheme = "webdavs"
        base_s = s
    elif s.startswith("webdav://"):
        wire_scheme = "webdav"
        base_s = "http://" + s[9:]
    elif s.startswith("webdavs://"):
        wire_scheme = "webdavs"
        base_s = "https://" + s[10:]
    else:
        return False, f"Storage URL must start with http://, https://, webdav:// or webdavs:// (got: '{s[:30]}')", {}

    parsed = urllib.parse.urlsplit(base_s)
    if not parsed.hostname:
        return False, f"Storage URL missing hostname: '{url_str}'", {}
    if parsed.username or parsed.password:
        return False, f"Storage URL must not contain userinfo (username/password): '{url_str}'", {}
    if parsed.query or parsed.fragment:
        return False, f"Storage URL must not contain query parameters or fragments: '{url_str}'", {}

    h = parsed.hostname
    if ":" in h and not h.startswith("["):
        h = f"[{h}]"

    port_part = f":{parsed.port}" if parsed.port else ""
    host_port = f"{h}{port_part}"

    path = parsed.path
    if not path or not path.startswith("/"):
        path = "/" + path if path else "/"

    std_scheme = "https" if wire_scheme == "webdavs" else "http"
    std_url = f"{std_scheme}://{host_port}{path}"

    return True, "", {
        "raw_url": std_url,
        "wire_scheme": wire_scheme,
        "host_port": host_port,
        "path": path,
    }

def validate_storage_spec(spec: dict, is_primary: bool = False) -> tuple[bool, str, dict]:
    """Валидация спецификации хранилища (URL, логин, пароль, метка)."""
    if not isinstance(spec, dict):
        return False, "Storage specification must be a dictionary", {}

    url = spec.get("url", "")
    ok, err, parsed = parse_storage_url(url)
    if not ok:
        return False, err, {}

    username = str(spec.get("username", "")).strip()
    if not username:
        return False, "Storage login cannot be empty", {}
    if len(username) > MAX_WEBDAV_LOGIN_LEN:
        return False, f"Storage login exceeds maximum length of {MAX_WEBDAV_LOGIN_LEN} characters", {}

    password = str(spec.get("password", "")).strip()
    if not password:
        return False, "Storage password cannot be empty", {}
    if len(password) > MAX_WEBDAV_PASSWORD_LEN:
        return False, f"Storage password exceeds maximum length of {MAX_WEBDAV_PASSWORD_LEN} characters", {}

    label = str(spec.get("label", "")).strip()

    return True, "", {
        "url": parsed["raw_url"],
        "wire_scheme": parsed["wire_scheme"],
        "host_port": parsed["host_port"],
        "path": parsed["path"],
        "username": username,
        "password": password,
        "label": label,
    }

def serialize_webdav_uri(conn: dict) -> tuple[bool, str, str]:
    """
    Канонический сериализатор WebDAV URI по нормативу TUNA rc9:
    - Primary: webdav[s]://LOGIN:PASS@HOST:PORT/path/
    - Query: timeout, poll-min, poll-max, coalesce, chunk-size, puts, read-min, read-max, enc (if 1), dns (if set), backend (repeating)
    - Fragment: #NAME (percent-encoded UTF-8)
    - Вложенные backends: webdav[s]://LOGIN:PASS@HOST:PORT/path/ percent-encoded в backend=
    - Ограничение итогового URI <= 131072 байт ASCII/UTF-8.
    """
    name = str(conn.get("name", "")).strip()
    if not name:
        return False, "Connection name cannot be empty", ""

    primary_spec = {
        "url": conn.get("url", ""),
        "username": conn.get("username", ""),
        "password": conn.get("password", ""),
        "label": conn.get("label", ""),
    }
    ok_p, err_p, p_clean = validate_storage_spec(primary_spec, is_primary=True)
    if not ok_p:
        return False, f"Primary storage error: {err_p}", ""

    # Валидация параметров тюнинга
    ok_t, err_t, t_clean = validate_tuning_params(conn)
    if not ok_t:
        return False, f"Tuning parameters error: {err_t}", ""

    # Дополнительные backends (0..8)
    raw_backends = conn.get("backends", [])
    if not isinstance(raw_backends, list):
        return False, "Backends must be a list", ""
    if len(raw_backends) > MAX_WEBDAV_BACKENDS:
        return False, f"Too many backends: {len(raw_backends)} (max {MAX_WEBDAV_BACKENDS} allowed)", ""

    clean_backends = []
    for idx, b in enumerate(raw_backends):
        ok_b, err_b, b_clean = validate_storage_spec(b, is_primary=False)
        if not ok_b:
            return False, f"Backend #{idx+1} error: {err_b}", ""
        clean_backends.append(b_clean)

    # Кодирование реквизитов основного хранилища (safe='' кодирует : @ + & % ? # /)
    enc_p_user = urllib.parse.quote(p_clean["username"], safe="")
    enc_p_pass = urllib.parse.quote(p_clean["password"], safe="")
    base_uri = f"{p_clean['wire_scheme']}://{enc_p_user}:{enc_p_pass}@{p_clean['host_port']}{p_clean['path']}"

    # Query параметры в каноническом порядке
    q_pairs = [
        f"timeout={t_clean['timeout']}",
        f"poll-min={t_clean['poll_min']}",
        f"poll-max={t_clean['poll_max']}",
        f"coalesce={t_clean['coalesce']}",
        f"chunk-size={t_clean['chunk_size']}",
        f"puts={t_clean['puts']}",
        f"read-min={t_clean['read_min']}",
        f"read-max={t_clean['read_max']}",
    ]

    if t_clean["enc"] == 1:
        q_pairs.append("enc=1")

    if t_clean["dns"]:
        enc_dns = urllib.parse.quote(t_clean["dns"], safe="")
        q_pairs.append(f"dns={enc_dns}")

    for b in clean_backends:
        enc_b_user = urllib.parse.quote(b["username"], safe="")
        enc_b_pass = urllib.parse.quote(b["password"], safe="")
        nested_uri = f"{b['wire_scheme']}://{enc_b_user}:{enc_b_pass}@{b['host_port']}{b['path']}"
        # Весь вложенный URI кодируется как значение query параметра backend
        enc_nested = urllib.parse.quote(nested_uri, safe="")
        q_pairs.append(f"backend={enc_nested}")

    query_str = "&".join(q_pairs)
    frag_str = urllib.parse.quote(name, safe="")

    full_uri = f"{base_uri}?{query_str}#{frag_str}"
    uri_bytes = len(full_uri.encode("utf-8"))
    if uri_bytes > MAX_WEBDAV_URI_BYTES:
        return False, f"Resulting WebDAV URI size ({uri_bytes} bytes) exceeds limit of {MAX_WEBDAV_URI_BYTES} bytes", ""

    return True, "", full_uri

def parse_webdav_uri(uri_str: str) -> tuple[bool, str, dict]:
    """
    Канонический парсер WebDAV URI по нормативу TUNA rc9:
    - Проверка размера <= 131072
    - Парсинг fragment (#NAME)
    - Парсинг схемы (webdav / webdavs)
    - Парсинг userinfo и authority основного хранилища
    - Проверка отсутствия неизвестных query параметров и дубликатов одиночных ключей
    - Разбор повторяющихся backend параметров
    - Возврат структурированного словаря подключения.
    """
    if not uri_str or not isinstance(uri_str, str):
        return False, "URI must be a non-empty string", {}
    s = uri_str.strip()
    if len(s.encode("utf-8")) > MAX_WEBDAV_URI_BYTES:
        return False, f"URI exceeds max allowed size of {MAX_WEBDAV_URI_BYTES} bytes", {}

    if not (s.startswith("webdav://") or s.startswith("webdavs://")):
        return False, "URI must start with webdav:// or webdavs://", {}

    # Fragment
    if "#" in s:
        s_no_frag, frag_raw = s.split("#", 1)
        name = urllib.parse.unquote(frag_raw)
    else:
        s_no_frag = s
        name = "WebDAV"

    if "?" in s_no_frag:
        base_part, query_part = s_no_frag.split("?", 1)
    else:
        base_part = s_no_frag
        query_part = ""

    parsed_base = urllib.parse.urlsplit(base_part)
    scheme = parsed_base.scheme
    if scheme not in ("webdav", "webdavs"):
        return False, f"Invalid scheme '{scheme}'", {}

    if not parsed_base.netloc:
        return False, "Missing authority in URI", {}

    if "@" not in parsed_base.netloc:
        return False, "Missing userinfo (username:password) in primary storage", {}

    userinfo, hostport = parsed_base.netloc.split("@", 1)
    if ":" not in userinfo:
        return False, "Malformed userinfo: expected username:password", {}
    enc_user, enc_pass = userinfo.split(":", 1)
    user = urllib.parse.unquote(enc_user)
    password = urllib.parse.unquote(enc_pass)

    if not user:
        return False, "Primary storage username cannot be empty", {}
    if not password:
        return False, "Primary storage password cannot be empty", {}

    path = parsed_base.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    std_scheme = "https" if scheme == "webdavs" else "http"
    primary_url = f"{std_scheme}://{hostport}{path}"

    tuning = {
        "timeout": "60s",
        "poll_min": "200ms",
        "poll_max": "500ms",
        "coalesce": "10ms",
        "chunk_size": 131071,
        "puts": 8,
        "read_min": 3,
        "read_max": 8,
        "enc": 0,
        "dns": "",
    }
    backends = []

    if query_part:
        raw_pairs = query_part.split("&")
        seen_single_keys = set()
        for pair in raw_pairs:
            if not pair:
                continue
            if "=" not in pair:
                return False, f"Malformed query parameter '{pair}' (missing '=')", {}
            k, v = pair.split("=", 1)
            k = k.strip()
            if k not in ALLOWED_WEBDAV_QUERY_KEYS:
                return False, f"Unknown query parameter '{k}'", {}
            if k in SINGLE_VALUE_QUERY_KEYS:
                if k in seen_single_keys:
                    return False, f"Duplicate query parameter '{k}'", {}
                seen_single_keys.add(k)

            unquoted_v = urllib.parse.unquote(v)
            if k == "timeout":
                tuning["timeout"] = unquoted_v
            elif k == "poll-min":
                tuning["poll_min"] = unquoted_v
            elif k == "poll-max":
                tuning["poll_max"] = unquoted_v
            elif k == "coalesce":
                tuning["coalesce"] = unquoted_v
            elif k == "chunk-size":
                try:
                    tuning["chunk_size"] = int(unquoted_v)
                except ValueError:
                    return False, f"Invalid chunk-size '{unquoted_v}'", {}
            elif k == "puts":
                try:
                    tuning["puts"] = int(unquoted_v)
                except ValueError:
                    return False, f"Invalid puts '{unquoted_v}'", {}
            elif k == "read-min":
                try:
                    tuning["read_min"] = int(unquoted_v)
                except ValueError:
                    return False, f"Invalid read-min '{unquoted_v}'", {}
            elif k == "read-max":
                try:
                    tuning["read_max"] = int(unquoted_v)
                except ValueError:
                    return False, f"Invalid read-max '{unquoted_v}'", {}
            elif k == "enc":
                if unquoted_v not in ("0", "1"):
                    return False, f"Invalid enc value '{unquoted_v}' (expected 0 or 1)", {}
                tuning["enc"] = int(unquoted_v)
            elif k == "dns":
                tuning["dns"] = unquoted_v
            elif k == "backend":
                nested_uri = unquoted_v
                if not (nested_uri.startswith("webdav://") or nested_uri.startswith("webdavs://")):
                    return False, f"Invalid nested backend scheme in '{nested_uri}'", {}
                if "?" in nested_uri or "#" in nested_uri:
                    return False, f"Nested backend must not contain query or fragment: '{nested_uri}'", {}
                b_parsed = urllib.parse.urlsplit(nested_uri)
                if not b_parsed.netloc or "@" not in b_parsed.netloc:
                    return False, f"Nested backend missing credentials in '{nested_uri}'", {}
                b_userinfo, b_hostport = b_parsed.netloc.split("@", 1)
                if ":" not in b_userinfo:
                    return False, f"Malformed nested backend credentials in '{nested_uri}'", {}
                b_enc_u, b_enc_p = b_userinfo.split(":", 1)
                b_user = urllib.parse.unquote(b_enc_u)
                b_pass = urllib.parse.unquote(b_enc_p)
                if not b_user:
                    return False, "Nested backend username cannot be empty", {}
                if not b_pass:
                    return False, "Nested backend password cannot be empty", {}
                b_path = b_parsed.path or "/"
                if not b_path.startswith("/"):
                    b_path = "/" + b_path
                b_std_scheme = "https" if b_parsed.scheme == "webdavs" else "http"
                b_std_url = f"{b_std_scheme}://{b_hostport}{b_path}"
                backends.append({
                    "url": b_std_url,
                    "username": b_user,
                    "password": b_pass,
                    "label": "",
                })

    if len(backends) > MAX_WEBDAV_BACKENDS:
        return False, f"Too many backends in URI: {len(backends)} (max {MAX_WEBDAV_BACKENDS} allowed)", {}

    ok_t, err_t, clean_tuning = validate_tuning_params(tuning)
    if not ok_t:
        return False, err_t, {}

    res = {
        "name": name,
        "url": primary_url,
        "username": user,
        "password": password,
        "backends": backends,
        **clean_tuning
    }
    return True, "", res

def compute_webdav_canonical_fingerprint(conn: dict) -> str:
    """
    Вычисляет криптографический отпечаток (SHA256) канонической конфигурации WebDAV.
    Используется для надежного распознавания повторного импорта идентичных подключений
    без создания дубликатов и без зависимости от пользовательского имени или ID.
    """
    primary_spec = {
        "url": conn.get("url", ""),
        "username": conn.get("username", ""),
        "password": conn.get("password", ""),
    }
    ok_p, _, p_clean = validate_storage_spec(primary_spec, is_primary=True)
    if not ok_p:
        p_clean = {
            "url": str(conn.get("url", "")).strip(),
            "username": str(conn.get("username", "")).strip(),
            "password": str(conn.get("password", "")).strip(),
        }

    raw_backends = conn.get("backends", [])
    if isinstance(raw_backends, str):
        try:
            raw_backends = json.loads(raw_backends)
        except Exception:
            raw_backends = []
    if not isinstance(raw_backends, list):
        raw_backends = []

    clean_backends = []
    for b in raw_backends:
        if isinstance(b, dict):
            clean_backends.append({
                "url": str(b.get("url", "")).strip(),
                "username": str(b.get("username", "")).strip(),
                "password": str(b.get("password", "")).strip(),
            })

    ok_t, _, t_clean = validate_tuning_params(conn)
    if not ok_t:
        t_clean = {
            "timeout": str(conn.get("timeout") or "60s").strip(),
            "poll_min": str(conn.get("poll_min") or "200ms").strip(),
            "poll_max": str(conn.get("poll_max") or "500ms").strip(),
            "coalesce": str(conn.get("coalesce") or "10ms").strip(),
            "chunk_size": int(conn.get("chunk_size") or 131071),
            "puts": int(conn.get("puts") or 8),
            "read_min": int(conn.get("read_min") or 3),
            "read_max": int(conn.get("read_max") or 8),
            "enc": 1 if conn.get("enc") else 0,
            "dns": str(conn.get("dns") or "").strip(),
        }

    canon_obj = {
        "primary": {
            "url": p_clean.get("url", ""),
            "username": p_clean.get("username", ""),
            "password": p_clean.get("password", ""),
        },
        "backends": clean_backends,
        "tuning": t_clean,
    }
    canon_bytes = json.dumps(canon_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon_bytes).hexdigest()

def mask_secret(val: str, prefix_len: int = 2, suffix_len: int = 2) -> str:
    """Маскирование секретов (пароли, ключи шифрования) для безопасного предпросмотра."""
    if not val:
        return ""
    val_str = str(val)
    if len(val_str) <= 6:
        return "******"
    return f"{val_str[:prefix_len]}...{val_str[-suffix_len:]}"

def compute_user_openflux_state_token(u_id: str, cfg: dict | None, groups: list) -> str:
    """Вычисляет токен состояния конфигурации OpenFlux для оптимистичной блокировки."""
    if not cfg:
        token_data = f"empty:{u_id}"
    else:
        c_dict = dict(cfg) if not isinstance(cfg, dict) else cfg
        g_ids = []
        for g in groups:
            gd = dict(g) if not isinstance(g, dict) else g
            g_ids.append(str(gd.get("id", "")))
        token_data = f"{u_id}:{c_dict.get('revision')}:{c_dict.get('connection_id')}:{','.join(g_ids)}:{c_dict.get('updated_at')}"
    return hashlib.sha256(token_data.encode("utf-8")).hexdigest()

def compute_user_webdav_state_token(u_id: str, cfg: dict | None, conns: list) -> str:
    """Вычисляет токен состояния конфигурации WebDAV для оптимистичной блокировки."""
    if not cfg:
        token_data = f"empty:{u_id}"
    else:
        c_dict = dict(cfg) if not isinstance(cfg, dict) else cfg
        c_ids = []
        for c in conns:
            cd = dict(c) if not isinstance(c, dict) else c
            c_ids.append(str(cd.get("id") or cd.get("connection_id") or ""))
        token_data = f"{u_id}:{c_dict.get('revision')}:{','.join(c_ids)}:{c_dict.get('updated_at')}"
    return hashlib.sha256(token_data.encode("utf-8")).hexdigest()

def import_server_webdav_config(env_path: str = "/etc/webdav-tunnel/config.env", server_ip: str = "127.0.0.1") -> tuple[bool, str, dict]:
    """
    Инспектирует активную конфигурацию сервера WebDAV (config.env) и строит
    объект подключения для предварительного просмотра владельцем.
    НЕ перезапускает службы и НЕ меняет файлы конфигурации.
    """
    if not os.path.isfile(env_path):
        return False, f"Server WebDAV config file not found: {env_path}", {}

    env = {}
    with open(env_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("\"'")
            env[k] = v

    mode = env.get("WEBDAV_MODE", "selfhosted").strip().lower()
    # Match runner defaults and the legacy listen-port override.
    local_port = env.get("SELFHOSTED_PORT", "18080") or "18080"
    listen_port = re.search(r":([0-9]+)$", env.get("WEBDAV_LISTEN", ""))
    if listen_port:
        local_port = listen_port.group(1)
    enc_val = env.get("WEBDAV_ENC", "false").strip().lower() in ("true", "1", "yes")
    enc = 1 if enc_val else 0

    timeout = env.get("WEBDAV_TIMEOUT", "60s").strip() or "60s"
    poll_min = env.get("WEBDAV_POLL_MIN", "200ms").strip() or "200ms"
    poll_max = env.get("WEBDAV_POLL_MAX", "500ms").strip() or "500ms"
    coalesce = env.get("WEBDAV_COALESCE", "10ms").strip() or "10ms"
    try:
        chunk_size = int(env.get("WEBDAV_CHUNK_SIZE", 131071))
    except (ValueError, TypeError):
        chunk_size = 131071
    try:
        puts = int(env.get("WEBDAV_PUTS", 8))
    except (ValueError, TypeError):
        puts = 8
    try:
        read_min = int(env.get("WEBDAV_READ_MIN", 3))
    except (ValueError, TypeError):
        read_min = 3
    try:
        read_max = int(env.get("WEBDAV_READ_MAX", 8))
    except (ValueError, TypeError):
        read_max = 8
    dns = env.get("WEBDAV_DNS", "").strip()

    storages = []

    if mode == "multi":
        loc_en = env.get("MULTI_LOCAL_ENABLED", "true").strip().lower() in ("true", "1", "yes")
        l_port = local_port
        l_user = env.get("SELFHOSTED_LOGIN", "wdav").strip() or "wdav"
        l_pass = env.get("SELFHOSTED_PASSWORD", env.get("WEBDAV_PASSWORD", "")).strip()
        if loc_en and l_pass:
            storages.append({
                "url": f"http://{server_ip}:{l_port}/",
                "username": l_user,
                "password": l_pass,
                "label": "Local Selfhosted"
            })

        m_en = env.get("MULTI_MAILRU_ENABLED", "true").strip().lower() in ("true", "1", "yes")
        m_user = env.get("MAILRU_LOGIN", env.get("MULTI_MAILRU_LOGIN", "")).strip()
        m_pass = env.get("MAILRU_PASSWORD", env.get("MULTI_MAILRU_PASSWORD", "")).strip()
        if m_en and m_user and m_pass:
            storages.append({
                "url": "https://webdav.cloud.mail.ru/",
                "username": m_user,
                "password": m_pass,
                "label": "Mail.ru Cloud"
            })

        y_en = env.get("MULTI_YANDEX_ENABLED", "false").strip().lower() in ("true", "1", "yes")
        y_user = env.get("YANDEX_LOGIN", env.get("MULTI_YANDEX_LOGIN", "")).strip()
        y_pass = env.get("YANDEX_PASSWORD", env.get("MULTI_YANDEX_PASSWORD", "")).strip()
        if y_en and y_user and y_pass:
            storages.append({
                "url": "https://webdav.yandex.ru/",
                "username": y_user,
                "password": y_pass,
                "label": "Yandex Disk"
            })

        c_en = env.get("MULTI_CUSTOM_ENABLED", "false").strip().lower() in ("true", "1", "yes")
        c_url = env.get("CUSTOM_URL", env.get("MULTI_CUSTOM_URL", "")).strip()
        c_user = env.get("CUSTOM_LOGIN", env.get("MULTI_CUSTOM_LOGIN", "")).strip()
        c_pass = env.get("CUSTOM_PASSWORD", env.get("MULTI_CUSTOM_PASSWORD", "")).strip()
        if c_en and c_url and c_user and c_pass:
            storages.append({
                "url": c_url,
                "username": c_user,
                "password": c_pass,
                "label": "Custom Storage"
            })

        if not storages:
            return False, "No configured storages enabled in multi mode", {}

        primary = storages[0]
        backends = storages[1:]
        name = "Multi-WebDAV"

    elif mode == "selfhosted":
        l_port = local_port
        l_user = env.get("SELFHOSTED_LOGIN", "wdav").strip() or "wdav"
        l_pass = env.get("SELFHOSTED_PASSWORD", env.get("WEBDAV_PASSWORD", "")).strip()
        if not l_pass:
            return False, "Selfhosted mode missing password in server config", {}
        primary = {
            "url": f"http://{server_ip}:{l_port}/",
            "username": l_user,
            "password": l_pass,
            "label": "Local Selfhosted"
        }
        backends = []
        name = "Selfhosted-WebDAV"

    elif mode == "mailru":
        m_user = env.get("MAILRU_LOGIN", env.get("MULTI_MAILRU_LOGIN", "")).strip()
        m_pass = env.get("MAILRU_PASSWORD", env.get("MULTI_MAILRU_PASSWORD", "")).strip()
        if not m_user or not m_pass:
            return False, "Mailru mode missing login or password in server config", {}
        primary = {
            "url": "https://webdav.cloud.mail.ru/",
            "username": m_user,
            "password": m_pass,
            "label": "Mail.ru Cloud"
        }
        backends = []
        name = "Mailru-WebDAV"

    elif mode == "yandex":
        y_user = env.get("YANDEX_LOGIN", env.get("MULTI_YANDEX_LOGIN", "")).strip()
        y_pass = env.get("YANDEX_PASSWORD", env.get("MULTI_YANDEX_PASSWORD", "")).strip()
        if not y_user or not y_pass:
            return False, "Yandex mode missing login or password in server config", {}
        primary = {
            "url": "https://webdav.yandex.ru/",
            "username": y_user,
            "password": y_pass,
            "label": "Yandex Disk"
        }
        backends = []
        name = "Yandex-WebDAV"

    elif mode == "custom":
        c_url = env.get("CUSTOM_URL", env.get("MULTI_CUSTOM_URL", "")).strip()
        c_user = env.get("CUSTOM_LOGIN", env.get("MULTI_CUSTOM_LOGIN", "")).strip()
        c_pass = env.get("CUSTOM_PASSWORD", env.get("MULTI_CUSTOM_PASSWORD", "")).strip()
        if not c_url or not c_user or not c_pass:
            return False, "Custom mode missing url, login or password in server config", {}
        primary = {
            "url": c_url,
            "username": c_user,
            "password": c_pass,
            "label": "Custom Storage"
        }
        backends = []
        name = "Custom-WebDAV"
    else:
        return False, f"Unknown WEBDAV_MODE: '{mode}'", {}

    conn = {
        "name": name,
        "url": primary["url"],
        "username": primary["username"],
        "password": primary["password"],
        "label": primary.get("label", ""),
        "backends": backends,
        "timeout": timeout,
        "poll_min": poll_min,
        "poll_max": poll_max,
        "coalesce": coalesce,
        "chunk_size": chunk_size,
        "puts": puts,
        "read_min": read_min,
        "read_max": read_max,
        "enc": enc,
        "dns": dns,
    }
    return True, "", conn

SNELL_SELECTION_FILE = "/etc/x-manager/snell-active.json"
SNELL_SERVICE_CONTROL_DIRS = (
    "/etc/x-manager/service-control/off",
    "/run/x-manager/service-control/stopped",
)


class SnellSelectionError(ValueError):
    """Selection errors never disclose marker contents or connection credentials."""


def snell_delivery_selection(db, user_id):
    return set(), {}, b""


class SnellSelectedConnectionGroupStore(ConnectionGroupStore):
    pass


class SubscriptionApp:
    def __init__(self, config):
        self.config = config
        self.db_path = config["database"]["path"]
        self.conn = init_database(self.db_path)
        self.bind_addr = config["server"]["bind_address"]
        self.bind_port = config["server"]["port"]
        self.public_host = str(config["server"].get("public_host") or "").strip()
        self.max_nick_len = config["limits"]["max_nickname_length"]
        self.max_uri_len = config["limits"]["max_uri_length"]
        self.max_users = config["limits"]["max_users"]
        self.issuer_id = self.get_issuer_id()
        self.connection_groups = SnellSelectedConnectionGroupStore(self.db_path, {
            'WEBDAV': parse_webdav_uri, 'OPENFLUX': deserialize_openflux_v2_bundle,
        })

    def get_issuer_id(self) -> str:
        c = self.conn.cursor()
        c.execute("SELECT value FROM server_metadata WHERE key = 'issuer_id';")
        r = c.fetchone()
        if r and r["value"]:
            return r["value"]
        new_id = str(uuid.uuid4())
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO server_metadata (key, value) VALUES ('issuer_id', ?);", (new_id,))
        return new_id

    def get_sub_url(self, raw_token: str) -> str:
        if not raw_token:
            return ""
        if self.public_host:
            host = self.public_host
        elif self.bind_addr not in ("0.0.0.0", "", "::"):
            host = self.bind_addr
        else:
            host = "127.0.0.1"
        return f"http://{host}:{self.bind_port}/sub/{raw_token}"

    def create_user(self, data: dict) -> tuple[int, dict]:
        nickname = str(data.get("nickname") or "").strip()
        ok, err = validate_nickname(nickname, self.max_nick_len)
        if not ok:
            return 400, {"error": err}

        # Поддерживаемые поля ссылок (строка или массив, с суффиксами и без)
        field_specs = [
            ("csqtt", ["csqtt_uri", "csqtt_uris", "csqtt"]),
            ("qwdtt", ["qwdtt_uri", "qwdtt_uris", "qwdtt"]),
            ("snell", ["snell_uri", "snell_uris", "snell"]),
            ("mieru", ["mieru_uri", "mieru_uris", "mieru"]),
            ("masterdnsvpn", ["masterdnsvpn_uri", "masterdnsvpn_uris", "masterdnsvpn", "dns_uri", "stormdns_uri", "dns"]),
            ("custom", ["custom_uri", "custom_uris", "custom"])
        ]

        normalized_fields = {}
        for name, keys in field_specs:
            val = None
            for k in keys:
                if k in data and data[k] is not None:
                    val = data[k]
                    break
            valid, v_err, norm_val = normalize_and_validate_uris(val, self.max_uri_len)
            if not valid:
                return 400, {"error": f"Invalid {name}: {v_err}"}
            normalized_fields[name] = norm_val

        csqtt = normalized_fields["csqtt"]
        qwdtt = normalized_fields["qwdtt"]
        snell = normalized_fields["snell"]
        mieru = normalized_fields["mieru"]
        dns   = normalized_fields["masterdnsvpn"]
        custom = normalized_fields["custom"]

        # Генерация криптографически стойкого токена
        raw_token = secrets.token_urlsafe(32)
        tok_hash = hash_token(raw_token)
        u_id = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            with self.conn:
                c = self.conn.cursor()
                # Проверка лимита пользователей
                c.execute("SELECT COUNT(*) FROM users;")
                if c.fetchone()[0] >= self.max_users:
                    return 403, {"error": f"Maximum user capacity reached ({self.max_users})"}

                c.execute("""
                    INSERT INTO users (id, nickname, csqtt_uri, qwdtt_uri, snell_uri, mieru_uri, masterdnsvpn_uri, custom_uri,
                                       enabled, subscription_token, subscription_token_hash, revision, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, ?);
                """, (u_id, nickname, csqtt, qwdtt, snell, mieru, dns, custom, raw_token, tok_hash, now, now))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{nickname}' already exists"}
        except Exception as e:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in normalized_fields.values() if v)
        sub_url = self.get_sub_url(raw_token)
        return 201, {
            "id": u_id,
            "nickname": nickname,
            "subscription_url": sub_url,
            "token": raw_token,
            "subscription_token": raw_token,
            "revision": 1,
            "enabled": True,
            "total_uris": total_uris,
            "created_at": now,
            "updated_at": now
        }

    def list_users(self) -> tuple[int, list]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users ORDER BY created_at DESC;")
        users = []
        for r in c.fetchall():
            csqtt_list = [u for u in (r["csqtt_uri"] or "").splitlines() if u.strip()]
            qwdtt_list = [u for u in (r["qwdtt_uri"] or "").splitlines() if u.strip()]
            snell_list = [u for u in (r["snell_uri"] or "").splitlines() if u.strip()]
            mieru_list = [u for u in (r["mieru_uri"] or "").splitlines() if u.strip()]
            dns_list   = [u for u in (r["masterdnsvpn_uri"] or "").splitlines() if u.strip()]
            custom_val = r["custom_uri"] if "custom_uri" in r.keys() else ""
            custom_list = [u for u in (custom_val or "").splitlines() if u.strip()]

            # Проверка OpenFlux v2
            c_of = self.conn.cursor()
            c_of.execute("SELECT enabled FROM user_openflux_config WHERE user_id = ?;", (r["id"],))
            of_row = c_of.fetchone()
            of_en = bool(of_row["enabled"]) if of_row else False
            c_of.execute("SELECT COUNT(*) FROM user_openflux_selection WHERE user_id = ?;", (r["id"],))
            of_cnt = c_of.fetchone()[0] if of_en else 0

            # Проверка WebDAV
            c_wd = self.conn.cursor()
            c_wd.execute("SELECT enabled FROM user_webdav_config WHERE user_id = ?;", (r["id"],))
            wd_row = c_wd.fetchone()
            wd_en = bool(wd_row["enabled"]) if wd_row else False
            c_wd.execute("""
                SELECT COUNT(*) FROM user_webdav_selection s
                JOIN webdav_connections c ON s.connection_id = c.id
                WHERE s.user_id = ? AND s.enabled = 1 AND c.enabled = 1;
            """, (r["id"],))
            wd_cnt = c_wd.fetchone()[0] if wd_en else 0

            external = [self._imported_openflux_item(x) for x in self._imported_openflux_rows(r["id"]) if x["enabled"]]
            total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list) + len(external)
            if of_en and of_cnt > 0:
                total_uris += 1
            if wd_en and wd_cnt > 0:
                total_uris += wd_cnt

            raw_token = r["subscription_token"] if "subscription_token" in r.keys() and r["subscription_token"] else ""
            sub_url = self.get_sub_url(raw_token)

            users.append({
                "id": r["id"],
                "nickname": r["nickname"],
                "enabled": bool(r["enabled"]),
                "revision": r["revision"],
                "total_uris": total_uris,
                "subscription_url": sub_url,
                "token": raw_token,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "protocols": {
                    "csqtt": len(csqtt_list) > 0,
                    "qwdtt": len(qwdtt_list) > 0,
                    "snell": len(snell_list) > 0,
                    "mieru": len(mieru_list) > 0,
                    "masterdnsvpn": len(dns_list) > 0,
                    "custom": len(custom_list) > 0,
                    "openflux": (of_en and of_cnt > 0) or bool(external),
                    "webdav": wd_en and wd_cnt > 0,
                },
                "counts": {
                    "csqtt": len(csqtt_list),
                    "qwdtt": len(qwdtt_list),
                    "snell": len(snell_list),
                    "mieru": len(mieru_list),
                    "masterdnsvpn": len(dns_list),
                    "custom": len(custom_list),
                    "openflux": of_cnt + sum(x["total_groups"] for x in external),
                    "webdav": wd_cnt,
                }
            })
        return 200, users

    def get_user(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
        r = c.fetchone()
        if not r:
            return 404, {"error": "User not found"}

        csqtt_list = [u for u in (r["csqtt_uri"] or "").splitlines() if u.strip()]
        qwdtt_list = [u for u in (r["qwdtt_uri"] or "").splitlines() if u.strip()]
        snell_list = [u for u in (r["snell_uri"] or "").splitlines() if u.strip()]
        mieru_list = [u for u in (r["mieru_uri"] or "").splitlines() if u.strip()]
        dns_list   = [u for u in (r["masterdnsvpn_uri"] or "").splitlines() if u.strip()]
        custom_val = r["custom_uri"] if "custom_uri" in r.keys() else ""
        custom_list = [u for u in (custom_val or "").splitlines() if u.strip()]

        # Проверка OpenFlux v2
        c_of = self.conn.cursor()
        c_of.execute("SELECT enabled FROM user_openflux_config WHERE user_id = ?;", (r["id"],))
        of_row = c_of.fetchone()
        of_en = bool(of_row["enabled"]) if of_row else False
        c_of.execute("SELECT COUNT(*) FROM user_openflux_selection WHERE user_id = ?;", (r["id"],))
        of_cnt = c_of.fetchone()[0] if of_en else 0

        # Проверка WebDAV
        c_wd = self.conn.cursor()
        c_wd.execute("SELECT enabled FROM user_webdav_config WHERE user_id = ?;", (r["id"],))
        wd_row = c_wd.fetchone()
        wd_en = bool(wd_row["enabled"]) if wd_row else False
        c_wd.execute("""
            SELECT COUNT(*) FROM user_webdav_selection s
            JOIN webdav_connections c ON s.connection_id = c.id
            WHERE s.user_id = ? AND s.enabled = 1 AND c.enabled = 1;
        """, (r["id"],))
        wd_cnt = c_wd.fetchone()[0] if wd_en else 0

        external = [self._imported_openflux_item(x) for x in self._imported_openflux_rows(r["id"]) if x["enabled"]]
        total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list) + len(external)
        if of_en and of_cnt > 0:
            total_uris += 1
        if wd_en and wd_cnt > 0:
            total_uris += wd_cnt

        raw_token = r["subscription_token"] if "subscription_token" in r.keys() and r["subscription_token"] else ""
        sub_url = self.get_sub_url(raw_token)

        return 200, {
            "id": r["id"],
            "nickname": r["nickname"],
            "subscription_url": sub_url,
            "token": raw_token,
            "subscription_token": raw_token,
            "csqtt": r["csqtt_uri"],
            "qwdtt": r["qwdtt_uri"],
            "snell": r["snell_uri"],
            "mieru": r["mieru_uri"],
            "masterdnsvpn": r["masterdnsvpn_uri"],
            "custom": custom_val,
            "csqtt_uris": csqtt_list,
            "qwdtt_uris": qwdtt_list,
            "snell_uris": snell_list,
            "mieru_uris": mieru_list,
            "masterdnsvpn_uris": dns_list,
            "custom_uris": custom_list,
            "openflux_enabled": of_en or bool(external),
            "openflux_imported_count": len(external),
            "openflux_groups_count": of_cnt + sum(x["total_groups"] for x in external),
            "webdav_enabled": wd_en,
            "webdav_connections_count": wd_cnt,
            "total_uris": total_uris,
            "enabled": bool(r["enabled"]),
            "revision": r["revision"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"]
        }

    def update_user(self, user_id: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        resolved_id = cur["id"]
        new_nick = cur["nickname"]
        if "nickname" in data:
            candidate_nick = str(data["nickname"]).strip()
            ok, err = validate_nickname(candidate_nick, self.max_nick_len)
            if not ok:
                return 400, {"error": err}
            new_nick = candidate_nick

        field_specs = [
            ("csqtt", ["csqtt_uri", "csqtt_uris", "csqtt"], cur["csqtt_uri"]),
            ("qwdtt", ["qwdtt_uri", "qwdtt_uris", "qwdtt"], cur["qwdtt_uri"]),
            ("snell", ["snell_uri", "snell_uris", "snell"], cur["snell_uri"]),
            ("mieru", ["mieru_uri", "mieru_uris", "mieru"], cur["mieru_uri"]),
            ("masterdnsvpn", ["masterdnsvpn_uri", "masterdnsvpn_uris", "masterdnsvpn", "dns_uri", "stormdns_uri", "dns"], cur["masterdnsvpn_uri"]),
            ("custom", ["custom_uri", "custom_uris", "custom"], cur["custom_uri"] if "custom_uri" in cur.keys() else ""),
        ]

        updated_fields = {}
        for name, keys, current_val in field_specs:
            found = False
            raw_val = None
            for k in keys:
                if k in data:
                    found = True
                    raw_val = data[k]
                    break
            if found:
                ok, err, norm_val = normalize_and_validate_uris(raw_val, self.max_uri_len)
                if not ok:
                    return 400, {"error": f"Invalid {name}: {err}"}
                updated_fields[name] = norm_val
            else:
                updated_fields[name] = current_val

        new_enabled = cur["enabled"]
        if "enabled" in data:
            new_enabled = 1 if data["enabled"] else 0

        new_revision = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            with self.conn:
                c.execute("""
                    UPDATE users
                    SET nickname = ?, csqtt_uri = ?, qwdtt_uri = ?, snell_uri = ?, mieru_uri = ?,
                        masterdnsvpn_uri = ?, custom_uri = ?, enabled = ?, revision = ?, updated_at = ?
                    WHERE id = ?;
                """, (new_nick, updated_fields["csqtt"], updated_fields["qwdtt"], updated_fields["snell"],
                      updated_fields["mieru"], updated_fields["masterdnsvpn"], updated_fields["custom"],
                      new_enabled, new_revision, now, resolved_id))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{new_nick}' already exists"}
        except Exception:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in updated_fields.values() if v)

        return 200, {
            "id": resolved_id,
            "nickname": new_nick,
            "csqtt": updated_fields["csqtt"],
            "qwdtt": updated_fields["qwdtt"],
            "snell": updated_fields["snell"],
            "mieru": updated_fields["mieru"],
            "masterdnsvpn": updated_fields["masterdnsvpn"],
            "custom": updated_fields["custom"],
            "csqtt_uris": [u for u in updated_fields["csqtt"].splitlines() if u.strip()],
            "qwdtt_uris": [u for u in updated_fields["qwdtt"].splitlines() if u.strip()],
            "snell_uris": [u for u in updated_fields["snell"].splitlines() if u.strip()],
            "mieru_uris": [u for u in updated_fields["mieru"].splitlines() if u.strip()],
            "masterdnsvpn_uris": [u for u in updated_fields["masterdnsvpn"].splitlines() if u.strip()],
            "custom_uris": [u for u in updated_fields["custom"].splitlines() if u.strip()],
            "total_uris": total_uris,
            "enabled": bool(new_enabled),
            "revision": new_revision,
            "updated_at": now
        }

    def delete_user(self, user_id: str) -> tuple[int, dict]:
        user_id = (user_id or "").strip()
        if not user_id:
            return 400, {"error": "User ID or nickname cannot be empty"}
        with self.conn:
            c = self.conn.cursor()
            c.execute("SELECT id FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
            cur = c.fetchone()
            if not cur:
                return 404, {"error": "User not found"}
            resolved_id = cur["id"]
            c.execute("DELETE FROM user_openflux_selection WHERE user_id = ?;", (resolved_id,))
            c.execute("DELETE FROM user_openflux_config WHERE user_id = ?;", (resolved_id,))
            c.execute("DELETE FROM user_openflux_imports WHERE user_id = ?;", (resolved_id,))
            c.execute("DELETE FROM users WHERE id = ?;", (resolved_id,))
            self.conn.commit()
        return 200, {"success": True, "message": f"User '{user_id}' deleted successfully"}

    def rotate_token(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT id, revision FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        resolved_id = cur["id"]
        new_raw_token = secrets.token_urlsafe(32)
        new_tok_hash = hash_token(new_raw_token)
        new_rev = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.conn:
            c.execute("""
                UPDATE users
                SET subscription_token = ?, subscription_token_hash = ?, revision = ?, updated_at = ?
                WHERE id = ?;
            """, (new_raw_token, new_tok_hash, new_rev, now, resolved_id))

        sub_url = self.get_sub_url(new_raw_token)
        return 200, {
            "id": resolved_id,
            "subscription_url": sub_url,
            "token": new_raw_token,
            "subscription_token": new_raw_token,
            "revision": new_rev,
            "updated_at": now
        }

    def list_openflux_groups(self) -> tuple[int, list]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups ORDER BY created_at ASC;")
        res = []
        for r in c.fetchall():
            try:
                urls = json.loads(r["urls_json"])
            except Exception:
                urls = []
            res.append({
                "id": r["id"],
                "name": r["name"],
                "mode": r["mode"],
                "transport": r["transport"],
                "urls": urls,
                "codec": r["codec"],
                "encryption_key": r["encryption_key"] or "",
                "source_slot": r["source_slot"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return 200, res

    def get_openflux_group(self, group_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups WHERE id = ? OR name = ?;", (group_id, group_id))
        r = c.fetchone()
        if not r:
            return 404, {"error": "OpenFlux group not found"}
        try:
            urls = json.loads(r["urls_json"])
        except Exception:
            urls = []
        return 200, {
            "id": r["id"],
            "name": r["name"],
            "mode": r["mode"],
            "transport": r["transport"],
            "urls": urls,
            "codec": r["codec"],
            "encryption_key": r["encryption_key"] or "",
            "source_slot": r["source_slot"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def create_openflux_group(self, data: dict) -> tuple[int, dict]:
        name = str(data.get("name") or "").strip()
        if not name or len(name) > MAX_OPENFLUX_NAME_CODEPOINTS:
            return 400, {"error": f"Group name is required and must be between 1 and {MAX_OPENFLUX_NAME_CODEPOINTS} characters"}

        mode = str(data.get("mode") or "classic").strip().lower()
        if mode not in ALLOWED_OPENFLUX_MODES:
            return 400, {"error": f"Invalid mode '{mode}'. Allowed: {', '.join(sorted(ALLOWED_OPENFLUX_MODES))}"}

        transport = str(data.get("transport") or "").strip().lower()
        if transport not in ALLOWED_OPENFLUX_TRANSPORTS:
            return 400, {"error": f"Invalid transport '{transport}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}"}

        codec = str(data.get("codec") or "legacy").strip().lower()
        if codec not in ALLOWED_OPENFLUX_CODECS:
            return 400, {"error": f"Invalid codec '{codec}'. Allowed: {', '.join(sorted(ALLOWED_OPENFLUX_CODECS))}"}

        raw_urls = data.get("urls")
        urls = []
        if isinstance(raw_urls, str):
            for line in raw_urls.splitlines():
                s = line.strip()
                if s:
                    if "," in s:
                        return 400, {"error": f"URL '{s}' cannot contain literal comma"}
                    urls.append(s)
        elif isinstance(raw_urls, list):
            for item in raw_urls:
                if isinstance(item, str):
                    s = item.strip()
                    if s:
                        if "," in s:
                            return 400, {"error": f"URL '{s}' cannot contain literal comma"}
                        urls.append(s)
                else:
                    return 400, {"error": "All URLs must be strings"}
        else:
            return 400, {"error": "Field 'urls' must be a string or list of strings"}

        if mode == "classic" and len(urls) != 1:
            return 400, {"error": f"Classic mode requires exactly 1 URL (provided: {len(urls)})"}
        if mode == "multistream" and not (1 <= len(urls) <= 4):
            return 400, {"error": f"Multistream mode requires 1 to 4 URLs (provided: {len(urls)})"}

        seen_u = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u, transport)
            if not ok_u:
                return 400, {"error": f"Invalid URL '{u}': {err_u}"}
            if u in seen_u:
                return 400, {"error": f"Duplicate URL in group: '{u}'"}
            seen_u.add(u)

        encryption_key = str(data.get("encryption_key") or "").strip()
        if encryption_key:
            key_bytes = encryption_key.encode("utf-8")
            if not (MIN_ENCRYPTION_KEY_BYTES <= len(key_bytes) <= MAX_ENCRYPTION_KEY_BYTES):
                return 400, {"error": f"Encryption key length must be between {MIN_ENCRYPTION_KEY_BYTES} and {MAX_ENCRYPTION_KEY_BYTES} bytes (got {len(key_bytes)})"}

        source_slot = data.get("source_slot")
        if source_slot is not None:
            try:
                source_slot = int(source_slot)
                if not (1 <= source_slot <= 8):
                    source_slot = None
            except Exception:
                source_slot = None

        group_id = str(data.get("id") or "").strip().lower()
        if not group_id:
            group_id = str(uuid.uuid4()).lower()
        else:
            if not is_canonical_uuid(group_id):
                return 400, {"error": f"Invalid group ID format (must be canonical lowercase UUID): '{group_id}'"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                c = self.conn.cursor()
                c.execute("""
                    INSERT INTO openflux_groups (id, name, mode, transport, urls_json, codec, encryption_key, source_slot, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (group_id, name, mode, transport, json.dumps(urls), codec, encryption_key, source_slot, now, now))
        except sqlite3.IntegrityError:
            return 409, {"error": f"OpenFlux group with ID '{group_id}' already exists"}
        except Exception as e:
            return 500, {"error": f"Internal database error: {e}"}

        return 201, {
            "id": group_id,
            "name": name,
            "mode": mode,
            "transport": transport,
            "urls": urls,
            "codec": codec,
            "encryption_key": encryption_key,
            "source_slot": source_slot,
            "created_at": now,
            "updated_at": now,
        }

    def update_openflux_group(self, group_id: str, data: dict) -> tuple[int, dict]:
        group_id = str(group_id).strip().lower()
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups WHERE id = ?;", (group_id,))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "OpenFlux group not found"}

        name = cur["name"]
        if "name" in data:
            candidate_name = str(data["name"]).strip()
            if not candidate_name or len(candidate_name) > MAX_OPENFLUX_NAME_CODEPOINTS:
                return 400, {"error": f"Group name must be between 1 and {MAX_OPENFLUX_NAME_CODEPOINTS} characters"}
            name = candidate_name

        mode = cur["mode"]
        if "mode" in data:
            candidate_mode = str(data["mode"]).strip().lower()
            if candidate_mode not in ALLOWED_OPENFLUX_MODES:
                return 400, {"error": f"Invalid mode '{candidate_mode}'"}
            mode = candidate_mode

        transport = cur["transport"]
        if "transport" in data:
            candidate_transport = str(data["transport"]).strip().lower()
            if candidate_transport not in ALLOWED_OPENFLUX_TRANSPORTS:
                return 400, {"error": f"Invalid transport '{candidate_transport}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}"}
            transport = candidate_transport

        codec = cur["codec"]
        if "codec" in data:
            candidate_codec = str(data["codec"]).strip().lower()
            if candidate_codec not in ALLOWED_OPENFLUX_CODECS:
                return 400, {"error": f"Invalid codec '{candidate_codec}'"}
            codec = candidate_codec

        encryption_key = cur["encryption_key"] or ""
        if "encryption_key" in data:
            candidate_key = str(data["encryption_key"]).strip()
            if candidate_key:
                k_bytes = candidate_key.encode("utf-8")
                if not (MIN_ENCRYPTION_KEY_BYTES <= len(k_bytes) <= MAX_ENCRYPTION_KEY_BYTES):
                    return 400, {"error": f"Encryption key length must be between {MIN_ENCRYPTION_KEY_BYTES} and {MAX_ENCRYPTION_KEY_BYTES} bytes"}
            encryption_key = candidate_key

        source_slot = cur["source_slot"]
        if "source_slot" in data:
            val = data["source_slot"]
            if val is not None:
                try:
                    source_slot = int(val)
                except Exception:
                    pass
            else:
                source_slot = None

        if "urls" in data:
            raw_urls = data["urls"]
            urls = []
            if isinstance(raw_urls, str):
                for line in raw_urls.splitlines():
                    s = line.strip()
                    if s:
                        if "," in s:
                            return 400, {"error": f"URL '{s}' cannot contain literal comma"}
                        urls.append(s)
            elif isinstance(raw_urls, list):
                for item in raw_urls:
                    if isinstance(item, str):
                        s = item.strip()
                        if s:
                            if "," in s:
                                return 400, {"error": f"URL '{s}' cannot contain literal comma"}
                            urls.append(s)
                    else:
                        return 400, {"error": "All URLs must be strings"}
            else:
                return 400, {"error": "Field 'urls' must be a string or list of strings"}
        else:
            try:
                urls = json.loads(cur["urls_json"])
            except Exception:
                urls = []

        if mode == "classic" and len(urls) != 1:
            return 400, {"error": f"Classic mode requires exactly 1 URL (provided: {len(urls)})"}
        if mode == "multistream" and not (1 <= len(urls) <= 4):
            return 400, {"error": f"Multistream mode requires 1 to 4 URLs (provided: {len(urls)})"}

        seen_u = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u, transport)
            if not ok_u:
                return 400, {"error": f"Invalid URL '{u}': {err_u}"}
            if u in seen_u:
                return 400, {"error": f"Duplicate URL in group: '{u}'"}
            seen_u.add(u)

        # Проверка влияния обновления на активных пользователей до совершения commit
        c.execute("""
            SELECT DISTINCT u.user_id, cfg.connection_id, cfg.name, cfg.mode, cfg.balancer_strategy, cfg.revision, usr.nickname
            FROM user_openflux_selection u
            JOIN user_openflux_config cfg ON u.user_id = cfg.user_id
            JOIN users usr ON u.user_id = usr.id
            WHERE u.group_id = ? AND cfg.enabled = 1;
        """, (group_id,))
        affected_user_rows = c.fetchall()

        for u_row in affected_user_rows:
            u_id = u_row["user_id"]
            u_nick = u_row["nickname"]
            c.execute("""
                SELECT g.* FROM user_openflux_selection s
                JOIN openflux_groups g ON s.group_id = g.id
                WHERE s.user_id = ?
                ORDER BY s.position ASC;
            """, (u_id,))
            sim_groups = []
            for grp_row in c.fetchall():
                if grp_row["id"] == group_id:
                    sim_groups.append({
                        "id": group_id,
                        "name": name,
                        "mode": mode,
                        "transport": transport,
                        "urls": urls,
                        "codec": codec,
                        "encryption_key": encryption_key,
                    })
                else:
                    try:
                        g_u = json.loads(grp_row["urls_json"])
                    except Exception:
                        g_u = []
                    sim_groups.append({
                        "id": grp_row["id"],
                        "name": grp_row["name"],
                        "mode": grp_row["mode"],
                        "transport": grp_row["transport"],
                        "urls": g_u,
                        "codec": grp_row["codec"],
                        "encryption_key": grp_row["encryption_key"] or "",
                    })
            ok_sim, err_sim, _ = build_openflux_v2_payload(
                self.issuer_id,
                u_row["connection_id"],
                u_row["revision"] + 1,
                u_row["name"],
                u_row["mode"],
                u_row["balancer_strategy"],
                sim_groups
            )
            if not ok_sim:
                return 400, {"error": f"Cannot update group: would invalidate active OpenFlux bundle for user '{u_nick}': {err_sim}"}

        cur_urls = []
        try:
            cur_urls = json.loads(cur["urls_json"])
        except Exception:
            pass

        content_changed = (
            name != cur["name"] or
            mode != cur["mode"] or
            transport != cur["transport"] or
            codec != cur["codec"] or
            encryption_key != (cur["encryption_key"] or "") or
            urls != cur_urls or
            source_slot != cur["source_slot"]
        )

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if content_changed:
            try:
                with self.conn:
                    c.execute("""
                        UPDATE openflux_groups
                        SET name = ?, mode = ?, transport = ?, urls_json = ?, codec = ?,
                            encryption_key = ?, source_slot = ?, updated_at = ?
                        WHERE id = ?;
                    """, (name, mode, transport, json.dumps(urls), codec, encryption_key, source_slot, now, group_id))

                    # Автоматический инкремент ревизии для всех пользователей, выбравших эту группу
                    c.execute("SELECT DISTINCT user_id FROM user_openflux_selection WHERE group_id = ?;", (group_id,))
                    affected_users = [row[0] for row in c.fetchall()]
                    for u_id in affected_users:
                        c.execute("""
                            UPDATE user_openflux_config
                            SET revision = revision + 1, updated_at = ?
                            WHERE user_id = ?;
                        """, (now, u_id))
                        c.execute("""
                            UPDATE users
                            SET revision = revision + 1, updated_at = ?
                            WHERE id = ?;
                        """, (now, u_id))
            except Exception as e:
                return 500, {"error": f"Database update error: {e}"}

        return 200, {
            "id": group_id,
            "name": name,
            "mode": mode,
            "transport": transport,
            "urls": urls,
            "codec": codec,
            "encryption_key": encryption_key,
            "source_slot": source_slot,
            "created_at": cur["created_at"],
            "updated_at": now if content_changed else cur["updated_at"],
        }

    def delete_openflux_group(self, group_id: str) -> tuple[int, dict]:
        group_id = str(group_id).strip().lower()
        c = self.conn.cursor()
        c.execute("SELECT id FROM openflux_groups WHERE id = ?;", (group_id,))
        if not c.fetchone():
            return 404, {"error": "OpenFlux group not found"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                c.execute("SELECT DISTINCT user_id FROM user_openflux_selection WHERE group_id = ?;", (group_id,))
                affected_users = [row[0] for row in c.fetchall()]

                c.execute("DELETE FROM openflux_groups WHERE id = ?;", (group_id,))
                c.execute("DELETE FROM user_openflux_selection WHERE group_id = ?;", (group_id,))

                for u_id in affected_users:
                    c.execute("""
                        UPDATE user_openflux_config
                        SET revision = revision + 1, updated_at = ?
                        WHERE user_id = ?;
                    """, (now, u_id))
                    c.execute("""
                        UPDATE users
                        SET revision = revision + 1, updated_at = ?
                        WHERE id = ?;
                    """, (now, u_id))
                    c.execute("SELECT group_id FROM user_openflux_selection WHERE user_id = ? ORDER BY position ASC;", (u_id,))
                    remaining = [row[0] for row in c.fetchall()]
                    if not remaining:
                        c.execute("UPDATE user_openflux_config SET enabled = 0 WHERE user_id = ?;", (u_id,))
                    for pos, gid in enumerate(remaining):
                        c.execute("UPDATE user_openflux_selection SET position = ? WHERE user_id = ? AND group_id = ?;", (pos, u_id, gid))
        except Exception as e:
            return 500, {"error": f"Database delete error: {e}"}

        return 200, {"success": True, "message": f"OpenFlux group '{group_id}' deleted successfully"}

    def get_user_openflux(self, user_id_or_nick: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
        of_cfg = c.fetchone()

        if not of_cfg:
            stable_conn_id = str(uuid.uuid4()).lower()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.conn:
                self.conn.execute("""
                    INSERT INTO user_openflux_config (user_id, enabled, connection_id, name, mode, balancer_strategy, revision, updated_at)
                    VALUES (?, 0, ?, ?, 'classic', 'roundRobin', 1, ?);
                """, (u_id, stable_conn_id, f"TUNA-{user['nickname']}", now))
            c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
            of_cfg = c.fetchone()

        c.execute("""
            SELECT g.* FROM user_openflux_selection s
            JOIN openflux_groups g ON s.group_id = g.id
            WHERE s.user_id = ?
            ORDER BY s.position ASC;
        """, (u_id,))
        sel_groups = c.fetchall()

        groups_res = []
        group_ids = []
        total_urls = 0
        for g in sel_groups:
            try:
                urls = json.loads(g["urls_json"])
            except Exception:
                urls = []
            group_ids.append(g["id"])
            total_urls += len(urls)
            groups_res.append({
                "id": g["id"],
                "name": g["name"],
                "mode": g["mode"],
                "transport": g["transport"],
                "urls": urls,
                "codec": g["codec"],
                "encryption_key": g["encryption_key"] or "",
                "source_slot": g["source_slot"],
                "created_at": g["created_at"],
                "updated_at": g["updated_at"],
            })

        v2_uri = ""
        bundle_payload = None
        if of_cfg["enabled"] and 1 <= len(groups_res) <= 8:
            ok_b, _, b_dict = build_openflux_v2_payload(
                self.issuer_id,
                of_cfg["connection_id"],
                int(of_cfg["revision"]),
                of_cfg["name"],
                of_cfg["mode"],
                of_cfg["balancer_strategy"],
                groups_res
            )
            if ok_b:
                ok_ser, _, uri_res = serialize_openflux_v2_bundle(b_dict)
                if ok_ser:
                    v2_uri = uri_res
                    bundle_payload = b_dict

        return 200, {
            "user_id": u_id,
            "nickname": user["nickname"],
            "enabled": bool(of_cfg["enabled"]),
            "connection_id": of_cfg["connection_id"],
            "name": of_cfg["name"],
            "mode": of_cfg["mode"],
            "balancer_strategy": of_cfg["balancer_strategy"],
            "revision": of_cfg["revision"],
            "group_ids": group_ids,
            "groups": groups_res,
            "total_groups": len(groups_res),
            "total_urls": total_urls,
            "v2_uri": v2_uri,
            "bundle_payload": bundle_payload,
            "imported_connections": [self._imported_openflux_item(r) for r in self._imported_openflux_rows(u_id)],
            "updated_at": of_cfg["updated_at"],
        }

    def update_user_openflux(self, user_id_or_nick: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
        cur = c.fetchone()
        if not cur:
            stable_conn_id = str(uuid.uuid4()).lower()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.conn:
                self.conn.execute("""
                    INSERT INTO user_openflux_config (user_id, enabled, connection_id, name, mode, balancer_strategy, revision, updated_at)
                    VALUES (?, 0, ?, ?, 'classic', 'roundRobin', 1, ?);
                """, (u_id, stable_conn_id, f"TUNA-{user['nickname']}", now))
            c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
            cur = c.fetchone()

        new_conn_id = cur["connection_id"]
        if "connection_id" in data or "id" in data:
            cand_id = str(data.get("connection_id") or data.get("id")).strip().lower()
            if not is_canonical_uuid(cand_id):
                return 400, {"error": f"Field 'connection_id' must be a canonical lowercase UUID: '{cand_id}'"}
            new_conn_id = cand_id

        new_enabled = cur["enabled"]
        if "enabled" in data:
            new_enabled = 1 if data["enabled"] else 0

        name = cur["name"]
        if "name" in data:
            candidate_name = str(data["name"]).strip()
            if not candidate_name or len(candidate_name) > MAX_OPENFLUX_NAME_CODEPOINTS:
                return 400, {"error": f"Connection name must be between 1 and {MAX_OPENFLUX_NAME_CODEPOINTS} characters"}
            name = candidate_name

        mode = cur["mode"]
        if "mode" in data:
            candidate_mode = str(data["mode"]).strip().lower()
            if candidate_mode not in ALLOWED_OPENFLUX_MODES:
                return 400, {"error": f"Invalid mode '{candidate_mode}'"}
            mode = candidate_mode

        balancer_strategy = cur["balancer_strategy"]
        if "balancer_strategy" in data:
            candidate_strat = str(data["balancer_strategy"]).strip()
            if candidate_strat not in ALLOWED_BALANCER_STRATEGIES:
                return 400, {"error": f"Invalid balancer_strategy '{candidate_strat}'. Allowed: {', '.join(sorted(ALLOWED_BALANCER_STRATEGIES))}"}
            balancer_strategy = candidate_strat

        if "group_ids" in data:
            raw_gids = data["group_ids"]
            if not isinstance(raw_gids, list):
                return 400, {"error": "Field 'group_ids' must be a list of group IDs"}
            group_ids = [str(gid).strip().lower() for gid in raw_gids if str(gid).strip()]
        else:
            c.execute("SELECT group_id FROM user_openflux_selection WHERE user_id = ? ORDER BY position ASC;", (u_id,))
            group_ids = [r[0] for r in c.fetchall()]

        if len(group_ids) != len(set(group_ids)):
            return 400, {"error": "Duplicate group IDs in selection are not allowed"}

        if new_enabled:
            if not (1 <= len(group_ids) <= 8):
                return 400, {"error": f"Active OpenFlux bundle requires between 1 and 8 groups (provided: {len(group_ids)})"}

        groups_to_attach = []
        for gid in group_ids:
            c.execute("SELECT * FROM openflux_groups WHERE id = ?;", (gid,))
            g = c.fetchone()
            if not g:
                return 400, {"error": f"Referenced OpenFlux group '{gid}' does not exist"}
            try:
                g_urls = json.loads(g["urls_json"])
            except Exception:
                g_urls = []
            groups_to_attach.append({
                "id": g["id"],
                "name": g["name"],
                "mode": g["mode"],
                "transport": g["transport"],
                "urls": g_urls,
                "codec": g["codec"],
                "encryption_key": g["encryption_key"] or "",
            })

        if new_enabled:
            ok_v, err_v, _ = build_openflux_v2_payload(
                self.issuer_id,
                new_conn_id,
                cur["revision"] + 1,
                name,
                mode,
                balancer_strategy,
                groups_to_attach
            )
            if not ok_v:
                return 400, {"error": f"Invalid OpenFlux bundle configuration: {err_v}"}

        c.execute("SELECT group_id FROM user_openflux_selection WHERE user_id = ? ORDER BY position ASC;", (u_id,))
        cur_group_ids = [r[0] for r in c.fetchall()]

        content_changed = (
            new_enabled != cur["enabled"] or
            name != cur["name"] or
            mode != cur["mode"] or
            balancer_strategy != cur["balancer_strategy"] or
            new_conn_id != cur["connection_id"] or
            group_ids != cur_group_ids
        )

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if content_changed:
            new_rev = cur["revision"] + 1
            try:
                with self.conn:
                    c.execute("""
                        UPDATE user_openflux_config
                        SET enabled = ?, connection_id = ?, name = ?, mode = ?, balancer_strategy = ?, revision = ?, updated_at = ?
                        WHERE user_id = ?;
                    """, (new_enabled, new_conn_id, name, mode, balancer_strategy, new_rev, now, u_id))

                    c.execute("DELETE FROM user_openflux_selection WHERE user_id = ?;", (u_id,))
                    for pos, gid in enumerate(group_ids):
                        c.execute("""
                            INSERT INTO user_openflux_selection (user_id, group_id, position)
                            VALUES (?, ?, ?);
                        """, (u_id, gid, pos))

                    c.execute("""
                        UPDATE users
                        SET revision = revision + 1, updated_at = ?
                        WHERE id = ?;
                    """, (now, u_id))
            except Exception as e:
                return 500, {"error": f"Database error updating OpenFlux user config: {e}"}

        return self.get_user_openflux(u_id)

    def export_user_openflux(self, user_id_or_nick: str) -> tuple[int, dict]:
        """
        Экспорт полного снимка настроек OpenFlux v2 для пользователя в виде переносимого URI.
        Независим от флага публикации (enabled) в подписке: работает при включенной и выключенной публикации.
        НЕ создает ленивых записей в БД (чистый read-only, вернет 404 если настройки нет).
        НЕ изменяет revision, ID или данные.
        Содержит неискаженные секреты (unmasked encryption_key) по каноническому контракту v2.
        """
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
        of_cfg = c.fetchone()
        if not of_cfg:
            return 404, {"error": f"OpenFlux configuration not found for user '{user['nickname']}'"}

        c.execute("""
            SELECT g.* FROM user_openflux_selection s
            JOIN openflux_groups g ON s.group_id = g.id
            WHERE s.user_id = ?
            ORDER BY s.position ASC;
        """, (u_id,))
        sel_groups = c.fetchall()
        if not sel_groups or len(sel_groups) < 1:
            return 400, {"error": f"No OpenFlux groups configured for user '{user['nickname']}'"}
        if len(sel_groups) > MAX_BUNDLE_GROUPS:
            return 400, {"error": f"Too many groups ({len(sel_groups)}) for OpenFlux bundle (max {MAX_BUNDLE_GROUPS})"}

        wire_groups = []
        for g in sel_groups:
            try:
                raw_urls = json.loads(g["urls_json"])
            except Exception:
                raw_urls = []
            wire_groups.append({
                "id": g["id"],
                "name": g["name"],
                "transport": g["transport"],
                "urls": raw_urls,
                "codec": g["codec"],
                "encryption_key": g["encryption_key"] or "",
            })

        ok_b, err_b, payload = build_openflux_v2_payload(
            self.issuer_id,
            of_cfg["connection_id"],
            int(of_cfg["revision"]),
            of_cfg["name"],
            of_cfg["mode"],
            of_cfg["balancer_strategy"],
            wire_groups
        )
        if not ok_b:
            return 400, {"error": f"Failed to build OpenFlux export bundle: {err_b}"}

        ok_s, err_s, full_uri = serialize_openflux_v2_bundle(payload)
        if not ok_s:
            return 500, {"error": f"Failed to serialize OpenFlux bundle URI: {err_s}"}

        return 200, {
            "success": True,
            "uri": full_uri,
            "payload": payload,
            "user_id": u_id,
            "nickname": user["nickname"],
            "enabled": bool(of_cfg["enabled"]),
            "revision": int(of_cfg["revision"]),
        }

    def _imported_openflux_rows(self, user_id):
        return self.conn.execute("SELECT * FROM user_openflux_imports WHERE user_id=? ORDER BY rowid", (user_id,)).fetchall()

    @staticmethod
    def _imported_openflux_token(user, rows):
        state = [user['id'], user['revision'], [(r['id'], r['uri'], r['enabled']) for r in rows]]
        return hashlib.sha256(json.dumps(state, ensure_ascii=False).encode()).hexdigest()

    @staticmethod
    def _imported_openflux_item(row):
        ok, error, payload = deserialize_openflux_v2_bundle(row['uri'])
        if not ok:
            raise ValueError('Stored imported OpenFlux bundle is invalid')
        return {'import_id': row['id'], 'enabled': bool(row['enabled']), 'uri': row['uri'],
                'name': payload['name'], 'connection_id': payload['id'],
                'source_issuer_id': payload['issuer_id'], 'revision': payload['revision'],
                'mode': payload['mode'], 'balancer_strategy': payload['balancer_strategy'],
                'total_groups': len(payload['groups']), 'total_urls': sum(len(g['urls']) for g in payload['groups']),
                'groups': payload['groups'], 'payload': payload}

    def list_imported_openflux(self, user_id_or_nick):
        user = self.conn.execute('SELECT * FROM users WHERE id=? OR nickname=?', (user_id_or_nick, user_id_or_nick)).fetchone()
        if not user:
            return 404, {'error': 'User not found'}
        rows = self._imported_openflux_rows(user['id'])
        try:
            items = [self._imported_openflux_item(r) for r in rows]
        except ValueError as exc:
            return 500, {'error': str(exc)}
        return 200, {'connections': items, 'state_token': self._imported_openflux_token(user, rows)}

    def import_user_openflux(self, user_id_or_nick: str, data: dict) -> tuple[int, dict]:
        """Add an independent remote bundle; never replace local settings or catalog.

        Identity and wire payload are preserved. Exact repeats are no-ops; conflicting
        reuse of an identity requires explicitly removing the old imported entry first.
        """
        if data.get('uri'):
            if not isinstance(data['uri'], str):
                return 400, {'error': 'uri must be a string'}
            ok, error, payload = deserialize_openflux_v2_bundle(data['uri'].strip())
        elif isinstance(data.get('payload'), dict):
            payload = data['payload']
            ok, error = validate_openflux_v2_payload(payload)
        else:
            return 400, {'error': "Either 'uri' or 'payload' is required"}
        if not ok:
            return 400, {'error': error}
        ok, error, uri = serialize_openflux_v2_bundle(payload)
        if not ok:
            return 400, {'error': error}
        # A separate connection serializes commits against all other SQLite writers.
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                user = db.execute('SELECT * FROM users WHERE id=? OR nickname=?', (user_id_or_nick, user_id_or_nick)).fetchone()
                if not user:
                    return 404, {'error': 'User not found'}
                uid = user['id']
                rows = db.execute('SELECT * FROM user_openflux_imports WHERE user_id=? ORDER BY rowid', (uid,)).fetchall()
                state_token = self._imported_openflux_token(user, rows)
                existing = next((r for r in rows if r['source_issuer_id']==payload['issuer_id'] and r['source_connection_id']==payload['id']), None)
                local = db.execute('SELECT * FROM user_openflux_config WHERE user_id=?', (uid,)).fetchone()
                local_identical = False
                if local and local['connection_id']==payload['id'] and self.issuer_id==payload['issuer_id']:
                    code, exported = self.export_user_openflux(uid)
                    local_identical = code==200 and exported['uri']==uri
                    if not local_identical:
                        return 409, {'error': 'This identity belongs to the original connection. Import cannot overwrite it.'}
                if existing and existing['uri']!=uri:
                    return 409, {'error': 'This remote connection is already imported with different settings. Remove that imported entry explicitly before importing a replacement; the original connection is unchanged.'}
                identical = bool(existing or local_identical)
                if not data.get('commit') or data.get('preview_only') is True:
                    return 200, {'success': True, 'preview': True, 'is_identical': identical,
                        'state_token': state_token, 'operation': 'add_connection',
                        'incoming_config': {'name': payload['name'], 'mode': payload['mode'],
                            'balancer_strategy': payload['balancer_strategy'], 'groups_count': len(payload['groups']),
                            'groups': [{'name': g['name'], 'transport': g['transport'], 'codec': g['codec'],
                                        'urls_count': len(g['urls']), 'has_encryption': bool(g.get('encryption_key'))} for g in payload['groups']]}}
                if data.get('expected_state_token') and data['expected_state_token']!=state_token:
                    return 409, {'error': 'Configuration changed since preview. Please request a new preview before committing.'}
                if identical:
                    item = self._imported_openflux_item(existing) if existing else {'connection_id': payload['id'], 'revision': payload['revision']}
                    return 200, dict(item, success=True, no_op=True)
                if sum(len(r['uri'].encode())+1 for r in rows)+len(uri.encode()) > MAX_SUBSCRIPTION_RESPONSE_BYTES:
                    return 400, {'error': 'Imported connections exceed subscription size limit'}
                item_id = str(uuid.uuid4())
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                db.execute('INSERT INTO user_openflux_imports (id,user_id,source_issuer_id,source_connection_id,uri,enabled,created_at) VALUES (?,?,?,?,?,1,?)',
                           (item_id,uid,payload['issuer_id'],payload['id'],uri,now))
                db.execute('UPDATE users SET revision=revision+1,updated_at=? WHERE id=?', (now,uid))
                row = db.execute('SELECT * FROM user_openflux_imports WHERE id=?', (item_id,)).fetchone()
                return 200, dict(self._imported_openflux_item(row), success=True, no_op=False)
        except sqlite3.Error:
            return 500, {'error': 'Imported connection transaction failed; no changes committed'}
        finally:
            db.close()

    def change_imported_openflux(self, user_id_or_nick, item_id, data):
        action = data.get('action')
        if action not in ('enable', 'disable', 'delete'):
            return 400, {'error': 'Expected enable, disable or delete'}
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute('BEGIN IMMEDIATE')
                user = db.execute('SELECT * FROM users WHERE id=? OR nickname=?', (user_id_or_nick,user_id_or_nick)).fetchone()
                if not user:
                    return 404, {'error': 'User not found'}
                rows = db.execute('SELECT * FROM user_openflux_imports WHERE user_id=? ORDER BY rowid', (user['id'],)).fetchall()
                if data.get('expected_state_token') != self._imported_openflux_token(user, rows):
                    return 409, {'error': 'Configuration changed since preview. Reload the list.'}
                row = next((r for r in rows if r['id']==item_id), None)
                if not row:
                    return 404, {'error': 'Imported connection not found'}
                if action!='delete' and bool(row['enabled'])==(action=='enable'):
                    return 200, {'success': True, 'no_op': True}
                if action=='delete':
                    db.execute('DELETE FROM user_openflux_imports WHERE id=? AND user_id=?', (item_id,user['id']))
                else:
                    db.execute('UPDATE user_openflux_imports SET enabled=? WHERE id=? AND user_id=?', (int(action=='enable'),item_id,user['id']))
                db.execute('UPDATE users SET revision=revision+1,updated_at=? WHERE id=?', (datetime.datetime.now(datetime.timezone.utc).isoformat(),user['id']))
                return 200, {'success': True}
        except sqlite3.Error:
            return 500, {'error': 'Imported connection transaction failed; no changes committed'}
        finally:
            db.close()

    def import_local_openflux_groups(self, instances_dir: str = "/etc/openflux/instances", pool_mode_file: str = "/etc/openflux/pool.mode") -> tuple[int, dict]:
        """
        Безопасный импорт локально настроенных инстансов OpenFlux (слоты 1..8) в каталог БД.
        Парсинг без eval/source/sh.
        - Разделение URL строго по буквальной запятой (',')
        - Сохранение параметров query/fragment/+, без декодирования %2C
        - Композитный ключ (source_slot, mode): classic не затирает multistream
        - Сохранение пользовательских названий групп
        - Инкремент revision только при реальном изменении содержания
        """
        pool_mode = "classic"
        if os.path.isfile(pool_mode_file):
            try:
                with open(pool_mode_file, "r", encoding="utf-8") as f:
                    content = f.read().strip().lower()
                    if content in ALLOWED_OPENFLUX_MODES:
                        pool_mode = content
            except Exception:
                pass

        if not os.path.isdir(instances_dir):
            return 404, {"error": f"Instances directory '{instances_dir}' not found", "imported_count": 0, "groups": []}

        imported_groups = []
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        for slot in range(1, 9):
            env_path = os.path.join(instances_dir, f"{slot}.env")
            if not os.path.isfile(env_path):
                continue

            props = {}
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f.read().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        props[k] = v
            except Exception:
                continue

            url_raw = props.get("URL", "").strip()
            if not url_raw:
                continue

            # Разделение строго по запятым без декодирования %2C
            urls = []
            for part in url_raw.split(","):
                u_str = part.strip()
                if u_str:
                    urls.append(u_str)

            if not urls:
                continue

            transport = props.get("TRANSPORT", "").strip().lower()
            if transport not in ALLOWED_OPENFLUX_TRANSPORTS:
                continue

            # Валидация каждого URL документа
            urls_valid = True
            for u in urls:
                ok_u, _ = validate_openflux_url(u, transport)
                if not ok_u:
                    urls_valid = False
                    break
            if not urls_valid:
                continue

            # Проверка дубликатов внутри слота
            if len(urls) != len(set(urls)):
                continue

            # Кодек: отклоняем неизвестный кодек без подстановки legacy
            raw_codec = props.get("CODEC", "").strip().lower()
            if not raw_codec:
                codec = "legacy"
            elif raw_codec not in ALLOWED_OPENFLUX_CODECS:
                continue
            else:
                codec = raw_codec

            enc_key = props.get("ENCRYPTION_KEY", "").strip()
            if enc_key:
                k_bytes = enc_key.encode("utf-8")
                if not (MIN_ENCRYPTION_KEY_BYTES <= len(k_bytes) <= MAX_ENCRYPTION_KEY_BYTES):
                    continue

            slot_mode = props.get("POOL_MODE", pool_mode).strip().lower()
            if slot_mode not in ALLOWED_OPENFLUX_MODES:
                slot_mode = pool_mode

            # Строгая проверка количества документов без молчаливого усечения
            if slot_mode == "classic" and len(urls) != 1:
                continue
            elif slot_mode == "multistream" and not (1 <= len(urls) <= 4):
                continue

            # Поиск по стабильному композитному ключу (source_slot, mode)
            c = self.conn.cursor()
            c.execute("SELECT * FROM openflux_groups WHERE source_slot = ? AND mode = ?;", (slot, slot_mode))
            existing = c.fetchone()

            if existing:
                grp_id = existing["id"]
                name = existing["name"]  # Сохраняем имя, заданное пользователем
                try:
                    existing_urls = json.loads(existing["urls_json"])
                except Exception:
                    existing_urls = []

                content_changed = (
                    existing["transport"] != transport or
                    existing_urls != urls or
                    existing["codec"] != codec or
                    (existing["encryption_key"] or "") != enc_key
                )

                if content_changed:
                    # Валидация влияния на активных пользователей до сохранения
                    c.execute("""
                        SELECT DISTINCT u.user_id, cfg.connection_id, cfg.name, cfg.mode, cfg.balancer_strategy, cfg.revision, usr.nickname
                        FROM user_openflux_selection u
                        JOIN user_openflux_config cfg ON u.user_id = cfg.user_id
                        JOIN users usr ON u.user_id = usr.id
                        WHERE u.group_id = ? AND cfg.enabled = 1;
                    """, (grp_id,))
                    affected_users_info = c.fetchall()
                    bundle_valid = True
                    for u_row in affected_users_info:
                        c.execute("""
                            SELECT g.* FROM user_openflux_selection s
                            JOIN openflux_groups g ON s.group_id = g.id
                            WHERE s.user_id = ?
                            ORDER BY s.position ASC;
                        """, (u_row["user_id"],))
                        sim_grps = []
                        for gr in c.fetchall():
                            if gr["id"] == grp_id:
                                sim_grps.append({
                                    "id": grp_id,
                                    "name": name,
                                    "mode": slot_mode,
                                    "transport": transport,
                                    "urls": urls,
                                    "codec": codec,
                                    "encryption_key": enc_key
                                })
                            else:
                                try:
                                    gu = json.loads(gr["urls_json"])
                                except Exception:
                                    gu = []
                                sim_grps.append({
                                    "id": gr["id"],
                                    "name": gr["name"],
                                    "mode": gr["mode"],
                                    "transport": gr["transport"],
                                    "urls": gu,
                                    "codec": gr["codec"],
                                    "encryption_key": gr["encryption_key"] or ""
                                })
                        ok_sim, _, _ = build_openflux_v2_payload(
                            self.issuer_id,
                            u_row["connection_id"],
                            u_row["revision"] + 1,
                            u_row["name"],
                            u_row["mode"],
                            u_row["balancer_strategy"],
                            sim_grps
                        )
                        if not ok_sim:
                            bundle_valid = False
                            break

                    if not bundle_valid:
                        continue

                    with self.conn:
                        c.execute("""
                            UPDATE openflux_groups
                            SET transport = ?, urls_json = ?, codec = ?,
                                encryption_key = ?, updated_at = ?
                            WHERE id = ?;
                        """, (transport, json.dumps(urls), codec, enc_key, now, grp_id))

                        c.execute("SELECT DISTINCT user_id FROM user_openflux_selection WHERE group_id = ?;", (grp_id,))
                        for row in c.fetchall():
                            u_id = row[0]
                            c.execute("""
                                UPDATE user_openflux_config
                                SET revision = revision + 1, updated_at = ?
                                WHERE user_id = ?;
                            """, (now, u_id))
                            c.execute("""
                                UPDATE users
                                SET revision = revision + 1, updated_at = ?
                                WHERE id = ?;
                            """, (now, u_id))
            else:
                grp_id = str(uuid.uuid4()).lower()
                name = f"OF-Slot-{slot}"
                with self.conn:
                    self.conn.execute("""
                        INSERT INTO openflux_groups (id, name, mode, transport, urls_json, codec, encryption_key, source_slot, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (grp_id, name, slot_mode, transport, json.dumps(urls), codec, enc_key, slot, now, now))

            imported_groups.append({
                "id": grp_id,
                "name": name,
                "slot": slot,
                "mode": slot_mode,
                "transport": transport,
                "urls": urls,
                "codec": codec,
            })

        return 200, {
            "success": True,
            "pool_mode": pool_mode,
            "imported_count": len(imported_groups),
            "groups": imported_groups
        }

    # ========================================================================
    # Управление каталогом WebDAV подключений и профилями пользователей
    # ========================================================================

    def list_webdav_connections(self, include_secrets: bool = False) -> tuple[int, list]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM webdav_connections ORDER BY created_at ASC;")
        rows = c.fetchall()
        res = []
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
            ok_u, _, full_uri = serialize_webdav_uri(c_dict)

            disp_pass = r["password"] if include_secrets else ("*" * min(len(r["password"]), 16))
            disp_backends = []
            for b in backends:
                b_copy = dict(b)
                if not include_secrets:
                    b_copy["password"] = "*" * min(len(b_copy.get("password", "")), 16)
                disp_backends.append(b_copy)

            item = {
                "id": r["id"],
                "name": r["name"],
                "enabled": bool(r["enabled"]),
                "revision": r["revision"],
                "url": r["url"],
                "username": r["username"],
                "password": disp_pass,
                "backends": disp_backends,
                "backends_count": len(backends),
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
                "uri": full_uri if ok_u else "",
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            res.append(item)
        return 200, res

    def get_webdav_connection(self, conn_id: str, include_secrets: bool = False) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM webdav_connections WHERE id = ?;", (conn_id,))
        r = c.fetchone()
        if not r:
            return 404, {"error": "WebDAV connection not found"}

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
        ok_u, _, full_uri = serialize_webdav_uri(c_dict)

        disp_pass = r["password"] if include_secrets else ("*" * min(len(r["password"]), 16))
        disp_backends = []
        for b in backends:
            b_copy = dict(b)
            if not include_secrets:
                b_copy["password"] = "*" * min(len(b_copy.get("password", "")), 16)
            disp_backends.append(b_copy)

        return 200, {
            "id": r["id"],
            "name": r["name"],
            "enabled": bool(r["enabled"]),
            "revision": r["revision"],
            "url": r["url"],
            "username": r["username"],
            "password": disp_pass,
            "backends": disp_backends,
            "backends_count": len(backends),
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
            "uri": full_uri if ok_u else "",
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def create_webdav_connection(self, data: dict) -> tuple[int, dict]:
        name = str(data.get("name") or "").strip()
        if not name:
            return 400, {"error": "Connection name is required"}

        primary_spec = {
            "url": data.get("url", ""),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "label": data.get("label", ""),
        }
        ok_p, err_p, clean_primary = validate_storage_spec(primary_spec, is_primary=True)
        if not ok_p:
            return 400, {"error": f"Primary storage error: {err_p}"}

        ok_t, err_t, clean_tuning = validate_tuning_params(data)
        if not ok_t:
            return 400, {"error": f"Tuning parameters error: {err_t}"}

        raw_backends = data.get("backends", [])
        if not isinstance(raw_backends, list):
            return 400, {"error": "Backends must be a list"}
        if len(raw_backends) > MAX_WEBDAV_BACKENDS:
            return 400, {"error": f"Too many backends: {len(raw_backends)} (max {MAX_WEBDAV_BACKENDS} allowed)"}

        clean_backends = []
        for idx, b in enumerate(raw_backends):
            ok_b, err_b, b_clean = validate_storage_spec(b, is_primary=False)
            if not ok_b:
                return 400, {"error": f"Backend #{idx+1} error: {err_b}"}
            clean_backends.append(b_clean)

        test_conn = {
            "name": name,
            "url": clean_primary["url"],
            "username": clean_primary["username"],
            "password": clean_primary["password"],
            "backends": clean_backends,
            **clean_tuning
        }
        ok_ser, err_ser, uri = serialize_webdav_uri(test_conn)
        if not ok_ser:
            return 400, {"error": f"WebDAV URI serialization error: {err_ser}"}

        conn_id = str(data.get("id") or "").strip().lower()
        if not conn_id or not is_canonical_uuid(conn_id):
            conn_id = str(uuid.uuid4()).lower()

        c = self.conn.cursor()
        c.execute("SELECT id FROM webdav_connections WHERE id = ?;", (conn_id,))
        if c.fetchone():
            return 409, {"error": f"WebDAV connection with ID '{conn_id}' already exists"}

        enabled = 1 if data.get("enabled", True) in (True, 1, "true", "1") else 0
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        fp = str(data.get("fingerprint") or compute_webdav_canonical_fingerprint(test_conn))

        with self.conn:
            self.conn.execute("""
                INSERT INTO webdav_connections (
                    id, name, enabled, revision, url, username, password, backends_json,
                    timeout, poll_min, poll_max, coalesce, chunk_size, puts, read_min, read_max,
                    enc, dns, fingerprint, created_at, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                conn_id, name, enabled, clean_primary["url"], clean_primary["username"], clean_primary["password"],
                json.dumps(clean_backends), clean_tuning["timeout"], clean_tuning["poll_min"], clean_tuning["poll_max"],
                clean_tuning["coalesce"], clean_tuning["chunk_size"], clean_tuning["puts"], clean_tuning["read_min"],
                clean_tuning["read_max"], clean_tuning["enc"], clean_tuning["dns"], fp, now, now
            ))

        return 201, {
            "id": conn_id,
            "name": name,
            "enabled": bool(enabled),
            "revision": 1,
            "url": clean_primary["url"],
            "username": clean_primary["username"],
            "backends": clean_backends,
            "backends_count": len(clean_backends),
            **clean_tuning,
            "uri": uri,
            "created_at": now,
            "updated_at": now,
        }

    def update_webdav_connection(self, conn_id: str, data: dict) -> tuple[int, dict]:
        conn_id = str(conn_id).strip().lower()
        c = self.conn.cursor()
        c.execute("SELECT * FROM webdav_connections WHERE id = ?;", (conn_id,))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "WebDAV connection not found"}

        name = str(data.get("name", cur["name"])).strip()
        if not name:
            return 400, {"error": "Connection name cannot be empty"}

        url = str(data.get("url", cur["url"])).strip()
        username = str(data.get("username", cur["username"])).strip()
        password = data.get("password")
        if password is None or password == "" or password == "********" or password == "[HIDDEN]":
            password = cur["password"]
        else:
            password = str(password).strip()

        primary_spec = {
            "url": url,
            "username": username,
            "password": password,
            "label": data.get("label", ""),
        }
        ok_p, err_p, clean_primary = validate_storage_spec(primary_spec, is_primary=True)
        if not ok_p:
            return 400, {"error": f"Primary storage error: {err_p}"}

        cur_backends = []
        try:
            cur_backends = json.loads(cur["backends_json"])
        except Exception:
            pass

        if "backends" in data:
            raw_backends = data["backends"]
            if not isinstance(raw_backends, list):
                return 400, {"error": "Backends must be a list"}
            if len(raw_backends) > MAX_WEBDAV_BACKENDS:
                return 400, {"error": f"Too many backends: {len(raw_backends)} (max {MAX_WEBDAV_BACKENDS} allowed)"}
            clean_backends = []
            for idx, b in enumerate(raw_backends):
                b_pass = b.get("password")
                if (b_pass is None or b_pass == "" or b_pass == "********" or b_pass == "[HIDDEN]") and idx < len(cur_backends):
                    b = dict(b)
                    b["password"] = cur_backends[idx].get("password", "")
                ok_b, err_b, b_clean = validate_storage_spec(b, is_primary=False)
                if not ok_b:
                    return 400, {"error": f"Backend #{idx+1} error: {err_b}"}
                clean_backends.append(b_clean)
        else:
            clean_backends = cur_backends

        tuning_input = {
            "timeout": data.get("timeout", cur["timeout"]),
            "poll_min": data.get("poll_min", cur["poll_min"]),
            "poll_max": data.get("poll_max", cur["poll_max"]),
            "coalesce": data.get("coalesce", cur["coalesce"]),
            "chunk_size": data.get("chunk_size", cur["chunk_size"]),
            "puts": data.get("puts", cur["puts"]),
            "read_min": data.get("read_min", cur["read_min"]),
            "read_max": data.get("read_max", cur["read_max"]),
            "enc": data.get("enc", cur["enc"]),
            "dns": data.get("dns", cur["dns"]),
        }
        ok_t, err_t, clean_tuning = validate_tuning_params(tuning_input)
        if not ok_t:
            return 400, {"error": f"Tuning parameters error: {err_t}"}

        enabled = cur["enabled"]
        if "enabled" in data:
            enabled = 1 if data["enabled"] in (True, 1, "true", "1") else 0

        test_conn = {
            "name": name,
            "url": clean_primary["url"],
            "username": clean_primary["username"],
            "password": clean_primary["password"],
            "backends": clean_backends,
            **clean_tuning
        }
        ok_ser, err_ser, uri = serialize_webdav_uri(test_conn)
        if not ok_ser:
            return 400, {"error": f"WebDAV URI serialization error: {err_ser}"}

        fp = compute_webdav_canonical_fingerprint(test_conn)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        new_rev = cur["revision"] + 1

        with self.conn:
            c.execute("SELECT DISTINCT user_id FROM user_webdav_selection WHERE connection_id = ? AND enabled = 1;", (conn_id,))
            affected_users = [row[0] for row in c.fetchall()]

            self.conn.execute("""
                UPDATE webdav_connections SET
                    name = ?, enabled = ?, revision = ?, url = ?, username = ?, password = ?,
                    backends_json = ?, timeout = ?, poll_min = ?, poll_max = ?, coalesce = ?,
                    chunk_size = ?, puts = ?, read_min = ?, read_max = ?, enc = ?, dns = ?,
                    fingerprint = ?, updated_at = ?
                WHERE id = ?;
            """, (
                name, enabled, new_rev, clean_primary["url"], clean_primary["username"], clean_primary["password"],
                json.dumps(clean_backends), clean_tuning["timeout"], clean_tuning["poll_min"], clean_tuning["poll_max"],
                clean_tuning["coalesce"], clean_tuning["chunk_size"], clean_tuning["puts"], clean_tuning["read_min"],
                clean_tuning["read_max"], clean_tuning["enc"], clean_tuning["dns"], fp, now, conn_id
            ))

            for u_id in affected_users:
                self.conn.execute("UPDATE user_webdav_config SET revision = revision + 1, updated_at = ? WHERE user_id = ?;", (now, u_id))
                self.conn.execute("UPDATE users SET revision = revision + 1, updated_at = ? WHERE id = ?;", (now, u_id))

        return 200, {
            "id": conn_id,
            "name": name,
            "enabled": bool(enabled),
            "revision": new_rev,
            "url": clean_primary["url"],
            "username": clean_primary["username"],
            "backends": clean_backends,
            "backends_count": len(clean_backends),
            **clean_tuning,
            "uri": uri,
            "created_at": cur["created_at"],
            "updated_at": now
        }

    def delete_webdav_connection(self, conn_id: str) -> tuple[int, dict]:
        conn_id = str(conn_id).strip().lower()
        c = self.conn.cursor()
        c.execute("SELECT id FROM webdav_connections WHERE id = ?;", (conn_id,))
        if not c.fetchone():
            return 404, {"error": "WebDAV connection not found"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.conn:
            c.execute("SELECT DISTINCT user_id FROM user_webdav_selection WHERE connection_id = ?;", (conn_id,))
            affected_users = [row[0] for row in c.fetchall()]

            self.conn.execute("DELETE FROM user_webdav_selection WHERE connection_id = ?;", (conn_id,))
            self.conn.execute("DELETE FROM webdav_connections WHERE id = ?;", (conn_id,))

            for u_id in affected_users:
                self.conn.execute("UPDATE user_webdav_config SET revision = revision + 1, updated_at = ? WHERE user_id = ?;", (now, u_id))
                self.conn.execute("UPDATE users SET revision = revision + 1, updated_at = ? WHERE id = ?;", (now, u_id))

        return 200, {"deleted": True, "id": conn_id}

    def import_webdav_uri(self, data: dict) -> tuple[int, dict]:
        uri = str(data.get("uri") or "").strip()
        if not uri:
            return 400, {"error": "URI is required"}
        ok, err, parsed = parse_webdav_uri(uri)
        if not ok:
            return 400, {"error": f"Failed to parse WebDAV URI: {err}"}

        fp = compute_webdav_canonical_fingerprint(parsed)
        parsed["fingerprint"] = fp

        c = self.conn.cursor()
        c.execute("SELECT * FROM webdav_connections WHERE fingerprint = ?;", (fp,))
        existing = c.fetchone()
        if existing:
            try:
                backends = json.loads(existing["backends_json"])
            except Exception:
                backends = []
            exist_conn = {
                "id": existing["id"],
                "name": existing["name"],
                "enabled": bool(existing["enabled"]),
                "revision": existing["revision"],
                "url": existing["url"],
                "username": existing["username"],
                "password": existing["password"],
                "backends": backends,
                "backends_count": len(backends),
                "timeout": existing["timeout"],
                "poll_min": existing["poll_min"],
                "poll_max": existing["poll_max"],
                "coalesce": existing["coalesce"],
                "chunk_size": existing["chunk_size"],
                "puts": existing["puts"],
                "read_min": existing["read_min"],
                "read_max": existing["read_max"],
                "enc": existing["enc"],
                "dns": existing["dns"],
            }
            return 200, {
                "success": True,
                "duplicate": True,
                "existing": True,
                "id": existing["id"],
                "name": existing["name"],
                "connection": exist_conn,
                "parsed": parsed,
                "message": f"Connection already exists in catalog as '{existing['name']}'"
            }

        if data.get("save"):
            return self.create_webdav_connection(parsed)

        return 200, {"success": True, "parsed": parsed, "connection": parsed}

    def import_server_webdav(self, data: dict) -> tuple[int, dict]:
        env_path = str(data.get("env_path") or "/etc/webdav-tunnel/config.env").strip()
        server_ip = str(data.get("server_ip") or "").strip()
        if not server_ip:
            if self.public_host:
                server_ip = self.public_host
            elif self.bind_addr not in ("0.0.0.0", "", "::"):
                server_ip = self.bind_addr
            else:
                server_ip = "127.0.0.1"

        ok, err, candidate = import_server_webdav_config(env_path, server_ip)
        if not ok:
            return 400, {"error": f"Failed to inspect server WebDAV config: {err}"}

        ok_ser, err_ser, uri = serialize_webdav_uri(candidate)
        if not ok_ser:
            return 400, {"error": f"Failed to serialize inspected connection: {err_ser}"}

        if data.get("save"):
            return self.create_webdav_connection(candidate)

        return 200, {
            "success": True,
            "connection": candidate,
            "uri": uri
        }

    def get_user_webdav(self, user_id_or_nick: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_webdav_config WHERE user_id = ?;", (u_id,))
        wd_cfg = c.fetchone()
        if not wd_cfg:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.conn:
                self.conn.execute("""
                    INSERT INTO user_webdav_config (user_id, enabled, revision, updated_at)
                    VALUES (?, 1, 1, ?);
                """, (u_id, now))
            c.execute("SELECT * FROM user_webdav_config WHERE user_id = ?;", (u_id,))
            wd_cfg = c.fetchone()

        c.execute("""
            SELECT c.*, s.enabled AS sel_enabled, s.position
            FROM user_webdav_selection s
            JOIN webdav_connections c ON s.connection_id = c.id
            WHERE s.user_id = ?
            ORDER BY s.position ASC;
        """, (u_id,))
        sel_rows = c.fetchall()

        conns_res = []
        conn_ids = []
        for r in sel_rows:
            try:
                backends = json.loads(r["backends_json"])
            except Exception:
                backends = []
            conn_ids.append(r["id"])
            conns_res.append({
                "id": r["id"],
                "name": r["name"],
                "enabled": bool(r["sel_enabled"]),
                "catalog_enabled": bool(r["enabled"]),
                "position": r["position"],
                "url": r["url"],
                "username": r["username"],
                "password": r["password"],
                "backends_count": len(backends),
                "backends": backends if isinstance(backends, list) else [],
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
            })

        return 200, {
            "user_id": u_id,
            "nickname": user["nickname"],
            "enabled": bool(wd_cfg["enabled"]),
            "revision": wd_cfg["revision"],
            "connections": conns_res,
            "connection_ids": conn_ids,
        }

    def update_user_webdav(self, user_id_or_nick: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_webdav_config WHERE user_id = ?;", (u_id,))
        wd_cfg = c.fetchone()
        cur_enabled = bool(wd_cfg["enabled"]) if wd_cfg else True

        new_enabled = cur_enabled
        if "enabled" in data:
            new_enabled = bool(data["enabled"])

        new_selection = None
        if "connections" in data and isinstance(data["connections"], list):
            new_selection = []
            for item in data["connections"]:
                if isinstance(item, dict) and "id" in item:
                    new_selection.append({
                        "id": str(item["id"]).strip().lower(),
                        "enabled": bool(item.get("enabled", True))
                    })
                elif isinstance(item, str):
                    new_selection.append({
                        "id": item.strip().lower(),
                        "enabled": True
                    })
        elif "connection_ids" in data and isinstance(data["connection_ids"], list):
            new_selection = [{"id": str(cid).strip().lower(), "enabled": True} for cid in data["connection_ids"]]

        if new_selection is not None:
            for item in new_selection:
                c.execute("SELECT id FROM webdav_connections WHERE id = ?;", (item["id"],))
                if not c.fetchone():
                    return 400, {"error": f"WebDAV connection '{item['id']}' not found in catalog"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.conn:
            if wd_cfg:
                self.conn.execute("""
                    UPDATE user_webdav_config SET enabled = ?, revision = revision + 1, updated_at = ?
                    WHERE user_id = ?;
                """, (1 if new_enabled else 0, now, u_id))
            else:
                self.conn.execute("""
                    INSERT INTO user_webdav_config (user_id, enabled, revision, updated_at)
                    VALUES (?, ?, 1, ?);
                """, (u_id, 1 if new_enabled else 0, now))

            if new_selection is not None:
                self.conn.execute("DELETE FROM user_webdav_selection WHERE user_id = ?;", (u_id,))
                for pos, item in enumerate(new_selection):
                    self.conn.execute("""
                        INSERT INTO user_webdav_selection (user_id, connection_id, position, enabled)
                        VALUES (?, ?, ?, ?);
                    """, (u_id, item["id"], pos, 1 if item["enabled"] else 0))

            self.conn.execute("UPDATE users SET revision = revision + 1, updated_at = ? WHERE id = ?;", (now, u_id))

        return self.get_user_webdav(u_id)

    def preview_user_webdav(self, user_id_or_nick: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT enabled FROM user_webdav_config WHERE user_id = ?;", (u_id,))
        wd_cfg = c.fetchone()
        wd_en = bool(wd_cfg["enabled"]) if wd_cfg else False
        if not wd_en:
            return 200, {
                "user_id": u_id,
                "nickname": user["nickname"],
                "enabled": False,
                "uris": [],
                "count": 0
            }

        c.execute("""
            SELECT c.* FROM user_webdav_selection s
            JOIN webdav_connections c ON s.connection_id = c.id
            WHERE s.user_id = ? AND s.enabled = 1 AND c.enabled = 1
            ORDER BY s.position ASC;
        """, (u_id,))
        conns = c.fetchall()

        uris = []
        for r in conns:
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
            ok_u, err_u, uri = serialize_webdav_uri(c_dict)
            if not ok_u:
                return 500, {"error": f"Failed to serialize connection '{r['name']}': {err_u}"}
            uris.append(uri)

        return 200, {
            "user_id": u_id,
            "nickname": user["nickname"],
            "enabled": True,
            "uris": uris,
            "count": len(uris)
        }

    def export_user_webdav(self, user_id_or_nick: str, conn_id: str = None) -> tuple[int, dict]:
        """
        Экспорт подключений WebDAV для пользователя в каноническом формате TUNA rc9:
        - Если передан conn_id: экспортирует ровно одну назначенную пользователю запись.
        - Если conn_id не передан: экспортирует список всех назначенных пользователю записей.
        - Независим от статуса публикации в подписке (чистый read-only).
        - Полный WebDAV URI включает основной URL и все вложенные backends.
        - НЕ использует вымышленную схему webdav-bundle:// (контракт rc9).
        """
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}
        u_id = user["id"]

        if conn_id:
            c.execute("""
                SELECT c.* FROM user_webdav_selection s
                JOIN webdav_connections c ON s.connection_id = c.id
                WHERE s.user_id = ? AND c.id = ?;
            """, (u_id, conn_id))
            row = c.fetchone()
            if not row:
                return 404, {"error": f"WebDAV connection '{conn_id}' is not assigned to user '{user['nickname']}'"}
            conns = [row]
        else:
            c.execute("""
                SELECT c.* FROM user_webdav_selection s
                JOIN webdav_connections c ON s.connection_id = c.id
                WHERE s.user_id = ?
                ORDER BY s.position ASC;
            """, (u_id,))
            conns = c.fetchall()

        items = []
        uris = []
        for r in conns:
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
            ok_u, err_u, uri = serialize_webdav_uri(c_dict)
            if not ok_u:
                return 500, {"error": f"Failed to serialize WebDAV URI for '{r['name']}': {err_u}"}
            items.append({
                "id": r["id"],
                "name": r["name"],
                "uri": uri
            })
            uris.append(uri)

        if conn_id:
            return 200, {
                "success": True,
                "connection_id": items[0]["id"],
                "name": items[0]["name"],
                "uri": items[0]["uri"],
                "user_id": u_id,
                "nickname": user["nickname"],
            }

        return 200, {
            "success": True,
            "total": len(items),
            "connections": items,
            "uris": uris,
            "user_id": u_id,
            "nickname": user["nickname"],
        }

    def import_user_webdav(self, user_id_or_nick: str, data: dict) -> tuple[int, dict]:
        """
        Импорт одного или нескольких WebDAV URI и назначение текущему пользователю:
        - Поддержка одиночного URI ('uri': str) или пачки ('uris': list[str]).
        - Валидация всех URI до записи (атомарность, ошибка не оставляет полкаталога).
        - Распознавание повторного импорта по каноническому отпечатку (SHA256).
        - Предпросмотр с маскировкой паролей и токеном состояния (expected_state_token).
        - Не создает дубликатов в каталоге и не перезаписывает по совпадению имени.
        - Не назначает повторно уже привязанное к пользователю подключение.
        - Контроль лимита: максимум 8 подключений на пользователя.
        """
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}
        u_id = user["id"]

        raw_uri = data.get("uri")
        raw_uris = data.get("uris")
        uris_to_process = []
        if raw_uris and isinstance(raw_uris, list):
            uris_to_process = [str(u).strip() for u in raw_uris if str(u).strip()]
        elif raw_uri and isinstance(raw_uri, str) and raw_uri.strip():
            uris_to_process = [raw_uri.strip()]
        else:
            return 400, {"error": "Field 'uri' (string) or 'uris' (list of strings) is required"}

        if not uris_to_process:
            return 400, {"error": "No non-empty WebDAV URI provided"}

        # Валидация ВСЕХ URI до любых изменений
        parsed_items = []
        for idx, u_str in enumerate(uris_to_process, 1):
            ok_p, err_p, parsed = parse_webdav_uri(u_str)
            if not ok_p:
                return 400, {"error": f"Invalid WebDAV URI at position #{idx}: {err_p}"}
            fp = compute_webdav_canonical_fingerprint(parsed)
            parsed["_fingerprint"] = fp
            parsed_items.append(parsed)

        # Текущие назначения пользователя и проверка лимита
        c.execute("SELECT * FROM user_webdav_config WHERE user_id = ?;", (u_id,))
        wd_cfg = c.fetchone()
        c.execute("""
            SELECT s.connection_id, c.fingerprint, c.name, s.position
            FROM user_webdav_selection s
            JOIN webdav_connections c ON s.connection_id = c.id
            WHERE s.user_id = ?
            ORDER BY s.position ASC;
        """, (u_id,))
        cur_sel = c.fetchall()
        cur_conn_ids = [r["connection_id"] for r in cur_sel]
        cur_fps = {r["fingerprint"] for r in cur_sel if r["fingerprint"]}

        cur_state_token = compute_user_webdav_state_token(u_id, wd_cfg, cur_sel)

        # Подсчет сколько подключений будет реально добавлено
        new_unique_fps = set()
        for p in parsed_items:
            if p["_fingerprint"] not in cur_fps:
                new_unique_fps.add(p["_fingerprint"])

        total_after = len(cur_sel) + len(new_unique_fps)
        if total_after > MAX_WEBDAV_CONNECTIONS:
            return 400, {
                "error": f"Import would result in {total_after} connections for user '{user['nickname']}', "
                         f"which exceeds the maximum limit of {MAX_WEBDAV_CONNECTIONS} (currently assigned: {len(cur_sel)})."
            }

        is_commit = bool(data.get("commit", False))
        if data.get("preview_only") is True:
            is_commit = False

        if not is_commit:
            # ФАЗА ПРЕДПРОСМОТРА
            preview_list = []
            for p in parsed_items:
                c.execute("SELECT id, name FROM webdav_connections WHERE fingerprint = ?;", (p["_fingerprint"],))
                exist_cat = c.fetchone()
                is_assigned = p["_fingerprint"] in cur_fps
                backends_preview = []
                for b in p.get("backends", []):
                    backends_preview.append({
                        "url": b.get("url"),
                        "username": b.get("username"),
                        "password_masked": mask_secret(b.get("password", "")),
                        "label": b.get("label", ""),
                    })
                preview_list.append({
                    "name": p.get("name"),
                    "url": p.get("url"),
                    "username": p.get("username"),
                    "password_masked": mask_secret(p.get("password", "")),
                    "backends_count": len(p.get("backends", [])),
                    "backends": backends_preview,
                    "timeout": p.get("timeout"),
                    "enc": p.get("enc"),
                    "dns": p.get("dns"),
                    "exists_in_catalog": bool(exist_cat),
                    "catalog_connection_id": exist_cat["id"] if exist_cat else None,
                    "already_assigned_to_user": is_assigned,
                })
            return 200, {
                "success": True,
                "preview": True,
                "state_token": cur_state_token,
                "total_input_uris": len(parsed_items),
                "new_connections_to_attach": len(new_unique_fps),
                "total_after_import": total_after,
                "connections": preview_list,
            }

        # ФАЗА КОММИТА
        expected_token = data.get("expected_state_token")
        if expected_token and expected_token != cur_state_token:
            return 409, {"error": "Configuration changed since preview. Please request a new preview before committing."}

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                max_pos = -1
                if cur_sel:
                    max_pos = max(r["position"] for r in cur_sel)

                for p in parsed_items:
                    fp = p["_fingerprint"]
                    # 1. Поиск или создание в каталоге
                    c.execute("SELECT id FROM webdav_connections WHERE fingerprint = ?;", (fp,))
                    exist_row = c.fetchone()
                    if exist_row:
                        target_cid = exist_row["id"]
                    else:
                        target_cid = str(uuid.uuid4()).lower()
                        c.execute("""
                            INSERT INTO webdav_connections (
                                id, name, enabled, revision, url, username, password, backends_json,
                                timeout, poll_min, poll_max, coalesce, chunk_size, puts, read_min, read_max,
                                enc, dns, fingerprint, created_at, updated_at
                            ) VALUES (?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            target_cid, p["name"], p["url"], p["username"], p["password"],
                            json.dumps(p.get("backends", [])), p["timeout"], p["poll_min"], p["poll_max"],
                            p["coalesce"], p["chunk_size"], p["puts"], p["read_min"], p["read_max"],
                            p["enc"], p["dns"], fp, now_iso, now_iso
                        ))

                    # 2. Привязка к пользователю (если еще не привязано)
                    if fp not in cur_fps and target_cid not in cur_conn_ids:
                        max_pos += 1
                        c.execute("""
                            INSERT INTO user_webdav_selection (user_id, connection_id, position, enabled)
                            VALUES (?, ?, ?, 1);
                        """, (u_id, target_cid, max_pos))
                        cur_fps.add(fp)
                        cur_conn_ids.append(target_cid)

                # 3. Обновление ревизии
                if wd_cfg:
                    c.execute("""
                        UPDATE user_webdav_config
                        SET revision = revision + 1, updated_at = ?
                        WHERE user_id = ?;
                    """, (now_iso, u_id))
                else:
                    c.execute("""
                        INSERT INTO user_webdav_config (user_id, enabled, revision, updated_at)
                        VALUES (?, 1, 1, ?);
                    """, (u_id, now_iso))

                c.execute("""
                    UPDATE users
                    SET revision = revision + 1, updated_at = ?
                    WHERE id = ?;
                """, (now_iso, u_id))
        except Exception as e:
            return 500, {"error": f"Database transaction failed: {e}"}

        return self.get_user_webdav(u_id)

    def get_subscription_payload(self, token: str, if_none_match: str = None) -> tuple[int, dict, bytes]:
        """
        Выдача подписки по токену:
        - Поиск по SHA256(token).
        - Все протоколы в строгом порядке: CSQTT -> QWDTT -> Snell -> Mieru -> MasterDNS -> Custom -> OpenFlux.
        - OpenFlux v2: если включен в user_openflux_config и содержит 1-8 валидных групп,
          добавляется ровно одна строка openflux-bundle://v2/<Base64URL-NoPadding>.
        - При ошибке валидации/генерации включенного бандла возвращается HTTP 500 (не скрывать и не удалять молча).
        - Все ссылки каждого протокола разбиваются построчно.
        - Если все пусты -> 204 No Content.
        - ETag и 304 Not Modified.
        - Base64 UTF-8.
        """
        tok_hash = hash_token(token)
        c = self.conn.cursor()
        c.execute("""
            SELECT * FROM users WHERE subscription_token_hash = ?;
        """, (tok_hash,))
        user = c.fetchone()

        if not user or not user["enabled"]:
            return 404, {"error": "Subscription not found or disabled"}, b""

        try:
            hidden_snell, snell_replacements, snell_selection = snell_delivery_selection(self.conn, user["id"])
        except (SnellSelectionError, sqlite3.Error):
            return 500, {"error": "Local Snell selection is unavailable or invalid"}, b""

        candidate_fields = [
            user["csqtt_uri"] if "csqtt_uri" in user.keys() else "",
            user["qwdtt_uri"] if "qwdtt_uri" in user.keys() else "",
            user["snell_uri"] if "snell_uri" in user.keys() else "",
            user["mieru_uri"] if "mieru_uri" in user.keys() else "",
            user["masterdnsvpn_uri"] if "masterdnsvpn_uri" in user.keys() else "",
            user["custom_uri"] if "custom_uri" in user.keys() else ""
        ]

        non_empty = []
        for field_val in candidate_fields:
            if field_val and str(field_val).strip():
                for line in str(field_val).splitlines():
                    clean = line.strip()
                    if clean:
                        non_empty.append(clean)

        # OpenFlux v2 интеграция
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (user["id"],))
        of_cfg = c.fetchone()
        if of_cfg and of_cfg["enabled"]:
            c.execute("""
                SELECT g.* FROM user_openflux_selection s
                JOIN openflux_groups g ON s.group_id = g.id
                WHERE s.user_id = ?
                ORDER BY s.position ASC;
            """, (user["id"],))
            selected_groups = c.fetchall()
            if not (1 <= len(selected_groups) <= 8):
                return 500, {"error": "Active OpenFlux bundle must have between 1 and 8 groups"}, b""

            groups_payload = []
            for g in selected_groups:
                try:
                    urls = json.loads(g["urls_json"])
                except Exception:
                    urls = []
                groups_payload.append({
                    "id": g["id"],
                    "name": g["name"],
                    "mode": g["mode"],
                    "transport": g["transport"],
                    "urls": urls,
                    "codec": g["codec"],
                    "encryption_key": g["encryption_key"] or "",
                })

            ok_b, err_b, bundle_dict = build_openflux_v2_payload(
                self.issuer_id,
                of_cfg["connection_id"],
                int(of_cfg["revision"]),
                of_cfg["name"],
                of_cfg["mode"],
                of_cfg["balancer_strategy"],
                groups_payload
            )
            if not ok_b:
                return 500, {"error": f"OpenFlux bundle generation failed: {err_b}"}, b""

            ok_ser, err_ser, v2_uri = serialize_openflux_v2_bundle(bundle_dict)
            if not ok_ser or not v2_uri:
                return 500, {"error": f"OpenFlux bundle serialization failed: {err_ser}"}, b""

            non_empty.append(v2_uri)

        # Imported bundles are separate profiles and retain their source identities.
        for imported in self._imported_openflux_rows(user['id']):
            if imported['enabled']:
                ok, error, _ = deserialize_openflux_v2_bundle(imported['uri'])
                if not ok:
                    return 500, {'error': 'Invalid stored imported OpenFlux bundle'}, b''
                if imported['uri'] not in non_empty:
                    non_empty.append(imported['uri'])

        # WebDAV интеграция
        c.execute("SELECT enabled FROM user_webdav_config WHERE user_id = ?;", (user["id"],))
        wd_cfg = c.fetchone()
        if wd_cfg and wd_cfg["enabled"]:
            c.execute("""
                SELECT c.* FROM user_webdav_selection s
                JOIN webdav_connections c ON s.connection_id = c.id
                WHERE s.user_id = ? AND s.enabled = 1 AND c.enabled = 1
                ORDER BY s.position ASC;
            """, (user["id"],))
            selected_conns = c.fetchall()
            for r in selected_conns:
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
                ok_u, err_u, uri = serialize_webdav_uri(c_dict)
                if not ok_u:
                    return 500, {"error": f"WebDAV serialization failed for connection '{r['name']}': {err_u}"}, b""
                non_empty.append(uri)

        if not non_empty:
            return 204, {}, b""

        raw_text = "\n".join(non_empty) + "\n"
        raw_bytes = raw_text.encode("utf-8")
        b64_payload = base64.b64encode(raw_bytes)
        if len(b64_payload) > MAX_SUBSCRIPTION_RESPONSE_BYTES:
            return 500, {"error": f"Subscription response exceeds maximum size of {MAX_SUBSCRIPTION_RESPONSE_BYTES} bytes"}, b""

        # Вычисление детерминированного ETag
        content_hash = hashlib.sha256(raw_bytes + snell_selection).hexdigest()[:16]
        etag = f'"{user["revision"]}-{content_hash}"'

        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "private, no-store",
            "ETag": etag,
            "Profile-Title": user["nickname"],
        }

        if if_none_match and if_none_match.strip() == etag:
            return 304, headers, b""

        return 200, headers, b64_payload


class SubscriptionRequestHandler(BaseHTTPRequestHandler):
    server_version = "TunaSubscription/1.0"

    @property
    def app(self) -> SubscriptionApp:
        return self.server.app

    def log_message(self, format, *args):
        """
        Маскирование логов: НИКОГДА не выводить секретные токены подписок и сырые URI.
        """
        msg = format % args
        # Замена токенов в путях /sub/...
        sanitized = re.sub(r'/sub(?:-json|-groups)?/[^\s?]+', '/sub/[REDACTED_TOKEN]', msg)
        log_file = self.app.config.get("logging", {}).get("file")
        log_entry = f"[{self.log_date_time_string()}] {self.client_address[0]} {sanitized}\n"
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                return
            except Exception:
                pass
        sys.stderr.write(log_entry)

    def send_json(self, status_code: int, data: any):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self, limit=None) -> dict:
        content_len = int(self.headers.get("Content-Length", 0))
        max_size = self.app.config["server"]["max_request_body_size"]
        if limit is not None:
            max_size = min(max_size, limit)
        if content_len < 0:
            raise ValueError("Invalid Content-Length")
        if content_len > max_size:
            raise ValueError("Payload Too Large")
        if content_len <= 0:
            return {}
        raw = self.rfile.read(content_len)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid JSON format")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith(('/sub-json/', '/sub-groups/')):
            transport = path.startswith('/sub-groups/')
            prefix = '/sub-groups/' if transport else '/sub-json/'
            token = path[len(prefix):]
            publish = self.app.connection_groups.publish_uri if transport else self.app.connection_groups.publish
            status, headers, payload = publish(token)
            if status != 200:
                self.send_json(status, {'error': headers.get('error', 'Subscription unavailable')})
                return
            if self.headers.get('If-None-Match', '').strip() == headers.get('ETag'):
                self.send_response(HTTPStatus.NOT_MODIFIED)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                return
            self.send_response(200)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        group_editor = re.fullmatch(r'/api/users/([^/]+)/connection-groups', path)
        if group_editor:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                self.send_json(403, {'error': 'Group administration is local only'})
                return
            uid = unquote(group_editor.group(1))
            status, result = self.app.connection_groups.editor(uid)
            self.send_json(status, result)
            return

        # Публичная выдача подписки: /sub/<secret-token>
        if path.startswith("/sub/"):
            token = path[len("/sub/"):]
            if not token:
                self.send_error(HTTPStatus.NOT_FOUND, "Token missing")
                return

            if_none_match = self.headers.get("If-None-Match")
            status, headers, payload = self.app.get_subscription_payload(token, if_none_match)

            if status == 304:
                self.send_response(HTTPStatus.NOT_MODIFIED)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                return

            if status == 204:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()
                return

            if status != 200:
                if status >= 500:
                    self.send_json(status, {'error': headers.get('error', 'Subscription unavailable')})
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "Subscription not found")
                return

            self.send_response(HTTPStatus.OK)
            for k, v in headers.items():
                # Profile-Title в заголовок UTF-8
                if k == "Profile-Title":
                    try:
                        v.encode("latin-1")
                        self.send_header(k, v)
                    except UnicodeEncodeError:
                        # RFC 5987 совместимый заголовок для UTF-8
                        from urllib.parse import quote
                        self.send_header(k, quote(v.encode("utf-8")))
                else:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # OpenFlux groups catalog: GET /api/openflux/groups
        if path == "/api/openflux/groups":
            status, res = self.app.list_openflux_groups()
            self.send_json(status, res)
            return

        # GET /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            status, res = self.app.get_openflux_group(group_id)
            self.send_json(status, res)
            return

        imported = re.match(r"^/api/users/([^/]+)/openflux/imported$", path)
        if imported:
            status, res = self.app.list_imported_openflux(unquote(imported.group(1)))
            self.send_json(status, res)
            return

        # OpenFlux user export: GET /api/users/<id_or_nickname>/openflux/export
        m_of_export = re.match(r"^/api/users/([^/]+)/openflux/export$", path)
        if m_of_export:
            user_id = unquote(m_of_export.group(1))
            status, res = self.app.export_user_openflux(user_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/openflux
        m_of_user = re.match(r"^/api/users/([^/]+)/openflux$", path)
        if m_of_user:
            user_id = unquote(m_of_user.group(1))
            status, res = self.app.get_user_openflux(user_id)
            self.send_json(status, res)
            return

        # WebDAV connections catalog: GET /api/webdav/connections
        if path == "/api/webdav/connections":
            qs = parse_qs(parsed.query)
            include_secrets = qs.get("secrets", ["0"])[0] in ("1", "true", "yes") or qs.get("include_secrets", ["0"])[0] in ("1", "true", "yes")
            status, res = self.app.list_webdav_connections(include_secrets=include_secrets)
            self.send_json(status, res)
            return

        # GET /api/webdav/connections/<id>
        m_wd_conn = re.match(r"^/api/webdav/connections/([^/]+)$", path)
        if m_wd_conn:
            conn_id = unquote(m_wd_conn.group(1))
            qs = parse_qs(parsed.query)
            include_secrets = qs.get("secrets", ["0"])[0] in ("1", "true", "yes") or qs.get("include_secrets", ["0"])[0] in ("1", "true", "yes")
            status, res = self.app.get_webdav_connection(conn_id, include_secrets=include_secrets)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/webdav/export
        m_wd_export = re.match(r"^/api/users/([^/]+)/webdav/export$", path)
        if m_wd_export:
            user_id = unquote(m_wd_export.group(1))
            qs = parse_qs(parsed.query)
            conn_id = qs.get("conn_id", [None])[0] or qs.get("connection_id", [None])[0]
            status, res = self.app.export_user_webdav(user_id, conn_id=conn_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/webdav/preview
        m_wd_user_prev = re.match(r"^/api/users/([^/]+)/webdav/preview$", path)
        if m_wd_user_prev:
            user_id = unquote(m_wd_user_prev.group(1))
            status, res = self.app.preview_user_webdav(user_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/webdav
        m_wd_user = re.match(r"^/api/users/([^/]+)/webdav$", path)
        if m_wd_user:
            user_id = unquote(m_wd_user.group(1))
            status, res = self.app.get_user_webdav(user_id)
            self.send_json(status, res)
            return

        # Управляющий API: GET /api/users
        if path == "/api/users":
            status, res = self.app.list_users()
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1))
            status, res = self.app.get_user(user_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/subscription-url
        m_sub_url = re.match(r"^/api/users/([^/]+)/subscription-url$", path)
        if m_sub_url:
            user_id = unquote(m_sub_url.group(1))
            status, res = self.app.get_user(user_id)
            if status != 200:
                self.send_json(status, res)
                return
            self.send_json(200, {
                "id": res["id"],
                "nickname": res["nickname"],
                "token": res.get("token", ""),
                "subscription_url": res.get("subscription_url", ""),
                "structured_subscription_url": res.get("subscription_url", "").replace('/sub/', '/sub-json/', 1),
                "group_transport_subscription_url": res.get("subscription_url", "").replace('/sub/', '/sub-groups/', 1),
            })
            return

        # Healthcheck
        if path == "/health" or path == "/api/health":
            self.send_json(200, {"status": "ok", "service": "tuna-subscriptions"})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # POST /api/openflux/groups
        if path == "/api/openflux/groups":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.create_openflux_group(data)
            self.send_json(status, res)
            return

        # POST /api/openflux/import-local
        if path == "/api/openflux/import-local":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            instances_dir = str(data.get("instances_dir") or "/etc/openflux/instances")
            pool_mode_file = str(data.get("pool_mode_file") or "/etc/openflux/pool.mode")
            status, res = self.app.import_local_openflux_groups(instances_dir, pool_mode_file)
            self.send_json(status, res)
            return

        # POST /api/webdav/connections
        if path == "/api/webdav/connections":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.create_webdav_connection(data)
            self.send_json(status, res)
            return

        # POST /api/webdav/import-uri
        if path == "/api/webdav/import-uri":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.import_webdav_uri(data)
            self.send_json(status, res)
            return

        # POST /api/webdav/import-server
        if path == "/api/webdav/import-server":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.import_server_webdav(data)
            self.send_json(status, res)
            return

        # POST /api/users
        if path == "/api/users":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.create_user(data)
            self.send_json(status, res)
            return

        imported = re.match(r"^/api/users/([^/]+)/openflux/imported/([^/]+)$", path)
        if imported:
            try:
                data = self.read_json_body()
            except ValueError as exc:
                self.send_json(400, {'error': str(exc)})
                return
            status, res = self.app.change_imported_openflux(unquote(imported.group(1)), unquote(imported.group(2)), data)
            self.send_json(status, res)
            return

        # POST /api/users/<id_or_nickname>/openflux/import
        m_of_import = re.match(r"^/api/users/([^/]+)/openflux/import$", path)
        if m_of_import:
            user_id = unquote(m_of_import.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.import_user_openflux(user_id, data)
            self.send_json(status, res)
            return

        # POST /api/users/<id_or_nickname>/webdav/import
        m_wd_import = re.match(r"^/api/users/([^/]+)/webdav/import$", path)
        if m_wd_import:
            user_id = unquote(m_wd_import.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.import_user_webdav(user_id, data)
            self.send_json(status, res)
            return

        # POST /api/users/<id_or_nickname>/rotate-token
        m_rotate = re.match(r"^/api/users/([^/]+)/rotate-token$", path)
        if m_rotate:
            user_id = unquote(m_rotate.group(1))
            status, res = self.app.rotate_token(user_id)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        group_editor = re.fullmatch(r'/api/users/([^/]+)/connection-groups', path)
        if group_editor:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                self.send_json(403, {'error': 'Group administration is local only'})
                return
            try:
                data = self.read_json_body(limit=2 * 1024 * 1024)
            except (ValueError, TypeError):
                self.send_json(400, {'error': 'Invalid or oversized group document'})
                return
            status, result = self.app.connection_groups.save(unquote(group_editor.group(1)), data)
            self.send_json(status, result)
            return

        # PUT /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_openflux_group(group_id, data)
            self.send_json(status, res)
            return

        # PUT /api/users/<id_or_nickname>/openflux
        m_of_user = re.match(r"^/api/users/([^/]+)/openflux$", path)
        if m_of_user:
            user_id = unquote(m_of_user.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_user_openflux(user_id, data)
            self.send_json(status, res)
            return

        # PUT /api/webdav/connections/<id>
        m_wd_conn = re.match(r"^/api/webdav/connections/([^/]+)$", path)
        if m_wd_conn:
            conn_id = unquote(m_wd_conn.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_webdav_connection(conn_id, data)
            self.send_json(status, res)
            return

        # PUT /api/users/<id_or_nickname>/webdav
        m_wd_user = re.match(r"^/api/users/([^/]+)/webdav$", path)
        if m_wd_user:
            user_id = unquote(m_wd_user.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_user_webdav(user_id, data)
            self.send_json(status, res)
            return

        # PUT /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_user(user_id, data)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # DELETE /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            status, res = self.app.delete_openflux_group(group_id)
            self.send_json(status, res)
            return

        # DELETE /api/webdav/connections/<id>
        m_wd_conn = re.match(r"^/api/webdav/connections/([^/]+)$", path)
        if m_wd_conn:
            conn_id = unquote(m_wd_conn.group(1))
            status, res = self.app.delete_webdav_connection(conn_id)
            self.send_json(status, res)
            return

        # DELETE /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1)).strip()
            status, res = self.app.delete_user(user_id)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")


def run_server(config_path=None):
    config = load_config(config_path)
    bind_ip = config["server"]["bind_address"]
    port = int(config["server"]["port"])

    app = SubscriptionApp(config)
    server_address = (bind_ip, port)

    httpd = ThreadingHTTPServer(server_address, SubscriptionRequestHandler)
    httpd.app = app

    sys.stdout.write(f"[INFO] TUNA Subscription Server listening on http://{bind_ip}:{port}\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\n[INFO] Stopping server...\n")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: tuna-subscriptions.py [options]")
        print("Options:")
        print("  -c, --config FILE       Path to config.json (default: /etc/tuna-subscriptions/config.json)")
        print("  --db FILE               Path to SQLite database file")
        print("  --repair-openflux-v2    Repair legacy comma-separated OpenFlux URLs in database")
        print("  --rollback BACKUP_FILE  Restore database from backup file")
        print("  -v, --version           Show version")
        print("  -h, --help              Show this help message")
        sys.exit(0)

    if "--version" in sys.argv or "-v" in sys.argv:
        print("TUNA Subscription Server 1.1.43-rc8 (OpenFlux v2 Contract)")
        sys.exit(0)

    cfg_p = None
    db_p = None
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--config", "-c") and i + 1 < len(sys.argv):
            cfg_p = sys.argv[i + 1]
            i += 2
            continue
        elif arg in ("--db", "--database") and i + 1 < len(sys.argv):
            db_p = sys.argv[i + 1]
            i += 2
            continue
        elif not arg.startswith("-") and cfg_p is None:
            cfg_p = arg
        i += 1

    config = load_config(cfg_p)
    target_db = db_p or config["database"]["path"]

    if "--repair-openflux-v2" in sys.argv or "--repair" in sys.argv:
        ok, msg, details = repair_openflux_v2_database(target_db)
        if ok:
            print(f"[OK] {msg}")
            print(json.dumps(details, indent=2, ensure_ascii=False))
            sys.exit(0)
        else:
            print(f"[ERROR] {msg}", file=sys.stderr)
            print(json.dumps(details, indent=2, ensure_ascii=False), file=sys.stderr)
            sys.exit(1)

    if "--rollback" in sys.argv:
        idx = sys.argv.index("--rollback")
        if idx + 1 >= len(sys.argv):
            print("[ERROR] --rollback requires backup file path", file=sys.stderr)
            sys.exit(1)
        backup_file = sys.argv[idx + 1]
        ok, msg = rollback_openflux_v2_database(backup_file, target_db)
        if ok:
            print(f"[OK] {msg}")
            sys.exit(0)
        else:
            print(f"[ERROR] {msg}", file=sys.stderr)
            sys.exit(1)

    run_server(cfg_p)
