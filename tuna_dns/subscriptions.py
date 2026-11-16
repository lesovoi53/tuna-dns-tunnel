"""TUNA DNS Subscriptions — HTTP API client, CLI subcommands, and TUI management."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Union

DEFAULT_API_URL = "http://127.0.0.1:22217"
SERVICE_NAME = "tuna-subscriptions.service"
CONFIG_FILE = Path("/etc/tuna-subscriptions/config.toml")
DB_FILE = Path("/var/lib/tuna-subscriptions/subscriptions.db")


class SubscriptionAPIError(RuntimeError):
    """Raised when an operation against the local subscription server fails."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def validate_nickname(nickname: str) -> bool:
    """Validate nickname format (alphanumeric, dashes, underscores, 1-64 chars)."""
    if not nickname or len(nickname) > 64:
        return False
    return bool(re.fullmatch(r"^[a-zA-Z0-9_\-]+$", nickname))


def get_default_tunnel_link(
    settings: Optional[Dict[str, Any]] = None,
    config_path: Optional[Path] = None,
) -> Optional[str]:
    """Generate masterdnsvpn:// or tuna:// link from the current tunnel settings."""
    try:
        from . import exports
    except ImportError:
        return None

    current_settings = settings
    if current_settings is None:
        try:
            from . import config
            cfg_file = Path(config.CONFIG_PATH)
            settings_file = cfg_file.parent / "settings.json"
            if settings_file.is_file():
                current_settings = json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            current_settings = None

    if current_settings is not None:
        try:
            from . import config
            c_path = config_path or Path(getattr(config, "CONFIG_PATH", "/etc/tuna-dns-tunnel/server_config.toml"))
            links = exports.links(current_settings, 1, "tuna", c_path)
            if links:
                return links[0]
        except Exception:
            pass
    return None


class SubscriptionClient:
    """HTTP client for the local subscription daemon at 127.0.0.1:22217."""

    base_url: str = DEFAULT_API_URL
    timeout: float = 8.0

    def __init__(self, base_url: str = DEFAULT_API_URL, timeout: float = 8.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        data: Optional[bytes] = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"

        req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace").strip()
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace").strip()
            detail = err_body
            try:
                parsed = json.loads(err_body)
                if isinstance(parsed, dict):
                    detail = str(parsed.get("error") or parsed.get("detail") or err_body)
            except Exception:
                pass
            raise SubscriptionAPIError(
                f"HTTP {exc.code}: {detail}",
                status_code=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise SubscriptionAPIError(
                f"Сервер подписок ({self.base_url}) недоступен: {exc.reason}"
            ) from exc

    def list_users(self) -> List[Dict[str, Any]]:
        """Return all registered users."""
        resp = self._request("GET", "/api/users")
        if isinstance(resp, list):
            return resp
        if isinstance(resp, dict) and isinstance(resp.get("users"), list):
            return resp["users"]
        return []

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Return a user record by ID or nickname."""
        safe_id = urllib.parse.quote(str(user_id).strip(), safe="")
        resp = self._request("GET", f"/api/users/{safe_id}")
        return resp if isinstance(resp, dict) else {}

    def create_user(
        self,
        nickname: str,
        masterdnsvpn_uri: Optional[Union[str, List[str]]] = None,
        custom_uri: Optional[Union[str, List[str]]] = None,
        external_links: Optional[List[str]] = None,
        auto_tunnel_link: bool = True,
        settings: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create a new user with tunnel links and/or external links."""
        name = nickname.strip()
        if not validate_nickname(name):
            raise SubscriptionAPIError("Недопустимое имя пользователя (1-64 символа: латиница, цифры, дефис, _)")

        dns_links: List[str] = []
        if auto_tunnel_link and not masterdnsvpn_uri:
            t_link = get_default_tunnel_link(settings=settings)
            if t_link:
                dns_links.append(t_link)

        if masterdnsvpn_uri:
            if isinstance(masterdnsvpn_uri, list):
                dns_links.extend(x.strip() for x in masterdnsvpn_uri if x and x.strip())
            else:
                dns_links.append(masterdnsvpn_uri.strip())

        custom_links: List[str] = []
        if custom_uri:
            if isinstance(custom_uri, list):
                custom_links.extend(x.strip() for x in custom_uri if x and x.strip())
            else:
                custom_links.append(custom_uri.strip())
        if external_links:
            custom_links.extend(x.strip() for x in external_links if x and x.strip())

        payload: Dict[str, Any] = {
            "nickname": name,
            "enabled": 1 if enabled else 0,
        }
        if dns_links:
            payload["masterdnsvpn_uri"] = "\n".join(dns_links)
        if custom_links:
            payload["custom_uri"] = "\n".join(custom_links)

        resp = self._request("POST", "/api/users", payload=payload)
        return resp if isinstance(resp, dict) else {"result": resp}

    def update_user(
        self,
        user_id: str,
        nickname: Optional[str] = None,
        masterdnsvpn_uri: Optional[Union[str, List[str]]] = None,
        custom_uri: Optional[Union[str, List[str]]] = None,
        external_links: Optional[List[str]] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update existing user parameters."""
        safe_id = urllib.parse.quote(str(user_id).strip(), safe="")
        payload: Dict[str, Any] = {}
        if nickname is not None:
            name = nickname.strip()
            if not validate_nickname(name):
                raise SubscriptionAPIError("Недопустимое имя пользователя.")
            payload["nickname"] = name

        if masterdnsvpn_uri is not None:
            if isinstance(masterdnsvpn_uri, list):
                payload["masterdnsvpn_uri"] = "\n".join(x.strip() for x in masterdnsvpn_uri if x and x.strip())
            else:
                payload["masterdnsvpn_uri"] = masterdnsvpn_uri.strip()

        if custom_uri is not None or external_links is not None:
            links: List[str] = []
            if custom_uri:
                links.extend(custom_uri if isinstance(custom_uri, list) else [custom_uri])
            if external_links:
                links.extend(external_links)
            payload["custom_uri"] = "\n".join(x.strip() for x in links if x and x.strip())

        if enabled is not None:
            payload["enabled"] = 1 if enabled else 0

        resp = self._request("PUT", f"/api/users/{safe_id}", payload=payload)
        return resp if isinstance(resp, dict) else {"result": resp}

    def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete user by ID or nickname."""
        safe_id = urllib.parse.quote(str(user_id).strip(), safe="")
        resp = self._request("DELETE", f"/api/users/{safe_id}")
        return resp if isinstance(resp, dict) else {"deleted": True}

    def rotate_token(self, user_id: str) -> Dict[str, Any]:
        """Revoke the current token and generate a fresh subscription URL."""
        safe_id = urllib.parse.quote(str(user_id).strip(), safe="")
        try:
            resp = self._request("POST", f"/api/users/{safe_id}/rotate-token", payload={})
            return resp if isinstance(resp, dict) else {"result": resp}
        except SubscriptionAPIError as exc:
            if exc.status_code == 404:
                resp = self._request("POST", f"/api/users/{safe_id}/token/rotate", payload={})
                return resp if isinstance(resp, dict) else {"result": resp}
            raise

    def status(self) -> Dict[str, Any]:
        """Check API daemon availability and user metrics."""
        try:
            users = self.list_users()
            return {
                "online": True,
                "base_url": self.base_url,
                "users_count": len(users),
                "error": None,
            }
        except SubscriptionAPIError as exc:
            return {
                "online": False,
                "base_url": self.base_url,
                "users_count": 0,
                "error": str(exc),
            }


def service_state() -> Dict[str, Any]:
    """Inspect systemd status of tuna-subscriptions.service."""
    if not shutil.which("systemctl"):
        return {"installed": False, "active": False, "enabled": False}
    act = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True, check=False)
    enb = subprocess.run(["systemctl", "is-enabled", SERVICE_NAME], capture_output=True, text=True, check=False)
    active = act.stdout.strip() == "active"
    enabled = enb.stdout.strip() == "enabled"
    installed = enb.stdout.strip() not in ("not-found", "")
    return {"installed": installed, "active": active, "enabled": enabled}


def service_action(action: str) -> bool:
    """Control tuna-subscriptions.service via systemctl."""
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise ValueError(f"Неизвестное действие службы: {action}")
    if not shutil.which("systemctl"):
        raise RuntimeError("systemctl не найден в системе.")
    res = subprocess.run(["systemctl", action, SERVICE_NAME], check=False)
    return res.returncode == 0


def service_journal(lines: int = 40) -> str:
    """Fetch recent journalctl logs for tuna-subscriptions."""
    if not shutil.which("journalctl"):
        return "journalctl не найден."
    res = subprocess.run(
        ["journalctl", "-u", SERVICE_NAME, "-n", str(lines), "--no-pager"],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip() or "Журнал пуст."


def launch_group_editor(user_id: str, api_url: str = DEFAULT_API_URL) -> None:
    """Launch tuna-groups CLI or script if available."""
    group_script = None
    for cand in (
        Path("/usr/local/bin/tuna-groups"),
        Path("/usr/local/bin/tuna-groups.py"),
        Path(__file__).resolve().parents[1] / "tuna-sub-server" / "tuna-groups.py",
    ):
        if cand.is_file():
            group_script = cand
            break

    if group_script:
        try:
            subprocess.run([sys.executable, str(group_script), user_id, "--api", api_url], check=False)
        except Exception as exc:
            print(f"Ошибка запуска редактора групп: {exc}")
    else:
        print("Скрипт tuna-groups не найден. Установите tuna-sub-server.")


def show_qr(text: str) -> None:
    """Render QR code in terminal using qrencode if available."""
    if shutil.which("qrencode"):
        res = subprocess.run(["qrencode", "-t", "UTF8"], input=text, text=True, check=False)
        if res.returncode:
            print("QR-код не поместился на экране. Скопируйте ссылку вручную.")
    else:
        print("(Для отображения QR-кода в терминале установите пакет: apt-get install qrencode)")


def run_subscriptions_tui(
    manager: Optional[Any] = None,
    client: Optional[SubscriptionClient] = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> None:
    """Interactive TUI menu for managing users, tokens, and external links."""
    api = client or SubscriptionClient()

    while True:
        st = api.status()
        srv = service_state()

        output_fn("\n╔════════════════════════════════════════════════════╗")
        output_fn("║     Пользователи и подписки (TUNA Subscriptions)   ║")
        output_fn("╚════════════════════════════════════════════════════╝")
        srv_str = "● Работает" if srv.get("active") else ("○ Остановлен" if srv.get("installed") else "Не установлен")
        api_str = f"● Онлайн ({st['users_count']} польз.)" if st["online"] else f"○ Офлайн ({st.get('error') or 'нет связи'})"
        output_fn(f"  Служба systemd: {srv_str}  |  HTTP API: {api_str}")
        output_fn("  Адрес API:      " + api.base_url)
        output_fn("")
        output_fn("  [1] Список пользователей и ссылки подписок (/sub/<token>)")
        output_fn("  [2] Создать пользователя из текущего DNS-туннеля")
        output_fn("  [3] Создать пользователя с внешними ссылками вручную")
        output_fn("  [4] Редактировать пользователя (ссылки, имя)")
        output_fn("  [5] Ротация токена подписки (отзыв и создание нового)")
        output_fn("  [6] Включить / отключить пользователя")
        output_fn("  [7] Управление группами URL-test и Speedtest")
        output_fn("  [8] Показать QR-код ссылки подписки")
        output_fn("  [9] Удалить пользователя")
        output_fn("  [S] Управление службой tuna-subscriptions.service")
        output_fn("  [0] Назад в главное меню")

        choice = input_fn("\nВыберите действие: ").strip().lower()
        if choice in ("0", "q", "exit"):
            break

        try:
            if choice == "1":
                users = api.list_users()
                if not users:
                    output_fn("Список пользователей пуст.")
                else:
                    output_fn(f"\nНайдено пользователей: {len(users)}")
                    output_fn("-" * 65)
                    for u in users:
                        uid = u.get("id", "-")
                        nick = u.get("nickname", "-")
                        en = "🟢 Вкл" if u.get("enabled", True) else "🔴 Откл"
                        uris = u.get("total_uris", 0)
                        sub_url = u.get("subscription_url") or f"/sub/{u.get('token', '')}"
                        output_fn(f"[{uid}] {nick} ({en}) | Ссылок: {uris}")
                        output_fn(f"    URL: {sub_url}")
                    output_fn("-" * 65)

            elif choice in ("2", "3"):
                name = input_fn("Имя пользователя (nickname): ").strip()
                if not name:
                    output_fn("Имя не может быть пустым.")
                    continue
                auto_tunnel = choice == "2"
                ext_input = input_fn(
                    "Внешние ссылки (vless://, ss://, trojan:// и т.д. через пробел или запятую, Enter — пропустить): "
                ).strip()
                ext_links = [x.strip() for x in re.split(r"[\s,]+", ext_input) if x.strip()] if ext_input else []

                tunnel_settings = None
                if manager is not None:
                    try:
                        m_st = manager.status()
                        if m_st.get("installed"):
                            tunnel_settings = m_st.get("settings")
                    except Exception:
                        pass

                created = api.create_user(
                    nickname=name,
                    external_links=ext_links,
                    auto_tunnel_link=auto_tunnel,
                    settings=tunnel_settings,
                )
                output_fn(f"[✓] Пользователь '{name}' создан!")
                output_fn(f"    ID:    {created.get('id', '-')}")
                output_fn(f"    Токен: {created.get('subscription_token') or created.get('token', '-')}")
                sub_url = created.get("subscription_url") or f"/sub/{created.get('subscription_token', '')}"
                output_fn(f"    URL:   {sub_url}")

            elif choice == "4":
                uid = input_fn("ID или никнейм пользователя: ").strip()
                new_nick = input_fn("Новый никнейм (Enter — оставить без изменений): ").strip() or None
                add_ext = input_fn(
                    "Новые внешние ссылки через запятую (Enter — оставить без изменений): "
                ).strip()
                ext_links = [x.strip() for x in add_ext.split(",") if x.strip()] if add_ext else None
                api.update_user(user_id=uid, nickname=new_nick, external_links=ext_links)
                output_fn(f"[✓] Пользователь '{uid}' успешно обновлён.")

            elif choice == "5":
                uid = input_fn("ID или никнейм пользователя для ротации токена: ").strip()
                res = api.rotate_token(uid)
                output_fn("[✓] Токен успешно обновлён!")
                output_fn(f"    Новый токен: {res.get('token') or res.get('subscription_token', '-')}")
                output_fn(f"    Новый URL:   {res.get('subscription_url', '-')}")

            elif choice == "6":
                uid = input_fn("ID или никнейм пользователя: ").strip()
                user = api.get_user(uid)
                cur_en = bool(user.get("enabled", True))
                target = not cur_en
                api.update_user(user_id=uid, enabled=target)
                status_str = "🟢 Включен" if target else "🔴 Отключен"
                output_fn(f"[✓] Статус пользователя '{uid}' изменён на: {status_str}")

            elif choice == "7":
                uid = input_fn("ID или никнейм пользователя: ").strip()
                launch_group_editor(uid, api_url=api.base_url)

            elif choice == "8":
                uid = input_fn("ID или никнейм пользователя: ").strip()
                user = api.get_user(uid)
                sub_url = user.get("subscription_url")
                if not sub_url:
                    sub_url = f"{api.base_url}/sub/{user.get('subscription_token') or user.get('token', '')}"
                output_fn(f"\nСсылка подписки:\n{sub_url}\n")
                show_qr(sub_url)

            elif choice == "9":
                uid = input_fn("ID или никнейм пользователя для удаления: ").strip()
                conf = input_fn(f"Вы действительно хотите удалить пользователя '{uid}'? (да/нет) [нет]: ").strip().lower()
                if conf in ("да", "yes", "y", "д"):
                    api.delete_user(uid)
                    output_fn(f"[✓] Пользователь '{uid}' удалён.")
                else:
                    output_fn("Удаление отменено.")

            elif choice == "s":
                output_fn("\n=== Служба tuna-subscriptions.service ===")
                output_fn("[1] Запустить  [2] Остановить  [3] Перезапустить")
                output_fn("[4] Автозапуск: вкл  [5] Автозапуск: выкл")
                output_fn("[6] Журнал службы (journalctl)")
                output_fn("[0] Назад")
                s_choice = input_fn("Выбор: ").strip()
                s_actions = {"1": "start", "2": "stop", "3": "restart", "4": "enable", "5": "disable"}
                if s_choice in s_actions:
                    ok = service_action(s_actions[s_choice])
                    output_fn(f"Операция '{s_actions[s_choice]}' выполнена: {'Успешно' if ok else 'Ошибка'}")
                elif s_choice == "6":
                    output_fn(service_journal(50))

            else:
                output_fn("Неверный пункт меню.")

        except SubscriptionAPIError as exc:
            output_fn(f"Ошибка подписок: {exc}")
        except Exception as exc:
            output_fn(f"Непредвиденная ошибка: {exc}")


def register_sub_cli(subparsers: argparse._SubParsersAction) -> None:
    """Register `tuna-dns sub` subparser and CLI actions."""
    sub_parser = subparsers.add_parser(
        "sub",
        help="Управление сервером подписок, пользователями и ссылками",
    )
    sub_parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help="URL HTTP API сервера подписок (по умолчанию: http://127.0.0.1:22217)",
    )
    sub_cmds = sub_parser.add_subparsers(dest="sub_action", required=False)

    sub_cmds.add_parser("list", help="Список пользователей и ссылок")

    add_p = sub_cmds.add_parser("add", help="Создать нового пользователя")
    add_p.add_argument("name", help="Имя пользователя (nickname)")
    add_p.add_argument(
        "--link",
        dest="links",
        action="append",
        default=[],
        help="Дополнительная внешняя ссылка (можно указывать несколько раз)",
    )
    add_p.add_argument(
        "--no-tunnel-link",
        action="store_true",
        help="Не добавлять автоматически ссылку из текущего DNS-туннеля",
    )

    get_p = sub_cmds.add_parser("get", help="Информация о пользователе")
    get_p.add_argument("user_id", help="ID или никнейм пользователя")

    del_p = sub_cmds.add_parser("delete", help="Удалить пользователя")
    del_p.add_argument("user_id", help="ID или никнейм пользователя")

    rot_p = sub_cmds.add_parser("rotate", help="Ротация токена подписки")
    rot_p.add_argument("user_id", help="ID или никнейм пользователя")

    sub_cmds.add_parser("status", help="Проверить статус сервиса подписок")

    srv_p = sub_cmds.add_parser("service", help="Управление службой tuna-subscriptions")
    srv_p.add_argument("action", choices=["start", "stop", "restart", "enable", "disable", "status", "logs"])


def handle_sub_cli(
    args: argparse.Namespace,
    manager: Optional[Any] = None,
    client: Optional[SubscriptionClient] = None,
) -> int:
    """Handle non-interactive `tuna-dns sub ...` CLI invocations."""
    api_url = getattr(args, "api_url", DEFAULT_API_URL)
    api = client or SubscriptionClient(base_url=api_url)
    action = getattr(args, "sub_action", None)

    if not action:
        # If bare `tuna-dns sub` is invoked, start TUI
        run_subscriptions_tui(manager=manager, client=api)
        return 0

    try:
        if action == "status":
            st = api.status()
            srv = service_state()
            state_str = "online" if st.get("online") else "offline"
            print(
                f"Подписки: {state_str} (API: {st['base_url']}, "
                f"пользователей: {st['users_count']}, systemd: {'active' if srv.get('active') else 'inactive'})"
            )
            return 0 if st.get("online") else 1

        if action == "list":
            users = api.list_users()
            if not users:
                print("Список пользователей пуст.")
                return 0
            for u in users:
                uid = u.get("id", "-")
                nick = u.get("nickname", "-")
                en = "enabled" if u.get("enabled", True) else "disabled"
                token = u.get("subscription_token") or u.get("token", "-")
                sub_url = u.get("subscription_url") or f"/sub/{token}"
                print(f"[{uid}] {nick} ({en}) | token={token} | url={sub_url}")
            return 0

        if action == "add":
            tunnel_settings = None
            if manager is not None:
                try:
                    m_st = manager.status()
                    if m_st.get("installed"):
                        tunnel_settings = m_st.get("settings")
                except Exception:
                    pass
            created = api.create_user(
                nickname=args.name,
                external_links=getattr(args, "links", []),
                auto_tunnel_link=not getattr(args, "no_tunnel_link", False),
                settings=tunnel_settings,
            )
            uid = created.get("id", "-")
            token = created.get("subscription_token") or created.get("token", "-")
            url = created.get("subscription_url") or f"/sub/{token}"
            print(f"Пользователь '{args.name}' создан (id={uid}, token={token}, url={url}).")
            return 0

        if action == "get":
            user = api.get_user(args.user_id)
            print(json.dumps(user, indent=2, ensure_ascii=False))
            return 0

        if action == "delete":
            api.delete_user(args.user_id)
            print(f"Пользователь '{args.user_id}' удалён.")
            return 0

        if action == "rotate":
            rotated = api.rotate_token(args.user_id)
            token = rotated.get("subscription_token") or rotated.get("token", "-")
            url = rotated.get("subscription_url", "-")
            print(f"Токен пользователя '{args.user_id}' обновлён: token={token}, url={url}")
            return 0

        if action == "service":
            srv_act = args.action
            if srv_act == "status":
                st = service_state()
                print(f"Служба {SERVICE_NAME}: active={st.get('active')}, enabled={st.get('enabled')}")
                return 0
            if srv_act == "logs":
                print(service_journal(50))
                return 0
            ok = service_action(srv_act)
            if ok:
                print(f"Действие '{srv_act}' для службы {SERVICE_NAME} успешно выполнено.")
                return 0
            print(f"Ошибка выполнения '{srv_act}' для {SERVICE_NAME}", file=sys.stderr)
            return 1

        print(f"Неизвестная команда подписок: {action}", file=sys.stderr)
        return 2

    except SubscriptionAPIError as exc:
        print(f"Ошибка API подписок: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
