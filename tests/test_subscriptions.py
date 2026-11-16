"""Unit tests for tuna_dns.subscriptions and its integration into tuna-dns-tunnel."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest.mock import MagicMock, patch

from tuna_dns import cli
from tuna_dns.subscriptions import (
    SubscriptionAPIError,
    SubscriptionClient,
    get_default_tunnel_link,
    handle_sub_cli,
    run_subscriptions_tui,
    validate_nickname,
)


class _FakeHTTPResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        if isinstance(payload, bytes):
            self._raw = payload
        elif isinstance(payload, str):
            self._raw = payload.encode("utf-8")
        else:
            self._raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class SubscriptionsClientTests(unittest.TestCase):
    def test_validate_nickname(self) -> None:
        self.assertTrue(validate_nickname("alice"))
        self.assertTrue(validate_nickname("User_123"))
        self.assertTrue(validate_nickname("test-client"))
        self.assertFalse(validate_nickname(""))
        self.assertFalse(validate_nickname("user@name"))
        self.assertFalse(validate_nickname("user space"))
        self.assertFalse(validate_nickname("a" * 65))

    @patch("urllib.request.urlopen")
    def test_list_and_get_users(self, mock_urlopen: MagicMock) -> None:
        client = SubscriptionClient("http://127.0.0.1:22217")

        mock_urlopen.return_value = _FakeHTTPResponse([
            {"id": "u1", "nickname": "alice", "subscription_token": "tok1", "enabled": True}
        ])
        users = client.list_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["nickname"], "alice")

        mock_urlopen.return_value = _FakeHTTPResponse({
            "id": "u1", "nickname": "alice", "subscription_token": "tok1"
        })
        user = client.get_user("u1")
        self.assertEqual(user["id"], "u1")

    @patch("urllib.request.urlopen")
    def test_create_user(self, mock_urlopen: MagicMock) -> None:
        client = SubscriptionClient("http://127.0.0.1:22217")
        mock_urlopen.return_value = _FakeHTTPResponse({
            "id": "u2", "nickname": "bob", "subscription_token": "tok2", "subscription_url": "/sub/tok2"
        })

        with patch("tuna_dns.subscriptions.get_default_tunnel_link", return_value="tuna://fake-tunnel-link"):
            res = client.create_user(
                nickname="bob",
                external_links=["vless://ext-node"],
                auto_tunnel_link=True,
            )
        self.assertEqual(res["id"], "u2")
        req_obj = mock_urlopen.call_args[0][0]
        data = json.loads(req_obj.data.decode("utf-8"))
        self.assertEqual(data["nickname"], "bob")
        self.assertIn("tuna://fake-tunnel-link", data["masterdnsvpn_uri"])
        self.assertIn("vless://ext-node", data["custom_uri"])

    @patch("urllib.request.urlopen")
    def test_update_delete_rotate(self, mock_urlopen: MagicMock) -> None:
        client = SubscriptionClient("http://127.0.0.1:22217")

        # Update
        mock_urlopen.return_value = _FakeHTTPResponse({"id": "u2", "nickname": "bob_new"})
        upd = client.update_user("u2", nickname="bob_new", enabled=False)
        self.assertEqual(upd["nickname"], "bob_new")
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "PUT")
        data = json.loads(req.data.decode("utf-8"))
        self.assertEqual(data["enabled"], 0)

        # Rotate token
        mock_urlopen.return_value = _FakeHTTPResponse({"token": "tok_rotated", "subscription_url": "/sub/tok_rotated"})
        rot = client.rotate_token("u2")
        self.assertEqual(rot["token"], "tok_rotated")

        # Delete
        mock_urlopen.return_value = _FakeHTTPResponse({"deleted": True})
        d_res = client.delete_user("u2")
        self.assertTrue(d_res.get("deleted"))

    @patch("urllib.request.urlopen")
    def test_status(self, mock_urlopen: MagicMock) -> None:
        client = SubscriptionClient("http://127.0.0.1:22217")
        mock_urlopen.return_value = _FakeHTTPResponse([{"id": "u1"}])
        st = client.status()
        self.assertTrue(st["online"])
        self.assertEqual(st["users_count"], 1)

    def test_get_default_tunnel_link(self) -> None:
        fake_settings = {
            "name": "test-tunnel",
            "domains": ["d1.example.org"],
            "listen_host": "0.0.0.0",
            "port": 53,
            "encryption_method": 5,
            "key": "A" * 32,
            "route": {"mode": "direct", "host": "127.0.0.1", "port": 1080, "username": "", "password": ""},
        }
        with patch("tuna_dns.exports.links", return_value=["tuna://generated-link"]):
            link = get_default_tunnel_link(settings=fake_settings)
            self.assertEqual(link, "tuna://generated-link")


class SubscriptionsCliTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_cli_sub_commands(self, mock_urlopen: MagicMock) -> None:
        # sub list
        mock_urlopen.return_value = _FakeHTTPResponse([
            {"id": "1", "nickname": "charlie", "subscription_token": "t_char", "enabled": True}
        ])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["sub", "list"])
        self.assertEqual(code, 0)
        self.assertIn("charlie", out.getvalue())

        # sub add
        mock_urlopen.return_value = _FakeHTTPResponse({
            "id": "2", "nickname": "dave", "subscription_token": "t_dave", "subscription_url": "/sub/t_dave"
        })
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["sub", "add", "dave", "--no-tunnel-link"])
        self.assertEqual(code, 0)
        self.assertIn("dave", out.getvalue())

        # sub rotate
        mock_urlopen.return_value = _FakeHTTPResponse({
            "token": "t_dave_new", "subscription_url": "/sub/t_dave_new"
        })
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["sub", "rotate", "dave"])
        self.assertEqual(code, 0)
        self.assertIn("t_dave_new", out.getvalue())

        # sub delete
        mock_urlopen.return_value = _FakeHTTPResponse({"deleted": True})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["sub", "delete", "dave"])
        self.assertEqual(code, 0)
        self.assertIn("удалён", out.getvalue())


class SubscriptionsTuiTests(unittest.TestCase):
    def test_tui_menu_list_and_exit(self) -> None:
        fake_client = MagicMock(spec=SubscriptionClient)
        fake_client.base_url = "http://127.0.0.1:22217"
        fake_client.status.return_value = {"online": True, "base_url": "http://127.0.0.1:22217", "users_count": 1}
        fake_client.list_users.return_value = [
            {"id": "1", "nickname": "eve", "enabled": True, "subscription_url": "/sub/eve_tok", "total_uris": 2}
        ]
        inputs = iter(["1", "0"])
        outputs: list[str] = []

        run_subscriptions_tui(
            client=fake_client,
            input_fn=lambda _: next(inputs),
            output_fn=outputs.append,
        )
        self.assertTrue(any("eve" in line for line in outputs))


if __name__ == "__main__":
    unittest.main()
