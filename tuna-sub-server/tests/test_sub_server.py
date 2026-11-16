#!/usr/bin/env python3
"""
Приемочные тесты для минимального сервера ссылок TUNA (Раздел 8 ТЗ).
Покрывает все 16 приемочных сценариев.
"""

import sys
import os
import io
import time
import json
import base64
import shutil
import urllib.request
import urllib.error
import tempfile
import threading
import sqlite3
import unittest

# Добавляем родительский каталог в sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from importlib import import_module
tuna_module = import_module("tuna-subscriptions")
SubscriptionApp = tuna_module.SubscriptionApp
SubscriptionRequestHandler = tuna_module.SubscriptionRequestHandler
ThreadingHTTPServer = tuna_module.ThreadingHTTPServer
serialize_openflux_v2_bundle = tuna_module.serialize_openflux_v2_bundle
deserialize_openflux_v2_bundle = tuna_module.deserialize_openflux_v2_bundle
validate_openflux_url = tuna_module.validate_openflux_url
validate_openflux_v2_payload = tuna_module.validate_openflux_v2_payload
build_openflux_v2_payload = tuna_module.build_openflux_v2_payload
repair_openflux_v2_database = tuna_module.repair_openflux_v2_database
rollback_openflux_v2_database = tuna_module.rollback_openflux_v2_database
is_canonical_uuid = tuna_module.is_canonical_uuid
init_database = tuna_module.init_database
serialize_webdav_uri = tuna_module.serialize_webdav_uri
parse_webdav_uri = tuna_module.parse_webdav_uri
validate_storage_spec = tuna_module.validate_storage_spec
validate_tuning_params = tuna_module.validate_tuning_params
import_server_webdav_config = tuna_module.import_server_webdav_config
MAX_WEBDAV_BACKENDS = tuna_module.MAX_WEBDAV_BACKENDS
MAX_WEBDAV_URI_BYTES = tuna_module.MAX_WEBDAV_URI_BYTES
MAX_SUBSCRIPTION_RESPONSE_BYTES = tuna_module.MAX_SUBSCRIPTION_RESPONSE_BYTES

repair_webdav_module = import_module("repair_webdav")
migrate_webdav_database = repair_webdav_module.migrate_webdav_database
rollback_webdav_database = repair_webdav_module.rollback_webdav_database




class TunaSubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp(prefix="tuna_test_")
        cls.db_path = os.path.join(cls.test_dir, "test_sub.db")
        cls.log_file = os.path.join(cls.test_dir, "test_service.log")

        cls.config = {
            "server": {
                "bind_address": "127.0.0.1",
                "port": 0,  # 0 выделит свободный системный порт
                "max_request_body_size": 65536,
            },
            "database": {
                "path": cls.db_path,
            },
            "limits": {
                "max_nickname_length": 64,
                "max_uri_length": 4096,
                "max_users": 1000,
            },
            "logging": {
                "file": cls.log_file,
                "level": "INFO",
            },
        }

        cls.app = SubscriptionApp(cls.config)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SubscriptionRequestHandler)
        cls.server.app = cls.app
        cls.port = cls.server.server_address[1]
        cls.app.bind_port = cls.port

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.conn.close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def api_request(self, method: str, path: str, data: dict = None, headers: dict = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req_headers = {"User-Agent": "TunaTest/1.0"}
        if headers:
            req_headers.update(headers)

        payload_bytes = None
        if data is not None:
            payload_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=payload_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                resp_data = resp.read()
                return resp.status, dict(resp.headers), resp_data
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    # --------------------------------------------------------------------------
    # ТЕСТ 1: Создание пользователя с ником и пятью ссылками
    # --------------------------------------------------------------------------
    def test_01_create_user(self):
        payload = {
            "nickname": "ivan",
            "csqtt": "csqtt://fixture-csqtt-password@192.0.2.40:37000?plugin=v2ray+tls",
            "qwdtt": "qwdtt://config?name=WDTT-Main&peer=192.0.2.40%3A56000&hashes=#",
            "snell": "snell://secret_psk_123@192.0.2.40:1488/?version=5&reuse=true&tfo=true#Snell-v5",
            "mieru": "mierus://ADMIN:mita_pass@192.0.2.40/?profile=Home&port=2020-2030&low-entropy-mode=LOW_ENTROPY_MODE_48",
            "masterdnsvpn": "stormdns://d.example.com?key=a7125b5f3cc23e525123c677bc6d202e#StormDNS"
        }
        status, headers, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        self.assertIn("id", res)
        self.assertIn("token", res)
        self.assertIn("subscription_url", res)
        self.assertEqual(res["nickname"], "ivan")
        self.assertEqual(res["revision"], 1)

    # --------------------------------------------------------------------------
    # ТЕСТ 2: Уникальный URL для двух пользователей
    # --------------------------------------------------------------------------
    def test_02_unique_url_for_two_users(self):
        s1, _, b1 = self.api_request("POST", "/api/users", {"nickname": "alice", "snell": "snell://p1@1.1.1.1:1488"})
        s2, _, b2 = self.api_request("POST", "/api/users", {"nickname": "bob", "snell": "snell://p2@2.2.2.2:1488"})
        self.assertEqual(s1, 201)
        self.assertEqual(s2, 201)
        u1 = json.loads(b1.decode())
        u2 = json.loads(b2.decode())
        self.assertNotEqual(u1["token"], u2["token"])
        self.assertNotEqual(u1["subscription_url"], u2["subscription_url"])

    # --------------------------------------------------------------------------
    # ТЕСТ 3: Изоляция: токен одного пользователя не выдаёт ссылки другого
    # --------------------------------------------------------------------------
    def test_03_token_isolation(self):
        _, _, b_alice = self.api_request("POST", "/api/users", {
            "nickname": "alice_iso",
            "snell": "snell://alice_secret@1.1.1.1:1488"
        })
        _, _, b_bob = self.api_request("POST", "/api/users", {
            "nickname": "bob_iso",
            "snell": "snell://bob_secret@2.2.2.2:1488"
        })
        tok_alice = json.loads(b_alice)["token"]
        tok_bob = json.loads(b_bob)["token"]

        # Запрос по токену Алисы
        s_a, _, body_a = self.api_request("GET", f"/sub/{tok_alice}")
        decoded_a = base64.b64decode(body_a).decode("utf-8")
        self.assertIn("alice_secret", decoded_a)
        self.assertNotIn("bob_secret", decoded_a)

        # Запрос по токену Боба
        s_b, _, body_b = self.api_request("GET", f"/sub/{tok_bob}")
        decoded_b = base64.b64decode(body_b).decode("utf-8")
        self.assertIn("bob_secret", decoded_b)
        self.assertNotIn("alice_secret", decoded_b)

    # --------------------------------------------------------------------------
    # ТЕСТ 4: Выдача всех пяти ссылок в заданном порядке
    # --------------------------------------------------------------------------
    def test_04_strict_five_protocols_order(self):
        csqtt_val = "csqtt://test_csqtt"
        qwdtt_val = "qwdtt://test_qwdtt"
        snell_val = "snell://test_snell"
        mieru_val = "mierus://test_mieru"
        dns_val   = "stormdns://test_dns"

        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "order_tester",
            "csqtt": csqtt_val,
            "qwdtt": qwdtt_val,
            "snell": snell_val,
            "mieru": mieru_val,
            "masterdnsvpn": dns_val
        })
        token = json.loads(body)["token"]

        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [line for line in base64.b64decode(sub_body).decode("utf-8").split("\n") if line]

        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], csqtt_val)
        self.assertEqual(lines[1], qwdtt_val)
        self.assertEqual(lines[2], snell_val)
        self.assertEqual(lines[3], mieru_val)
        self.assertEqual(lines[4], dns_val)

    # --------------------------------------------------------------------------
    # ТЕСТ 5: Выдача только непустых ссылок
    # --------------------------------------------------------------------------
    def test_05_only_non_empty_links(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "sparse_user",
            "csqtt": "",
            "qwdtt": "qwdtt://peer1",
            "snell": "",
            "mieru": "mierus://mita1",
            "masterdnsvpn": ""
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [line for line in base64.b64decode(sub_body).decode("utf-8").split("\n") if line]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "qwdtt://peer1")
        self.assertEqual(lines[1], "mierus://mita1")

    # --------------------------------------------------------------------------
    # ТЕСТ 6: Base64 корректно декодируется в UTF-8 строки URI
    # --------------------------------------------------------------------------
    def test_06_base64_decoding(self):
        csqtt = "csqtt://спец_пользователь:пароль@1.2.3.4:37000"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "utf8_user",
            "csqtt": csqtt
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        raw = base64.b64decode(sub_body).decode("utf-8")
        self.assertEqual(raw.strip(), csqtt)

    # --------------------------------------------------------------------------
    # ТЕСТ 7: Profile-Title содержит ник в UTF-8
    # --------------------------------------------------------------------------
    def test_07_profile_title_header(self):
        nick = "Алексей_VPN"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://test@1.1.1.1:1488"
        })
        token = json.loads(body)["token"]
        _, headers, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertIn("Profile-Title", headers)
        title_val = headers["Profile-Title"]
        # Декодируем если url-encoded или читаем напрямую
        from urllib.parse import unquote
        self.assertEqual(unquote(title_val), nick)
        # Проверяем, что в теле ответа никнейма нет как отдельной строки
        decoded_lines = base64.b64decode(sub_body).decode("utf-8").splitlines()
        self.assertNotIn(nick, decoded_lines)

    # --------------------------------------------------------------------------
    # ТЕСТ 8: CSQTT сохраняет '+' и специальные query-символы
    # --------------------------------------------------------------------------
    def test_08_csqtt_plus_and_query_symbols(self):
        csqtt_raw = "csqtt://sad+534188+sad@192.0.2.2:37000?plugin=v2ray+tls&path=/v2ray+path#CSQTT+VPN"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "plus_csqtt_user",
            "csqtt": csqtt_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, csqtt_raw)
        self.assertIn("+", decoded)
        self.assertNotIn(" ", decoded)

    # --------------------------------------------------------------------------
    # ТЕСТ 9: qWDTT с пустыми hash-параметрами проходит round-trip
    # --------------------------------------------------------------------------
    def test_09_qwdtt_empty_hash(self):
        qwdtt_raw = "qwdtt://config?name=WDTT-Main&peer=192.0.2.2%3A56000&hashes=#"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "qwdtt_empty_hash_user",
            "qwdtt": qwdtt_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, qwdtt_raw)

    # --------------------------------------------------------------------------
    # ТЕСТ 10: Snell, Mieru и MasterDnsVPN возвращаются без потери параметров
    # --------------------------------------------------------------------------
    def test_10_no_param_loss(self):
        snell_raw = "snell://psk_key@1.2.3.4:1488/?version=5&reuse=true&tfo=true&custom_unknown=param1#MySnell"
        mieru_raw = "mierus://user:pass@1.2.3.4/?profile=Mieru&port=2020-2030&custom_enum=999&unknown_flag=1"
        dns_raw   = "stormdns://d.lesovoi.pro?key=a7125b5f3cc23e525123c677bc6d202e&x=4#StormDNS"

        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "param_loss_user",
            "snell": snell_raw,
            "mieru": mieru_raw,
            "masterdnsvpn": dns_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]

        self.assertEqual(lines[0], snell_raw)
        self.assertEqual(lines[1], mieru_raw)
        self.assertEqual(lines[2], dns_raw)

    # --------------------------------------------------------------------------
    # ТЕСТ 11: stormdns:// возвращается без декодирования или сокращения payload
    # --------------------------------------------------------------------------
    def test_11_stormdns_full_payload(self):
        full_stormdns = "stormdns://full_complex_payload_base64_or_domain_data_1234567890?key=abcdef#FullPayloadName"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "stormdns_user",
            "masterdnsvpn": full_stormdns
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, full_stormdns)

    # --------------------------------------------------------------------------
    # ТЕСТ 12: Изменение ника или ссылки меняет revision и ETag
    # --------------------------------------------------------------------------
    def test_12_revision_and_etag_update(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "etag_user",
            "snell": "snell://key1@1.1.1.1:1488"
        })
        user = json.loads(body)
        u_id = user["id"]
        token = user["token"]

        # Первый запрос подписки
        _, h1, _ = self.api_request("GET", f"/sub/{token}")
        etag1 = h1.get("ETag")
        self.assertIsNotNone(etag1)

        # 304 Not Modified
        s_cache, _, _ = self.api_request("GET", f"/sub/{token}", headers={"If-None-Match": etag1})
        self.assertEqual(s_cache, 304)

        # Обновляем пользователя
        self.api_request("PUT", f"/api/users/{u_id}", {
            "snell": "snell://key2_MODIFIED@1.1.1.1:1488"
        })

        # Новый запрос подписки
        _, h2, _ = self.api_request("GET", f"/sub/{token}")
        etag2 = h2.get("ETag")
        self.assertNotEqual(etag1, etag2)

    # --------------------------------------------------------------------------
    # ТЕСТ 13: Ошибка обновления не стирает предыдущую рабочую выдачу
    # --------------------------------------------------------------------------
    def test_13_failed_update_preserves_data(self):
        orig_snell = "snell://working_psk@1.1.1.1:1488"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "fail_safe_user",
            "snell": orig_snell
        })
        user = json.loads(body)
        u_id = user["id"]
        token = user["token"]

        # Пытаемся передать невалидный URI с переводом строки
        bad_status, _, _ = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell": "snell://broken\nnewline@1.1.1.1:1488"
        })
        self.assertEqual(bad_status, 400)

        # Проверяем, что рабочая подписка цела
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, orig_snell)

    # --------------------------------------------------------------------------
    # ТЕСТ 14: Отключённый, удалённый или отозванный token не выдаёт ссылки
    # --------------------------------------------------------------------------
    def test_14_disabled_or_rotated_token(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "disable_user",
            "snell": "snell://pass@1.1.1.1:1488"
        })
        user = json.loads(body)
        u_id = user["id"]
        old_token = user["token"]

        # Работает
        s_ok, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_ok, 200)

        # 1. Отключаем пользователя (enabled = false)
        self.api_request("PUT", f"/api/users/{u_id}", {"enabled": False})
        s_dis, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_dis, 404)

        # Включаем обратно
        self.api_request("PUT", f"/api/users/{u_id}", {"enabled": True})

        # 2. Ротация токена
        _, _, b_rot = self.api_request("POST", f"/api/users/{u_id}/rotate-token")
        new_token = json.loads(b_rot)["token"]

        # Старый токен больше не работает
        s_old, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_old, 404)

        # Новый токен работает
        s_new, _, _ = self.api_request("GET", f"/sub/{new_token}")
        self.assertEqual(s_new, 200)

        # 3. Удаление пользователя
        self.api_request("DELETE", f"/api/users/{u_id}")
        s_del, _, _ = self.api_request("GET", f"/sub/{new_token}")
        self.assertEqual(s_del, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 15: URI и токены отсутствуют в обычных логах
    # --------------------------------------------------------------------------
    def test_15_no_tokens_or_uris_in_logs(self):
        super_secret_token = "TOP_SECRET_TOKEN_XYZ_12345"
        super_secret_uri = "snell://SECRET_PASS_999@1.1.1.1:1488"

        # Делаем запрос к серверу с секретным токеном
        self.api_request("GET", f"/sub/{super_secret_token}")

        # Проверяем файл лога
        if os.path.isfile(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                logs = f.read()
                self.assertNotIn(super_secret_token, logs, "Secret token leaked in logs!")
                self.assertNotIn(super_secret_uri, logs, "Secret URI leaked in logs!")

    # --------------------------------------------------------------------------
    # ТЕСТ 16: Сервис не меняет и не вызывает API существующей панели
    # --------------------------------------------------------------------------
    def test_16_service_isolation(self):
        # Сервис не открывает соединений к другим портам и не имеет зависимостей
        # от sing-box/xray/3x-ui
        status, _, body = self.api_request("GET", "/health")
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(res.get("service"), "tuna-subscriptions")
        # База данных не имеет таблиц от 3x-ui
        c = self.app.conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in c.fetchall()]
        self.assertNotIn("inbounds", tables)
        self.assertNotIn("settings", tables)
        self.assertIn("users", tables)

    # --------------------------------------------------------------------------
    # ТЕСТ 17: Поддержка нескольких ссылок (2, 3, 4 и более) на протокол
    # --------------------------------------------------------------------------
    def test_17_multi_links_per_protocol(self):
        snell_nodes = [
            "snell://psk_de@1.1.1.1:1488/?version=5&reuse=true#Snell-Frankfurt",
            "snell://psk_nl@2.2.2.2:1488/?version=5&reuse=true#Snell-Amsterdam",
            "snell://psk_us@3.3.3.3:1488/?version=5&reuse=true#Snell-NewYork",
        ]
        mieru_nodes = [
            "mierus://user1:pass1@4.4.4.4/?profile=Mieru-DE&port=2020-2030",
            "mierus://user2:pass2@5.5.5.5/?profile=Mieru-FI&port=3030-3040",
        ]
        qwdtt_node = "qwdtt://config?name=WDTT-Main&peer=6.6.6.6%3A56000&hashes=#"

        payload = {
            "nickname": "multi_node_user",
            "snell": "\n".join(snell_nodes),
            "mieru": "\n".join(mieru_nodes),
            "qwdtt": qwdtt_node
        }

        status, _, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res["total_uris"], 6)
        token = res["token"]

        # Получаем подписку и проверяем все 6 ссылок в теле
        sub_status, _, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(sub_status, 200)
        decoded_lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]

        self.assertEqual(len(decoded_lines), 6)
        # Порядок выдачи ТЗ: QWDTT -> Snell (все 3) -> Mieru (все 2)
        self.assertEqual(decoded_lines[0], qwdtt_node)
        self.assertEqual(decoded_lines[1], snell_nodes[0])
        self.assertEqual(decoded_lines[2], snell_nodes[1])
        self.assertEqual(decoded_lines[3], snell_nodes[2])
        self.assertEqual(decoded_lines[4], mieru_nodes[0])
        self.assertEqual(decoded_lines[5], mieru_nodes[1])

    # --------------------------------------------------------------------------
    # ТЕСТ 18: Передача мульти-ссылок в виде JSON-массивов и custom-протоколы
    # --------------------------------------------------------------------------
    def test_18_multi_links_as_json_arrays(self):
        csqtt_arr = [
            "csqtt://pass1@1.2.3.4:37000#CSQTT-1",
            "csqtt://pass2@1.2.3.5:37000#CSQTT-2"
        ]
        custom_arr = [
            "vless://uuid1@1.2.3.6:443?security=reality&sni=example.com#VLESS-Node",
            "ss://YWVzLTEyOC1nY206cGFzczE@1.2.3.7:8388#Shadowsocks-Node"
        ]

        payload = {
            "nickname": "json_array_user",
            "csqtt_uris": csqtt_arr,
            "custom": custom_arr
        }

        status, _, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        u_id = res["id"]
        token = res["token"]
        self.assertEqual(res["total_uris"], 4)

        # GET /api/users/<id>
        g_status, _, g_body = self.api_request("GET", f"/api/users/{u_id}")
        self.assertEqual(g_status, 200)
        g_res = json.loads(g_body.decode("utf-8"))
        self.assertEqual(len(g_res["csqtt_uris"]), 2)
        self.assertEqual(len(g_res["custom_uris"]), 2)
        self.assertEqual(g_res["total_uris"], 4)

        # Подписка
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0], csqtt_arr[0])
        self.assertEqual(lines[1], csqtt_arr[1])
        self.assertEqual(lines[2], custom_arr[0])
        self.assertEqual(lines[3], custom_arr[1])

    # --------------------------------------------------------------------------
    # ТЕСТ 19: Обновление пользователя новыми мульти-ссылками и валидация
    # --------------------------------------------------------------------------
    def test_19_update_user_multi_links(self):
        # Создаем пользователя с 1 Snell ссылкой
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "update_multi_user",
            "snell": "snell://init@1.1.1.1:1488"
        })
        user = json.loads(body.decode("utf-8"))
        u_id = user["id"]
        token = user["token"]

        # Обновляем на 3 Snell ссылки через PUT
        new_snell_list = [
            "snell://node_a@1.1.1.1:1488",
            "snell://node_b@1.1.1.2:1488",
            "snell://node_c@1.1.1.3:1488"
        ]
        u_status, _, u_body = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell_uris": new_snell_list
        })
        self.assertEqual(u_status, 200)
        u_res = json.loads(u_body.decode("utf-8"))
        self.assertEqual(u_res["total_uris"], 3)
        self.assertEqual(len(u_res["snell_uris"]), 3)

        # Подписка обновлена
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], new_snell_list[0])
        self.assertEqual(lines[2], new_snell_list[2])

        # Ошибка при попытке передать массив с невалидным элементом
        err_status, _, err_body = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell_uris": ["snell://valid@1.1.1.1:1488", "broken_without_scheme"]
        })
        self.assertEqual(err_status, 400)

    # --------------------------------------------------------------------------
    # ТЕСТ 20: Доступ, обновление и удаление пользователя напрямую по никнейму
    # --------------------------------------------------------------------------
    def test_20_access_and_modify_by_nickname(self):
        nick = "nick_tester"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://init@1.1.1.1:1488"
        })
        self.assertEqual(status, 201)

        # GET по никнейму
        g_status, _, g_body = self.api_request("GET", f"/api/users/{nick}")
        self.assertEqual(g_status, 200)
        u_info = json.loads(g_body.decode("utf-8"))
        self.assertEqual(u_info["nickname"], nick)

        # PUT по никнейму (обновление ссылок)
        p_status, _, p_body = self.api_request("PUT", f"/api/users/{nick}", {
            "csqtt": "csqtt://pass@1.1.1.1:37000#MyCSQTT"
        })
        self.assertEqual(p_status, 200)

        # DELETE по никнейму
        d_status, _, _ = self.api_request("DELETE", f"/api/users/{nick}")
        self.assertEqual(d_status, 200)

        # Проверка удаления
        chk_status, _, _ = self.api_request("GET", f"/api/users/{nick}")
        self.assertEqual(chk_status, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 21: Удаление пользователя с кириллическим никнеймом (например: тесовой3)
    # --------------------------------------------------------------------------
    def test_21_cyrillic_user_delete(self):
        nick = "тесовой_делете_тест"
        encoded_nick = urllib.parse.quote(nick)
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://init@1.1.1.1:1488#Node"
        })
        self.assertEqual(status, 201)

        # GET по закодированному никнейму
        g_status, _, g_body = self.api_request("GET", f"/api/users/{encoded_nick}")
        self.assertEqual(g_status, 200)

        # DELETE по закодированному никнейму
        d_status, _, d_body = self.api_request("DELETE", f"/api/users/{encoded_nick}")
        self.assertEqual(d_status, 200)

        # Проверка, что пользователя больше нет
        chk_status, _, _ = self.api_request("GET", f"/api/users/{encoded_nick}")
        self.assertEqual(chk_status, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 22: Сохранение индивидуальных имен серверов CSQTT в подписке
    # --------------------------------------------------------------------------
    def test_22_csqtt_server_names_preservation(self):
        nick = "csqtt_named_user"
        csqtt_nodes = [
            "csqtt://pass1@1.2.3.4:37000#CSQTT-SPB",
            "csqtt://pass2@5.6.7.8:37000#CSQTT-Frankfurt",
            "csqtt://pass3@9.10.11.12:37000#CSQTT-Home"
        ]
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "csqtt_uris": csqtt_nodes
        })
        self.assertEqual(status, 201)
        resp = json.loads(body.decode("utf-8"))
        token = resp["token"]

        # Получаем подписку
        sub_status, _, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(sub_status, 200)
        decoded = base64.b64decode(sub_body).decode("utf-8").strip().splitlines()

        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], "csqtt://pass1@1.2.3.4:37000#CSQTT-SPB")
        self.assertEqual(decoded[1], "csqtt://pass2@5.6.7.8:37000#CSQTT-Frankfurt")
        self.assertEqual(decoded[2], "csqtt://pass3@9.10.11.12:37000#CSQTT-Home")

    # --------------------------------------------------------------------------
    # ТЕСТ 23: Наличие subscription_url и token в list_users и get_user
    # --------------------------------------------------------------------------
    def test_23_subscription_url_in_list_and_get(self):
        nick = "sub_url_user"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://pass@1.1.1.1:1488#Node"
        })
        self.assertEqual(status, 201)
        created = json.loads(body.decode("utf-8"))
        tok = created["token"]
        expected_sub_url = created["subscription_url"]

        # 1. Проверяем в GET /api/users
        status_list, _, body_list = self.api_request("GET", "/api/users")
        self.assertEqual(status_list, 200)
        users = json.loads(body_list.decode("utf-8"))
        target = [u for u in users if u["nickname"] == nick]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["subscription_url"], expected_sub_url)
        self.assertEqual(target[0]["token"], tok)

        # 2. Проверяем в GET /api/users/<id>
        status_get, _, body_get = self.api_request("GET", f"/api/users/{target[0]['id']}")
        self.assertEqual(status_get, 200)
        u_get = json.loads(body_get.decode("utf-8"))
        self.assertEqual(u_get["subscription_url"], expected_sub_url)
        self.assertEqual(u_get["token"], tok)

    # --------------------------------------------------------------------------
    # ТЕСТ 24: Каноническая сериализация и десериализация OpenFlux v2
    # --------------------------------------------------------------------------
    def test_24_openflux_serialization_and_deserialization_roundtrip(self):
        sample_payload = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": "c1f10903-88f5-467f-94d7-eaeead8eef24",
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "TUNA-OpenFlux-Office",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "8bfa5716-1763-471a-ba2d-c1240c114ce7",
                    "name": "OF-Group-1",
                    "transport": "mailru",
                    "urls": [
                        "https://cloud.mail.ru/public/Test1/doc1"
                    ],
                    "codec": "legacy",
                    "encryption_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                }
            ]
        }
        ok, err, v2_uri = serialize_openflux_v2_bundle(sample_payload)
        self.assertTrue(ok, f"Serialization failed: {err}")
        self.assertTrue(v2_uri.startswith("openflux-bundle://v2/"))

        # Проверка отсутствия '=' в base64url
        raw_b64 = v2_uri[len("openflux-bundle://v2/"):]
        self.assertFalse(raw_b64.endswith("="))
        self.assertNotIn("+", raw_b64)
        self.assertNotIn("/", raw_b64)

        # Обратная десериализация
        ok_de, err_de, decoded = deserialize_openflux_v2_bundle(v2_uri)
        self.assertTrue(ok_de, f"Deserialization failed: {err_de}")
        self.assertEqual(decoded["schema"], "tuna.openflux.bundle")
        self.assertEqual(decoded["version"], 2)
        self.assertEqual(decoded["name"], "TUNA-OpenFlux-Office")
        self.assertEqual(decoded["groups"][0]["transport"], "mailru")
        self.assertEqual(decoded["groups"][0]["codec"], "legacy")
        self.assertNotIn("mode", decoded["groups"][0])

    # --------------------------------------------------------------------------
    # ТЕСТ 25: Валидация схемы и запрет недопустимых транспортов/форматов в v2
    # --------------------------------------------------------------------------
    def test_25_openflux_validation_rules_and_limits(self):
        base_payload = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": "c1f10903-88f5-467f-94d7-eaeead8eef24",
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "Validation-Test",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "name": "G1",
                    "transport": "mailru",
                    "urls": ["https://cloud.mail.ru/public/Test/doc1"],
                    "codec": "legacy",
                    "encryption_key": "key1234567890123"
                }
            ]
        }

        # 1. Запрещенный транспорт (yandex, vless и др.)
        bad_tr_payload = json.loads(json.dumps(base_payload))
        bad_tr_payload["groups"][0]["transport"] = "yandex"
        ok_tr, err_tr, _ = serialize_openflux_v2_bundle(bad_tr_payload)
        self.assertFalse(ok_tr)
        self.assertIn("forbidden transport", err_tr)

        # 2. Неверная схема (старая openflux-bundle должна отклоняться)
        bad_schema = json.loads(json.dumps(base_payload))
        bad_schema["schema"] = "openflux-bundle"
        ok_bs, err_bs, _ = serialize_openflux_v2_bundle(bad_schema)
        self.assertFalse(ok_bs)
        self.assertIn("Invalid schema", err_bs)

        # 3. Запрет mode внутри wire-группы
        bad_grp_mode = json.loads(json.dumps(base_payload))
        bad_grp_mode["groups"][0]["mode"] = "classic"
        ok_gm, err_gm, _ = serialize_openflux_v2_bundle(bad_grp_mode)
        self.assertFalse(ok_gm)
        self.assertIn("wire object must NOT contain 'mode'", err_gm)

        # 4. Неверная версия
        bad_ver = json.loads(json.dumps(base_payload))
        bad_ver["version"] = 1
        ok_bv, err_bv, _ = serialize_openflux_v2_bundle(bad_ver)
        self.assertFalse(ok_bv)

        # 5. В режиме classic более 1 URL
        bad_cl_urls = json.loads(json.dumps(base_payload))
        bad_cl_urls["groups"][0]["urls"] = ["https://cloud.mail.ru/1", "https://cloud.mail.ru/2"]
        ok_cl, _, _ = serialize_openflux_v2_bundle(bad_cl_urls)
        self.assertFalse(ok_cl)

        # 6. В режиме multistream более 4 URL
        bad_ms_urls = json.loads(json.dumps(base_payload))
        bad_ms_urls["mode"] = "multistream"
        bad_ms_urls["groups"][0]["urls"] = [f"https://cloud.mail.ru/{i}" for i in range(5)]
        ok_ms, _, _ = serialize_openflux_v2_bundle(bad_ms_urls)
        self.assertFalse(ok_ms)

        # 7. Дубликаты URL в группе
        bad_dup = json.loads(json.dumps(base_payload))
        bad_dup["mode"] = "multistream"
        bad_dup["groups"][0]["urls"] = ["https://cloud.mail.ru/same", "https://cloud.mail.ru/same"]
        ok_dup, _, _ = serialize_openflux_v2_bundle(bad_dup)
        self.assertFalse(ok_dup)

        # 8. Невалидный URL (http:// вместо https:// или пробелы или запятые)
        self.assertFalse(validate_openflux_url("http://insecure.site")[0])
        self.assertFalse(validate_openflux_url("https://site.com/with space")[0])
        self.assertFalse(validate_openflux_url("https://cloud.mail.ru/doc1,https://cloud.mail.ru/doc2")[0])
        self.assertTrue(validate_openflux_url("https://cloud.mail.ru/public/abc")[0])

    # --------------------------------------------------------------------------
    # ТЕСТ 26: CRUD API каталога групп OpenFlux (/api/openflux/groups)
    # --------------------------------------------------------------------------
    def test_26_openflux_groups_crud_api(self):
        # 1. Создание группы classic (mailru)
        g1_data = {
            "name": "MailRu-Cluster-1",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/123/file.dat"],
            "codec": "legacy",
            "encryption_key": "secret1234567890",
            "source_slot": 1
        }
        st1, _, b1 = self.api_request("POST", "/api/openflux/groups", g1_data)
        self.assertEqual(st1, 201)
        res1 = json.loads(b1.decode())
        g1_id = res1["id"]
        self.assertEqual(res1["name"], "MailRu-Cluster-1")
        self.assertEqual(res1["transport"], "mailru")

        # 2. Создание группы multistream (boards, 3 URL)
        g2_data = {
            "name": "Boards-Multi",
            "mode": "multistream",
            "transport": "boards",
            "urls": [
                "https://boards.example.com/d/1",
                "https://boards.example.com/d/2",
                "https://boards.example.com/d/3"
            ],
            "codec": "batched",
            "encryption_key": "sec_boards_12345"
        }
        st2, _, b2 = self.api_request("POST", "/api/openflux/groups", g2_data)
        self.assertEqual(st2, 201)
        res2 = json.loads(b2.decode())
        g2_id = res2["id"]
        self.assertEqual(len(res2["urls"]), 3)
        self.assertEqual(res2["codec"], "batched")

        # Проверка отклонения короткого ключа (< 16 байт)
        st_short_k, _, _ = self.api_request("POST", "/api/openflux/groups", {
            "name": "Short-Key",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/short/key"],
            "encryption_key": "short_key"
        })
        self.assertEqual(st_short_k, 400)

        # Проверка отклонения URL с буквальной запятой
        st_comma, _, _ = self.api_request("POST", "/api/openflux/groups", {
            "name": "Comma-URL",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/1,2"]
        })
        self.assertEqual(st_comma, 400)

        # 3. Отклонение запрещенного транспорта (yandex)
        st_bad, _, b_bad = self.api_request("POST", "/api/openflux/groups", {
            "name": "Bad-Legacy-Yandex",
            "mode": "classic",
            "transport": "yandex",
            "urls": ["https://disk.yandex.ru/i/123"]
        })
        self.assertEqual(st_bad, 400)
        self.assertIn("Invalid transport", json.loads(b_bad.decode())["error"])

        # 4. Отклонение недопустимого URL (без https)
        st_http, _, b_http = self.api_request("POST", "/api/openflux/groups", {
            "name": "HTTP-Test",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["http://cloud.mail.ru/plain"]
        })
        self.assertEqual(st_http, 400)

        # 5. Список групп GET /api/openflux/groups
        st_list, _, b_list = self.api_request("GET", "/api/openflux/groups")
        self.assertEqual(st_list, 200)
        groups = json.loads(b_list.decode())
        self.assertTrue(any(g["id"] == g1_id for g in groups))
        self.assertTrue(any(g["id"] == g2_id for g in groups))

        # 6. Получение группы по ID
        st_get, _, b_get = self.api_request("GET", f"/api/openflux/groups/{g1_id}")
        self.assertEqual(st_get, 200)
        self.assertEqual(json.loads(b_get.decode())["id"], g1_id)

        # 7. Обновление группы PUT
        st_upd, _, b_upd = self.api_request("PUT", f"/api/openflux/groups/{g1_id}", {
            "name": "MailRu-Cluster-Updated",
            "codec": "batched"
        })
        self.assertEqual(st_upd, 200)
        res_upd = json.loads(b_upd.decode())
        self.assertEqual(res_upd["name"], "MailRu-Cluster-Updated")
        self.assertEqual(res_upd["codec"], "batched")

        # 8. Удаление группы DELETE
        st_del, _, _ = self.api_request("DELETE", f"/api/openflux/groups/{g2_id}")
        self.assertEqual(st_del, 200)
        st_404, _, _ = self.api_request("GET", f"/api/openflux/groups/{g2_id}")
        self.assertEqual(st_404, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 27: Конфигурация OpenFlux для пользователя (/api/users/<id>/openflux)
    # --------------------------------------------------------------------------
    def test_27_openflux_user_config_and_validation(self):
        # Создаем тестового пользователя
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": "of_user_cfg"})
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]

        # Создаем валидную группу classic (cupsonline)
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Cups-Group",
            "mode": "classic",
            "transport": "cupsonline",
            "urls": ["https://cups.online/api/doc_abc"],
            "codec": "legacy"
        })
        grp_id = json.loads(b_g.decode())["id"]

        # 1. По умолчанию OpenFlux выключен
        st_init, _, b_init = self.api_request("GET", f"/api/users/{u_id}/openflux")
        self.assertEqual(st_init, 200)
        res_init = json.loads(b_init.decode())
        self.assertFalse(res_init["enabled"])
        self.assertEqual(res_init["groups"], [])
        self.assertEqual(res_init["v2_uri"], "")
        stable_conn_id = res_init["connection_id"]
        self.assertTrue(len(stable_conn_id) > 10)

        # 2. Включаем OpenFlux для пользователя
        st_put, _, b_put = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "TUNA-User-Connection",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "group_ids": [grp_id]
        })
        self.assertEqual(st_put, 200)
        res_put = json.loads(b_put.decode())
        self.assertTrue(res_put["enabled"])
        self.assertEqual(res_put["name"], "TUNA-User-Connection")
        self.assertEqual(res_put["connection_id"], stable_conn_id)
        self.assertTrue(res_put["v2_uri"].startswith("openflux-bundle://v2/"))
        self.assertEqual(len(res_put["groups"]), 1)

        # 3. Ошибка при несуществующей группе
        st_err, _, b_err = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": ["00000000-0000-0000-0000-000000000000"]
        })
        self.assertEqual(st_err, 400)

        # 4. Ошибка при дубликатах group_ids
        st_dup, _, b_dup = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [grp_id, grp_id]
        })
        self.assertEqual(st_dup, 400)

    # --------------------------------------------------------------------------
    # ТЕСТ 28: Обратная совместимость для существующих пользователей (выключен OpenFlux)
    # --------------------------------------------------------------------------
    def test_28_subscription_without_openflux_backward_compatibility(self):
        nick = "compat_user_no_of"
        _, _, b_u = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://psk123@1.2.3.4:1488#Snell",
            "mieru": "mierus://u:p@1.2.3.4/?profile=P1#Mieru"
        })
        tok = json.loads(b_u.decode())["token"]

        # Запрашиваем подписку
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        decoded = base64.b64decode(b_sub).decode("utf-8")
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "snell://psk123@1.2.3.4:1488#Snell")
        self.assertEqual(lines[1], "mierus://u:p@1.2.3.4/?profile=P1#Mieru")
        self.assertNotIn("openflux-bundle://", decoded)

    # --------------------------------------------------------------------------
    # ТЕСТ 29: Выдача подписки со строкой OpenFlux v2 бандла
    # --------------------------------------------------------------------------
    def test_29_subscription_with_openflux_bundle_output(self):
        nick = "of_bundle_subscriber"
        _, _, b_u = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://psk999@5.5.5.5:1488#SnellMain"
        })
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]
        tok = u_info["token"]

        # Создаем группу OpenFlux
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Sub-Group-1",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/Sub/test.txt"],
            "codec": "legacy",
            "encryption_key": "sub_key_12345678"
        })
        gid = json.loads(b_g.decode())["id"]

        # Привязываем и включаем для пользователя
        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "Office-Full-Bundle",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "group_ids": [gid]
        })

        # Получаем подписку
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        decoded_text = base64.b64decode(b_sub).decode("utf-8")
        lines = [l.strip() for l in decoded_text.splitlines() if l.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "snell://psk999@5.5.5.5:1488#SnellMain")
        self.assertTrue(lines[1].startswith("openflux-bundle://v2/"))

        # Валидируем распарсенный бандл v2
        ok, err, bundle = deserialize_openflux_v2_bundle(lines[1])
        self.assertTrue(ok, f"Bundle validation error: {err}")
        self.assertEqual(bundle["name"], "Office-Full-Bundle")
        self.assertEqual(bundle["mode"], "classic")
        self.assertEqual(len(bundle["groups"]), 1)
        self.assertEqual(bundle["groups"][0]["name"], "Sub-Group-1")
        self.assertEqual(bundle["groups"][0]["urls"], ["https://cloud.mail.ru/public/Sub/test.txt"])

    # --------------------------------------------------------------------------
    # ТЕСТ 30: Пользователь ТОЛЬКО с OpenFlux получает 200 OK (не 204!)
    # --------------------------------------------------------------------------
    def test_30_subscription_with_only_openflux_returns_200(self):
        nick = "only_of_subscriber"
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": nick})
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]
        tok = u_info["token"]

        # До включения OpenFlux: нет ссылок -> 204 No Content
        st_empty, _, _ = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_empty, 204)

        # Создаем и привязываем группу
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Solo-Group",
            "mode": "classic",
            "transport": "boards",
            "urls": ["https://boards.example.com/doc/single"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [gid]
        })

        # После включения OpenFlux: возвращает 200 OK
        st_ok, headers, b_payload = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_ok, 200)
        self.assertIn("ETag", headers)

        decoded = base64.b64decode(b_payload).decode("utf-8").strip().splitlines()
        self.assertEqual(len(decoded), 1)
        self.assertTrue(decoded[0].startswith("openflux-bundle://v2/"))

    # --------------------------------------------------------------------------
    # ТЕСТ 31: Каскадный инкремент ревизии и ETag при обновлении группы
    # --------------------------------------------------------------------------
    def test_31_openflux_group_update_cascades_revision_bump(self):
        nick = "cascade_rev_user"
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": nick})
        u_id = json.loads(b_u.decode())["id"]
        tok = json.loads(b_u.decode())["token"]

        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Cascade-Group",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/A/1"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [gid]
        })

        # Получаем подписку и ETag
        st1, h1, b_sub1 = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st1, 200)
        etag1 = h1["ETag"]

        # Повторный запрос с If-None-Match без изменений возвращает 304 Not Modified
        st_304, _, _ = self.api_request("GET", f"/sub/{tok}", headers={"If-None-Match": etag1})
        self.assertEqual(st_304, 304)

        # Теперь обновляем саму группу (меняем URL)
        st_upd, _, _ = self.api_request("PUT", f"/api/openflux/groups/{gid}", {
            "urls": ["https://cloud.mail.ru/public/A/2_updated"]
        })
        self.assertEqual(st_upd, 200)

        # Запрос с прежним ETag должен вернуть 200 OK (новые данные) и новый ETag
        st2, h2, b_sub2 = self.api_request("GET", f"/sub/{tok}", headers={"If-None-Match": etag1})
        self.assertEqual(st2, 200)
        etag2 = h2["ETag"]
        self.assertNotEqual(etag1, etag2)

        decoded2 = base64.b64decode(b_sub2).decode("utf-8").strip()
        ok_de, _, data2 = deserialize_openflux_v2_bundle(decoded2)
        self.assertTrue(ok_de)
        self.assertEqual(data2["groups"][0]["urls"], ["https://cloud.mail.ru/public/A/2_updated"])

    # --------------------------------------------------------------------------
    # ТЕСТ 32: Синтетические фикстуры (8 групп classic и 8 групп multistream 8x4)
    # --------------------------------------------------------------------------
    def test_32_synthetic_8_groups_classic_and_multistream_fixtures(self):
        fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
        os.makedirs(fixtures_dir, exist_ok=True)
        issuer_id = "c1f10903-88f5-467f-94d7-eaeead8eef24"

        # 0. Бандл Single Group (1 группа, classic, mailru)
        single_bundle = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "TUNA-OpenFlux-Single",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "8bfa5716-1763-471a-ba2d-c1240c114ce7",
                    "name": "OF-Group-MailRu",
                    "transport": "mailru",
                    "urls": ["https://cloud.mail.ru/public/Test/doc1"],
                    "codec": "legacy",
                    "encryption_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                }
            ]
        }
        ok_sg, err_sg, uri_sg = serialize_openflux_v2_bundle(single_bundle)
        self.assertTrue(ok_sg, f"Single group serialization failed: {err_sg}")
        with open(os.path.join(fixtures_dir, "single_group_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(single_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "single_group_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_sg)
        with open(os.path.join(fixtures_dir, "single_group_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_sg + "\n").encode("utf-8")).decode("ascii"))

        # 1. Бандл Classic (8 групп × 1 URL, смешанные транспорты)
        classic_groups = []
        transports = ["mailru", "boards", "cupsonline"]
        for idx in range(1, 9):
            tr = transports[(idx - 1) % len(transports)]
            codec = "batched" if idx % 2 == 0 else "legacy"
            url = f"https://{tr}.example.com/doc/ch{idx}"
            if tr == "cupsonline":
                url = f"https://cups.online/live-coding/?room=ch{idx}"
            classic_groups.append({
                "id": f"00000000-0000-0000-0000-00000000000{idx}",
                "name": f"Classic-Group-{idx}",
                "transport": tr,
                "urls": [url],
                "codec": codec,
                "encryption_key": f"key_hex_{idx * 11111111}"
            })

        classic_bundle = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "77777777-1111-4444-8888-999999999999",
            "revision": 2,
            "name": "TUNA-OpenFlux-Classic-8",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": classic_groups
        }

        ok_cl, err_cl, uri_cl = serialize_openflux_v2_bundle(classic_bundle)
        self.assertTrue(ok_cl, f"Classic 8x1 serialization failed: {err_cl}")
        self.assertLess(len(uri_cl), 700000)

        # Сохранение фикстуры classic 8x1
        with open(os.path.join(fixtures_dir, "classic_8x1_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(classic_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "classic_8x1_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_cl)
        with open(os.path.join(fixtures_dir, "classic_8x1_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_cl + "\n").encode("utf-8")).decode("ascii"))

        # 2. Бандл MultiStream (8 групп × 4 URL = 32 URL суммарно)
        ms_groups = []
        for idx in range(1, 9):
            tr = transports[(idx - 1) % len(transports)]
            codec = "batched" if idx % 2 == 0 else "legacy"
            if tr == "cupsonline":
                urls = [f"https://cups.online/live-coding/?room=ch{idx}_part_{part}" for part in range(1, 5)]
            else:
                urls = [f"https://{tr}.example.com/doc/ch{idx}/part_{part}" for part in range(1, 5)]
            ms_groups.append({
                "id": f"00000000-0000-0000-0000-00000000001{idx}",
                "name": f"MultiStream-Group-{idx}",
                "transport": tr,
                "urls": urls,
                "codec": codec,
                "encryption_key": f"ms_key_hex_{idx * 22222222}"
            })

        ms_bundle = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "88888888-2222-5555-9999-000000000000",
            "revision": 5,
            "name": "TUNA-OpenFlux-MultiStream-32",
            "mode": "multistream",
            "balancer_strategy": "leastPing",
            "groups": ms_groups
        }

        ok_ms, err_ms, uri_ms = serialize_openflux_v2_bundle(ms_bundle)
        self.assertTrue(ok_ms, f"MultiStream 8x4 serialization failed: {err_ms}")
        self.assertLess(len(uri_ms), 700000)

        # Сохранение фикстуры multistream 8x4
        with open(os.path.join(fixtures_dir, "multistream_8x4_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(ms_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "multistream_8x4_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_ms)
        with open(os.path.join(fixtures_dir, "multistream_8x4_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_ms + "\n").encode("utf-8")).decode("ascii"))

        # Проверка десериализации обоих
        ok_de_cl, _, de_cl = deserialize_openflux_v2_bundle(uri_cl)
        self.assertTrue(ok_de_cl)
        self.assertEqual(len(de_cl["groups"]), 8)

        ok_de_ms, _, de_ms = deserialize_openflux_v2_bundle(uri_ms)
        self.assertTrue(ok_de_ms)
        self.assertEqual(len(de_ms["groups"]), 8)
        total_urls_ms = sum(len(g["urls"]) for g in de_ms["groups"])
        self.assertEqual(total_urls_ms, 32)

    # --------------------------------------------------------------------------
    # ТЕСТ 33: Безопасный импорт локальных инстансов OpenFlux (/api/openflux/import-local)
    # --------------------------------------------------------------------------
    def test_33_openflux_local_instances_import(self):
        mock_instances_dir = os.path.join(self.test_dir, "openflux_instances")
        os.makedirs(mock_instances_dir, exist_ok=True)

        # Слот 1: mailru (валидный)
        with open(os.path.join(mock_instances_dir, "1.env"), "w", encoding="utf-8") as f:
            f.write('ROLE="exit"\nMODE="l4"\nTRANSPORT="mailru"\nCODEC="legacy"\nURL="https://cloud.mail.ru/public/A/1"\n')

        # Слот 2: boards (валидный)
        with open(os.path.join(mock_instances_dir, "2.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="boards"\nCODEC="batched"\nURL="https://boards.example.com/doc/2"\n')

        # Слот 3: yandex (НЕВАЛИДНЫЙ транспорт в v2 - должен быть пропущен)
        with open(os.path.join(mock_instances_dir, "3.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="yandex"\nURL="https://disk.yandex.ru/i/skipped"\n')

        pool_mode_file = os.path.join(self.test_dir, "pool.mode")
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("classic\n")

        st_imp, _, b_imp = self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_instances_dir,
            "pool_mode_file": pool_mode_file
        })
        self.assertEqual(st_imp, 200)
        res = json.loads(b_imp.decode())
        self.assertTrue(res["success"])
        self.assertEqual(res["imported_count"], 2)

        # Проверяем что в базе появились слоты 1 и 2, а слот 3 пропущен
        slot1_grp = [g for g in res["groups"] if g["slot"] == 1][0]
        st_get1, _, b_g1 = self.api_request("GET", f"/api/openflux/groups/{slot1_grp['id']}")
        self.assertEqual(st_get1, 200)
        self.assertEqual(json.loads(b_g1.decode())["transport"], "mailru")

        slot2_grp = [g for g in res["groups"] if g["slot"] == 2][0]
        st_get2, _, b_g2 = self.api_request("GET", f"/api/openflux/groups/{slot2_grp['id']}")
        self.assertEqual(st_get2, 200)
        self.assertEqual(json.loads(b_g2.decode())["transport"], "boards")

        self.assertFalse(any(g["slot"] == 3 for g in res["groups"]))
        st_get3, _, _ = self.api_request("GET", "/api/openflux/groups/OF-Slot-3")
        self.assertEqual(st_get3, 404)


    # --------------------------------------------------------------------------
    # ТЕСТ 34: Импорт env с четырьмя URL через запятую и сохранение %2C / параметров
    # --------------------------------------------------------------------------
    def test_34_import_env_four_comma_separated_urls_and_percent_preservation(self):
        mock_dir = os.path.join(self.test_dir, "test34_instances")
        os.makedirs(mock_dir, exist_ok=True)
        env_file = os.path.join(mock_dir, "1.env")

        # 4 URL через запятую: query с %2C (запятая закодированная), +, %20, fragment
        url1 = "https://cloud.mail.ru/public/A/1?tag=a%2Cb&val=1+2"
        url2 = "https://cloud.mail.ru/public/A/2?q=foo%20bar"
        url3 = "https://cloud.mail.ru/public/A/3#section1"
        url4 = "https://cloud.mail.ru/public/A/4?x=1&y=2"
        raw_val = f"{url1},{url2},{url3},{url4}"

        with open(env_file, "w", encoding="utf-8") as f:
            f.write(f'TRANSPORT="mailru"\nCODEC="batched"\nPOOL_MODE="multistream"\nURL="{raw_val}"\n')

        pool_mode_file = os.path.join(self.test_dir, "test34_pool.mode")
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("multistream\n")

        st_imp, _, b_imp = self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_dir,
            "pool_mode_file": pool_mode_file
        })
        self.assertEqual(st_imp, 200)
        res = json.loads(b_imp.decode())
        self.assertTrue(res["success"])
        imported = [g for g in res["groups"] if g["slot"] == 1][0]

        # Ровно 4 строки, без разделения по %2C
        self.assertEqual(len(imported["urls"]), 4)
        self.assertEqual(imported["urls"][0], url1)
        self.assertEqual(imported["urls"][1], url2)
        self.assertEqual(imported["urls"][2], url3)
        self.assertEqual(imported["urls"][3], url4)

        # Канонический API отклоняет элемент с буквальной запятой
        st_bad, _, b_bad = self.api_request("POST", "/api/openflux/groups", {
            "name": "Comma-Bad",
            "mode": "multistream",
            "transport": "mailru",
            "urls": [url1, f"{url2},{url3}"]
        })
        self.assertEqual(st_bad, 400)
        self.assertIn("cannot contain literal comma", json.loads(b_bad.decode())["error"])

    # --------------------------------------------------------------------------
    # ТЕСТ 35: Реальный текущий набор VPS (4 группы, 4 документа = 16 документов, batched)
    # --------------------------------------------------------------------------
    def test_35_four_groups_four_docs_batched_real_current_vps_set(self):
        mock_dir = os.path.join(self.test_dir, "test35_instances")
        os.makedirs(mock_dir, exist_ok=True)

        # Слоты 1, 2 (mailru), 3 (boards), 5 (cupsonline)
        slots_data = {
            1: ("mailru", [f"https://cloud.mail.ru/public/slot1/doc{i}" for i in range(1, 5)]),
            2: ("mailru", [f"https://cloud.mail.ru/public/slot2/doc{i}" for i in range(1, 5)]),
            3: ("boards", [f"https://boards.example.com/board/slot3_doc{i}" for i in range(1, 5)]),
            5: ("cupsonline", [f"https://cups.online/live-coding/?room=slot5_doc{i}" for i in range(1, 5)]),
        }

        for slot_num, (tr, u_list) in slots_data.items():
            env_f = os.path.join(mock_dir, f"{slot_num}.env")
            raw_urls = ",".join(u_list)
            with open(env_f, "w", encoding="utf-8") as f:
                f.write(f'ROLE="exit"\nMODE="l4"\nTRANSPORT="{tr}"\nCODEC="batched"\nURL="{raw_urls}"\nENCRYPTION_KEY=""\n')

        pool_mode_file = os.path.join(self.test_dir, "test35_pool.mode")
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("multistream\n")

        st_imp, _, b_imp = self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_dir,
            "pool_mode_file": pool_mode_file
        })
        self.assertEqual(st_imp, 200)
        res = json.loads(b_imp.decode())
        self.assertEqual(res["imported_count"], 4)

        # Создаем пользователя и подключаем 4 группы (multistream, roundRobin)
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": "vps_test_user"})
        user_info = json.loads(b_u.decode())
        u_id = user_info["id"]
        tok = user_info["token"]

        group_ids = [g["id"] for g in res["groups"]]
        st_cfg, _, _ = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "VPS-Multistream-16",
            "mode": "multistream",
            "balancer_strategy": "roundRobin",
            "group_ids": group_ids
        })
        self.assertEqual(st_cfg, 200)

        # Запрашиваем подписку
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        lines = [l.strip() for l in base64.b64decode(b_sub).decode("utf-8").splitlines() if l.strip()]
        of_lines = [l for l in lines if l.startswith("openflux-bundle://v2/")]
        self.assertEqual(len(of_lines), 1)

        ok, err, bundle = deserialize_openflux_v2_bundle(of_lines[0])
        self.assertTrue(ok, f"Bundle deserialization failed: {err}")
        self.assertEqual(bundle["schema"], "tuna.openflux.bundle")
        self.assertEqual(bundle["version"], 2)
        self.assertEqual(bundle["mode"], "multistream")
        self.assertEqual(bundle["balancer_strategy"], "roundRobin")
        self.assertEqual(len(bundle["groups"]), 4)

        lengths = [len(g["urls"]) for g in bundle["groups"]]
        self.assertEqual(lengths, [4, 4, 4, 4])
        total_docs = sum(lengths)
        self.assertEqual(total_docs, 16)

        # Все кодеки batched, все PSK пустые, mode отсутствует в wire-группах
        for g in bundle["groups"]:
            self.assertEqual(g["codec"], "batched")
            self.assertEqual(g["encryption_key"], "")
            self.assertNotIn("mode", g)

    # --------------------------------------------------------------------------
    # ТЕСТ 36: Проволочный контракт v2: отклонение старой schema, group.mode и объединенных URL
    # --------------------------------------------------------------------------
    def test_36_contract_v2_rejection_of_old_schema_group_mode_and_merged_urls(self):
        valid_group = {
            "id": "11111111-2222-3333-4444-555555555555",
            "name": "Valid-Group",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/123/doc1"],
            "codec": "batched",
            "encryption_key": ""
        }
        valid_bundle = {
            "schema": "tuna.openflux.bundle",
            "version": 2,
            "issuer_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "id": "22222222-3333-4444-5555-666666666666",
            "revision": 1,
            "name": "Contract-Check",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [valid_group]
        }

        # 1. Валидный бандл проходит
        ok, err = validate_openflux_v2_payload(valid_bundle)
        self.assertTrue(ok, f"Expected valid, got: {err}")

        # 2. Старая schema ("openflux-bundle") отклоняется
        bad_schema = dict(valid_bundle, schema="openflux-bundle")
        ok_bs, err_bs = validate_openflux_v2_payload(bad_schema)
        self.assertFalse(ok_bs)
        self.assertIn("Invalid schema", err_bs)

        # 3. Наличие mode в группе проволочного формата отклоняется
        grp_with_mode = dict(valid_group, mode="classic")
        bad_grp = dict(valid_bundle, groups=[grp_with_mode])
        ok_bg, err_bg = validate_openflux_v2_payload(bad_grp)
        self.assertFalse(ok_bg)
        self.assertIn("must NOT contain 'mode'", err_bg)

        # 4. Объединенный URL с буквальной запятой отклоняется
        grp_merged = dict(valid_group, urls=["https://cloud.mail.ru/1,https://cloud.mail.ru/2"])
        bad_urls = dict(valid_bundle, groups=[grp_merged])
        ok_bu, err_bu = validate_openflux_v2_payload(bad_urls)
        self.assertFalse(ok_bu)
        self.assertIn("literal comma", err_bu)

        # 5. Неизвестное поле в корне отклоняется
        bad_root = dict(valid_bundle, unknown_key="val")
        ok_br, err_br = validate_openflux_v2_payload(bad_root)
        self.assertFalse(ok_br)
        self.assertIn("Unknown field", err_br)

        # 6. Неканонический UUID отклоняется
        bad_uuid = dict(valid_bundle, id="NOT-A-UUID")
        ok_buu, err_buu = validate_openflux_v2_payload(bad_uuid)
        self.assertFalse(ok_buu)
        self.assertIn("canonical lowercase UUID", err_buu)

        # 7. Десериализация старого URI отклоняется
        old_uri = "openflux-bundle://v2/" + base64.urlsafe_b64encode(json.dumps(bad_schema).encode()).decode().rstrip("=")
        ok_des, err_des, _ = deserialize_openflux_v2_bundle(old_uri)
        self.assertFalse(ok_des)

    # --------------------------------------------------------------------------
    # ТЕСТ 37: Консистентность HTTP-выдачи, API-preview и TUI-preview
    # --------------------------------------------------------------------------
    def test_37_http_issuance_api_preview_tui_preview_consistency(self):
        # Создаем пользователя с OpenFlux
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": "preview_sync_user"})
        user = json.loads(b_u.decode())
        u_id = user["id"]
        tok = user["token"]

        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Sync-Group",
            "mode": "classic",
            "transport": "boards",
            "urls": ["https://boards.example.com/sync_doc"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "Preview-Sync",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "group_ids": [gid]
        })

        # 1. API Preview: GET /api/users/<id>/openflux
        st_api, _, b_api = self.api_request("GET", f"/api/users/{u_id}/openflux")
        self.assertEqual(st_api, 200)
        api_data = json.loads(b_api.decode())
        api_uri = api_data["v2_uri"]
        api_payload = api_data["bundle_payload"]

        # 2. HTTP Issuance: GET /sub/<token>
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        sub_text = base64.b64decode(b_sub).decode("utf-8").strip()
        http_uri = sub_text.splitlines()[-1]

        # URI байт-в-байт идентичен
        self.assertEqual(api_uri, http_uri)

        # 3. TUI Preview декодирует v2_uri
        # Имитируем поведение TUI (чтение base64url из v2_uri)
        raw_b64 = api_uri[len("openflux-bundle://v2/"):]
        padding = "=" * ((4 - len(raw_b64) % 4) % 4)
        tui_payload = json.loads(base64.urlsafe_b64decode(raw_b64 + padding).decode("utf-8"))

        # Все три представления идентичны
        self.assertEqual(api_payload, tui_payload)
        ok, _, deserialized_payload = deserialize_openflux_v2_bundle(http_uri)
        self.assertTrue(ok)
        self.assertEqual(api_payload, deserialized_payload)

    # --------------------------------------------------------------------------
    # ТЕСТ 38: Идемпотентность починки БД и откат (repair & rollback)
    # --------------------------------------------------------------------------
    def test_38_database_repair_and_rollback_idempotence(self):
        # Создаем отдельную тестовую БД для проверки починки
        test_db = os.path.join(self.test_dir, "repair_test.db")
        conn = init_database(test_db)

        # Создаем в repair_test.db некорректную группу с объединенным URL через запятую
        now = "2026-09-25T00:00:00+00:00"
        gid = "a0a0a0a0-bbbb-cccc-dddd-eeeeeeeeeeee"
        uid = "f0f0f0f0-1111-2222-3333-444444444444"
        merged_urls = ["https://cloud.mail.ru/public/1,https://cloud.mail.ru/public/2"]
        with conn:
            conn.execute("INSERT OR REPLACE INTO users (id, nickname, enabled, subscription_token, subscription_token_hash, revision, created_at, updated_at) VALUES (?, 'rep_user', 1, 'rep_tok', 'rep_hash', 5, ?, ?);", (uid, now, now))
            conn.execute("INSERT OR REPLACE INTO openflux_groups (id, name, mode, transport, urls_json, codec, encryption_key, source_slot, created_at, updated_at) VALUES (?, 'Corrupted-Group', 'multistream', 'mailru', ?, 'batched', '', 1, ?, ?);", (gid, json.dumps(merged_urls), now, now))
            conn.execute("INSERT OR REPLACE INTO user_openflux_config (user_id, enabled, connection_id, name, mode, balancer_strategy, revision, updated_at) VALUES (?, 1, 'cccccccc-dddd-eeee-ffff-000000000000', 'Rep-Cfg', 'multistream', 'roundRobin', 5, ?);", (uid, now))
            conn.execute("INSERT OR REPLACE INTO user_openflux_selection (user_id, group_id, position) VALUES (?, ?, 0);", (uid, gid))
        conn.close()

        # 1. Первый запуск repair
        ok1, msg1, res1 = repair_openflux_v2_database(test_db, backup=True)
        self.assertTrue(ok1, msg1)
        self.assertEqual(res1["repaired_groups_count"], 1)
        self.assertEqual(res1["affected_users_count"], 1)
        backup_file = res1["backup"]
        self.assertTrue(os.path.isfile(backup_file))

        # Проверяем что группа исправлена (2 URL) и revision инкрементирован (5 -> 6)
        conn = sqlite3.connect(test_db)
        c = conn.cursor()
        c.execute("SELECT urls_json FROM openflux_groups WHERE id = ?;", (gid,))
        urls_after = json.loads(c.fetchone()[0])
        self.assertEqual(len(urls_after), 2)
        self.assertEqual(urls_after[0], "https://cloud.mail.ru/public/1")
        self.assertEqual(urls_after[1], "https://cloud.mail.ru/public/2")

        c.execute("SELECT revision FROM user_openflux_config WHERE user_id = ?;", (uid,))
        self.assertEqual(c.fetchone()[0], 6)
        conn.close()

        # 2. Второй запуск repair (идемпотентность)
        ok2, msg2, res2 = repair_openflux_v2_database(test_db, backup=False)
        self.assertTrue(ok2, msg2)
        self.assertEqual(res2["repaired_groups_count"], 0)
        self.assertEqual(res2["affected_users_count"], 0)

        # Revision НЕ изменился
        conn = sqlite3.connect(test_db)
        c = conn.cursor()
        c.execute("SELECT revision FROM user_openflux_config WHERE user_id = ?;", (uid,))
        self.assertEqual(c.fetchone()[0], 6)
        conn.close()

        # 3. Откат к бэкапу
        ok_rb, msg_rb = rollback_openflux_v2_database(backup_file, test_db)
        self.assertTrue(ok_rb, msg_rb)

        # Проверяем возврат к 1 неисправленному URL и revision 5
        conn = sqlite3.connect(test_db)
        c = conn.cursor()
        c.execute("SELECT urls_json FROM openflux_groups WHERE id = ?;", (gid,))
        self.assertEqual(len(json.loads(c.fetchone()[0])), 1)
        c.execute("SELECT revision FROM user_openflux_config WHERE user_id = ?;", (uid,))
        self.assertEqual(c.fetchone()[0], 5)
        conn.close()

    # --------------------------------------------------------------------------
    # ТЕСТ 39: Атомарная валидация изменений группы предотвращает частичные поломки
    # --------------------------------------------------------------------------
    def test_39_atomic_prevalidation_prevents_partial_changes(self):
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": "atomic_user"})
        user = json.loads(b_u.decode())
        u_id = user["id"]

        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Atomic-Group",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/atomic1"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "mode": "classic",
            "group_ids": [gid]
        })

        # Попытка обновить группу в classic mode, добавив 2-й URL (недопустимо в classic)
        st_bad, _, b_bad = self.api_request("PUT", f"/api/openflux/groups/{gid}", {
            "urls": ["https://cloud.mail.ru/public/1", "https://cloud.mail.ru/public/2"]
        })
        self.assertEqual(st_bad, 400)
        self.assertIn("Classic mode requires exactly 1 URL", json.loads(b_bad.decode())["error"])

        # Проверяем что группа осталась неизменной
        st_g, _, b_chk = self.api_request("GET", f"/api/openflux/groups/{gid}")
        self.assertEqual(st_g, 200)
        chk = json.loads(b_chk.decode())
        self.assertEqual(chk["urls"], ["https://cloud.mail.ru/public/atomic1"])

    # --------------------------------------------------------------------------
    # ТЕСТ 40: Композитный ключ (source_slot, mode) сохраняет имена и разные режимы
    # --------------------------------------------------------------------------
    def test_40_composite_key_slot_and_mode_preserves_custom_names_and_separate_modes(self):
        mock_dir = os.path.join(self.test_dir, "test40_instances")
        os.makedirs(mock_dir, exist_ok=True)

        # 1. Импортируем слот 4 в classic
        with open(os.path.join(mock_dir, "4.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="mailru"\nURL="https://cloud.mail.ru/slot4_classic"\n')

        pool_mode_file = os.path.join(self.test_dir, "test40_pool.mode")
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("classic\n")

        self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_dir,
            "pool_mode_file": pool_mode_file
        })

        # Находим созданную группу и переименовываем
        st_l, _, b_l = self.api_request("GET", "/api/openflux/groups")
        all_groups = json.loads(b_l.decode())
        g4_classic = [g for g in all_groups if g["source_slot"] == 4 and g["mode"] == "classic"][0]
        g4_id = g4_classic["id"]

        self.api_request("PUT", f"/api/openflux/groups/{g4_id}", {
            "name": "Custom-Name-For-Slot-4"
        })

        # 2. Повторный импорт слота 4 в classic: имя Custom-Name-For-Slot-4 должно сохраниться!
        self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_dir,
            "pool_mode_file": pool_mode_file
        })

        st_get, _, b_get = self.api_request("GET", f"/api/openflux/groups/{g4_id}")
        self.assertEqual(st_get, 200)
        self.assertEqual(json.loads(b_get.decode())["name"], "Custom-Name-For-Slot-4")

        # 3. Теперь импортируем слот 4 в multistream: classic не должен быть затерт!
        with open(os.path.join(mock_dir, "4.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="boards"\nURL="https://boards.example.com/ms1,https://boards.example.com/ms2"\n')
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("multistream\n")

        self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_dir,
            "pool_mode_file": pool_mode_file
        })

        # Проверяем что обе группы существуют одновременно
        st_l2, _, b_l2 = self.api_request("GET", "/api/openflux/groups")
        all_grps2 = json.loads(b_l2.decode())
        classic_matches = [g for g in all_grps2 if g["source_slot"] == 4 and g["mode"] == "classic"]
        ms_matches = [g for g in all_grps2 if g["source_slot"] == 4 and g["mode"] == "multistream"]

        self.assertEqual(len(classic_matches), 1)
        self.assertEqual(classic_matches[0]["name"], "Custom-Name-For-Slot-4")
        self.assertEqual(len(ms_matches), 1)
        self.assertNotEqual(classic_matches[0]["id"], ms_matches[0]["id"])

    # --------------------------------------------------------------------------
    # ТЕСТ 41: Строгие типы, границы размеров, canonical UUID и маскирование логов
    # --------------------------------------------------------------------------
    def test_41_strict_schema_types_limits_and_log_masking(self):
        # 1. Проверка маскирования токена в логах
        token_secret = "SECRET_SUPER_TOKEN_123"
        self.api_request("GET", f"/sub/{token_secret}")
        if os.path.isfile(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                log_content = f.read()
                self.assertNotIn(token_secret, log_content)
                self.assertIn("[REDACTED_TOKEN]", log_content)

        # 2. Имя > 120 символов отклоняется
        st_long_n, _, _ = self.api_request("POST", "/api/openflux/groups", {
            "name": "A" * 121,
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/1"]
        })
        self.assertEqual(st_long_n, 400)

        # 3. URL > 8192 байт отклоняется
        st_long_u, _, _ = self.api_request("POST", "/api/openflux/groups", {
            "name": "Long-URL",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/" + ("x" * 8200)]
        })
        self.assertEqual(st_long_u, 400)

        # 4. Canonical UUID проверка
        self.assertTrue(is_canonical_uuid("00000000-0000-0000-0000-000000000000"))
        self.assertFalse(is_canonical_uuid("00000000-0000-0000-0000-00000000000A")) # Uppercase
        self.assertFalse(is_canonical_uuid("not-a-uuid"))

    # --------------------------------------------------------------------------
    # ТЕСТ 42: WebDAV - ядро сериализации, парсинга, валидации и контракта TUNA rc9
    # --------------------------------------------------------------------------
    def test_42_webdav_core_serialization_and_parsing(self):
        # 1. Основной backend без дополнительных (0 бэкендов)
        c0 = {
            "name": "Single-Dav",
            "url": "https://webdav.cloud.mail.ru/",
            "username": "mail_user",
            "password": "mail_password",
            "backends": [],
            "timeout": "45s",
            "poll_min": "100ms",
            "poll_max": "300ms",
            "coalesce": "10ms",
            "chunk_size": 65536,
            "puts": 4,
            "read_min": 2,
            "read_max": 6,
            "enc": 0,
            "dns": ""
        }
        ok, err, uri0 = serialize_webdav_uri(c0)
        self.assertTrue(ok, err)
        self.assertTrue(uri0.startswith("webdavs://mail_user:mail_password@webdav.cloud.mail.ru/"))
        self.assertIn("#Single-Dav", uri0)
        self.assertNotIn("enc=", uri0) # enc=0 опускается
        self.assertNotIn("backend=", uri0)

        # 2. Ровно 1 дополнительный бэкенд и 8 дополнительных бэкендов (максимум)
        c1 = dict(c0)
        c1["backends"] = [{"url": "http://192.0.2.1:8080/storage/", "username": "u1", "password": "p1"}]
        ok, err, uri1 = serialize_webdav_uri(c1)
        self.assertTrue(ok, err)
        self.assertIn("backend=webdav%3A%2F%2Fu1%3Ap1%40192.0.2.1%3A8080%2Fstorage%2F", uri1)

        c8 = dict(c0)
        c8["backends"] = [
            {"url": f"https://s{i}.example.com/dav/", "username": f"u{i}", "password": f"p{i}"}
            for i in range(1, 9)
        ]
        ok, err, uri8 = serialize_webdav_uri(c8)
        self.assertTrue(ok, err)
        self.assertEqual(uri8.count("backend="), 8)

        # 3. 9 дополнительных бэкендов отклоняются
        c9 = dict(c0)
        c9["backends"] = [
            {"url": f"https://s{i}.example.com/dav/", "username": f"u{i}", "password": f"p{i}"}
            for i in range(1, 10)
        ]
        ok, err, _ = serialize_webdav_uri(c9)
        self.assertFalse(ok)
        self.assertIn("Too many backends", err)

        # 4. HTTP vs HTTPS, нестандартный порт 8443, IPv6, путь, кириллица
        c_ipv6 = {
            "name": "Мой Сервер 2026",
            "url": "http://[::1]:8443/custom/path/",
            "username": "user",
            "password": "pass",
            "backends": [],
            "enc": 1,
            "dns": "tcp://[2001:4860:4860::8888]:853"
        }
        ok, err, uri_ipv6 = serialize_webdav_uri(c_ipv6)
        self.assertTrue(ok, err)
        self.assertTrue(uri_ipv6.startswith("webdav://user:pass@[::1]:8443/custom/path/"))
        self.assertIn("enc=1", uri_ipv6)
        self.assertIn("dns=tcp%3A%2F%2F%5B2001%3A4860%3A4860%3A%3A8888%5D%3A853", uri_ipv6)
        self.assertTrue(uri_ipv6.endswith("#%D0%9C%D0%BE%D0%B9%20%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80%202026"))

        # 5. Специальные символы в логинах и паролях: : @ + & % ? # /
        complex_spec = {
            "name": "Complex-Chars",
            "url": "https://storage.corp.com:9443/dav/",
            "username": "user:admin@corp+dept&co%3F#/",
            "password": "p:a@s+s&w%o?r#d/123!",
            "backends": [
                {
                    "url": "http://backup.local/dav/",
                    "username": "b:u@s+e&r",
                    "password": "b:p@a+s&s"
                }
            ],
            "timeout": "60s"
        }
        ok, err, uri_complex = serialize_webdav_uri(complex_spec)
        self.assertTrue(ok, err)
        # Обратный парсинг должен восстановить исходные символы 1 в 1
        ok_p, err_p, parsed_complex = parse_webdav_uri(uri_complex)
        self.assertTrue(ok_p, err_p)
        self.assertEqual(parsed_complex["username"], complex_spec["username"])
        self.assertEqual(parsed_complex["password"], complex_spec["password"])
        self.assertEqual(parsed_complex["backends"][0]["username"], "b:u@s+e&r")
        self.assertEqual(parsed_complex["backends"][0]["password"], "b:p@a+s&s")

        # 6. Отклонение дубликатов одиночных ключей и неизвестных параметров
        dup_uri = "webdav://u:p@127.0.0.1:8443/?timeout=10s&timeout=20s#Test"
        ok_d, err_d, _ = parse_webdav_uri(dup_uri)
        self.assertFalse(ok_d)
        self.assertIn("Duplicate", err_d)

        unknown_uri = "webdav://u:p@127.0.0.1:8443/?foo=bar#Test"
        ok_u, err_u, _ = parse_webdav_uri(unknown_uri)
        self.assertFalse(ok_u)
        self.assertIn("Unknown query parameter", err_u)

        # 7. Отклонение пустых credentials
        empty_cred = {
            "name": "Empty-Cred",
            "url": "http://127.0.0.1:8443/",
            "username": "",
            "password": "p"
        }
        ok_ec, err_ec, _ = serialize_webdav_uri(empty_cred)
        self.assertFalse(ok_ec)
        self.assertIn("cannot be empty", err_ec)

        # 8. Отклонение недопустимого диапазона тюнинга
        bad_tuning = dict(c0)
        bad_tuning["poll_min"] = "500ms"
        bad_tuning["poll_max"] = "200ms" # poll_max < poll_min
        ok_bt, err_bt, _ = serialize_webdav_uri(bad_tuning)
        self.assertFalse(ok_bt)
        self.assertIn("poll-max", err_bt)

    # --------------------------------------------------------------------------
    # ТЕСТ 43: WebDAV API - управление каталогом, CRUD, маскирование секретов и импорт
    # --------------------------------------------------------------------------
    def test_43_webdav_api_catalog_crud_and_secrets(self):
        # 1. Создание подключения в каталоге
        conn_payload = {
            "name": "Catalog-Conn-1",
            "url": "https://webdav.yandex.ru/",
            "username": "yandex_test",
            "password": "secret_yandex_password_999",
            "backends": [
                {
                    "url": "http://backup.local:8080/storage/",
                    "username": "b_user",
                    "password": "b_secret_pass",
                    "label": "Local Backup"
                }
            ],
            "timeout": "30s",
            "enc": 1
        }
        st, _, b = self.api_request("POST", "/api/webdav/connections", conn_payload)
        self.assertEqual(st, 201)
        created = json.loads(b.decode())
        conn_id = created["id"]
        self.assertEqual(created["name"], "Catalog-Conn-1")
        self.assertTrue(created["uri"].startswith("webdavs://"))

        # 2. Получение списка: по умолчанию пароли маскируются звездочками
        st, _, b = self.api_request("GET", "/api/webdav/connections")
        self.assertEqual(st, 200)
        conns = json.loads(b.decode())
        target = next((c for c in conns if c["id"] == conn_id), None)
        self.assertIsNotNone(target)
        self.assertNotIn("secret_yandex_password_999", target["password"])
        self.assertIn("*", target["password"])
        self.assertNotIn("b_secret_pass", target["backends"][0]["password"])

        # 3. Получение списка с ?secrets=1: пароли выдаются открытыми
        st, _, b = self.api_request("GET", "/api/webdav/connections?secrets=1")
        self.assertEqual(st, 200)
        conns_sec = json.loads(b.decode())
        target_sec = next((c for c in conns_sec if c["id"] == conn_id), None)
        self.assertEqual(target_sec["password"], "secret_yandex_password_999")
        self.assertEqual(target_sec["backends"][0]["password"], "b_secret_pass")

        # 4. Обновление подключения: сохранение пароля при маскированном/пропущенном значении
        update_payload = {
            "name": "Catalog-Conn-1-Renamed",
            "timeout": "50s"
        }
        st, _, b = self.api_request("PUT", f"/api/webdav/connections/{conn_id}", update_payload)
        self.assertEqual(st, 200)
        upd = json.loads(b.decode())
        self.assertEqual(upd["name"], "Catalog-Conn-1-Renamed")
        self.assertEqual(upd["timeout"], "50s")

        # Проверяем, что пароль не был затерт
        st, _, b = self.api_request("GET", f"/api/webdav/connections/{conn_id}?secrets=1")
        self.assertEqual(st, 200)
        target_upd = json.loads(b.decode())
        self.assertEqual(target_upd["password"], "secret_yandex_password_999")

        # 5. Импорт из URI (предпросмотр vs сохранение)
        raw_import_uri = (
            "webdav://imp_user:imp_pass@192.0.2.55:8443/dav/?"
            "timeout=25s&poll-min=150ms&poll-max=400ms&coalesce=15ms&chunk-size=65536&puts=6&read-min=2&read-max=6&enc=1"
            "&backend=webdavs%3A%2F%2Fextra_u%3Aextra_p%40s2.example.com%2Fdav%2F#Imported-Dav"
        )
        # 5a. Только предпросмотр (save=false)
        st, _, b = self.api_request("POST", "/api/webdav/import-uri", {"uri": raw_import_uri, "save": False})
        self.assertEqual(st, 200)
        prev_data = json.loads(b.decode())
        self.assertTrue(prev_data["success"])
        self.assertEqual(prev_data["connection"]["name"], "Imported-Dav")
        self.assertEqual(prev_data["connection"]["username"], "imp_user")
        self.assertEqual(prev_data["connection"]["password"], "imp_pass")
        self.assertEqual(len(prev_data["connection"]["backends"]), 1)

        # 5b. Сохранение (save=true)
        st, _, b = self.api_request("POST", "/api/webdav/import-uri", {"uri": raw_import_uri, "save": True})
        self.assertEqual(st, 201)
        saved_import = json.loads(b.decode())
        self.assertEqual(saved_import["name"], "Imported-Dav")

        # 6. Удаление подключения
        st, _, _ = self.api_request("DELETE", f"/api/webdav/connections/{saved_import['id']}")
        self.assertEqual(st, 200)
        st_get_del, _, _ = self.api_request("GET", f"/api/webdav/connections/{saved_import['id']}")
        self.assertEqual(st_get_del, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 44: WebDAV - привязка к пользователям, изоляция, порядок и предпросмотр
    # --------------------------------------------------------------------------
    def test_44_webdav_user_assignment_selection_and_preview(self):
        # 1. Создаем двух пользователей: wd_alice и wd_bob
        self.api_request("POST", "/api/users", {"nickname": "wd_alice"})
        self.api_request("POST", "/api/users", {"nickname": "wd_bob"})

        # 2. Создаем два подключения в каталоге
        st_c1, _, b_c1 = self.api_request("POST", "/api/webdav/connections", {
            "name": "Pool-Conn-Alpha",
            "url": "http://10.0.0.1:8443/dav/",
            "username": "user_a",
            "password": "pass_a",
            "backends": []
        })
        c_alpha_id = json.loads(b_c1.decode())["id"]

        st_c2, _, b_c2 = self.api_request("POST", "/api/webdav/connections", {
            "name": "Pool-Conn-Beta",
            "url": "https://10.0.0.2:8443/dav/",
            "username": "user_b",
            "password": "pass_b",
            "backends": []
        })
        c_beta_id = json.loads(b_c2.decode())["id"]

        # 3. Назначаем wd_alice: Alpha затем Beta
        st, _, b = self.api_request("PUT", "/api/users/wd_alice/webdav", {
            "enabled": True,
            "connection_ids": [c_alpha_id, c_beta_id]
        })
        self.assertEqual(st, 200)
        alice_cfg = json.loads(b.decode())
        self.assertEqual(len(alice_cfg["connections"]), 2)
        self.assertEqual(alice_cfg["connections"][0]["id"], c_alpha_id)
        self.assertEqual(alice_cfg["connections"][1]["id"], c_beta_id)

        # 4. Назначаем wd_bob: только Beta
        st, _, b = self.api_request("PUT", "/api/users/wd_bob/webdav", {
            "enabled": True,
            "connection_ids": [c_beta_id]
        })
        self.assertEqual(st, 200)
        bob_cfg = json.loads(b.decode())
        self.assertEqual(len(bob_cfg["connections"]), 1)
        self.assertEqual(bob_cfg["connections"][0]["id"], c_beta_id)

        # 5. Предпросмотр выдачи для wd_alice: 2 URI в строгом порядке
        st, _, b = self.api_request("GET", "/api/users/wd_alice/webdav/preview")
        self.assertEqual(st, 200)
        alice_prev = json.loads(b.decode())
        self.assertTrue(alice_prev["enabled"])
        self.assertEqual(alice_prev["count"], 2)
        self.assertIn("#Pool-Conn-Alpha", alice_prev["uris"][0])
        self.assertIn("#Pool-Conn-Beta", alice_prev["uris"][1])

        # 6. Предпросмотр выдачи для wd_bob: 1 URI
        st, _, b = self.api_request("GET", "/api/users/wd_bob/webdav/preview")
        self.assertEqual(st, 200)
        bob_prev = json.loads(b.decode())
        self.assertEqual(bob_prev["count"], 1)
        self.assertIn("#Pool-Conn-Beta", bob_prev["uris"][0])

        # 7. Изменение порядка для wd_alice: Beta затем Alpha
        self.api_request("PUT", "/api/users/wd_alice/webdav", {
            "enabled": True,
            "connection_ids": [c_beta_id, c_alpha_id]
        })
        st, _, b = self.api_request("GET", "/api/users/wd_alice/webdav/preview")
        alice_prev_reorder = json.loads(b.decode())
        self.assertIn("#Pool-Conn-Beta", alice_prev_reorder["uris"][0])
        self.assertIn("#Pool-Conn-Alpha", alice_prev_reorder["uris"][1])

        # wd_bob остался без изменений
        st, _, b = self.api_request("GET", "/api/users/wd_bob/webdav/preview")
        self.assertEqual(json.loads(b.decode())["count"], 1)

    # --------------------------------------------------------------------------
    # ТЕСТ 45: WebDAV в подписке - Base64 декодирование, ETag, 304 и лимит 2 MiB
    # --------------------------------------------------------------------------
    def test_45_webdav_subscription_emission_etag_and_limits(self):
        # 1. Получаем токен wd_alice
        st, _, b = self.api_request("GET", "/api/users/wd_alice")
        alice_info = json.loads(b.decode())
        token = alice_info["token"]

        # 2. Запрос подписки
        st, hdrs, body = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(st, 200)
        etag1 = hdrs.get("ETag") or hdrs.get("etag")
        self.assertIsNotNone(etag1)

        # Декодируем Base64 и проверяем наличие WebDAV строк
        lines = [line.strip() for line in base64.b64decode(body).decode("utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("webdavs://"))
        self.assertTrue(lines[1].startswith("webdav://"))

        # 3. Повторный запрос с If-None-Match возвращает 304 Not Modified
        st_304, _, _ = self.api_request("GET", f"/sub/{token}", headers={"If-None-Match": etag1})
        self.assertEqual(st_304, 304)

        # 4. Обновляем подключение в каталоге: меняем таймаут и проверяем смену ETag (не должно быть старого 304)
        c_cursor = self.app.conn.cursor()
        c_cursor.execute("SELECT id FROM webdav_connections WHERE name = 'Pool-Conn-Beta';")
        beta_id = c_cursor.fetchone()[0]

        self.api_request("PUT", f"/api/webdav/connections/{beta_id}", {
            "timeout": "42s"
        })

        st_new, hdrs_new, body_new = self.api_request("GET", f"/sub/{token}", headers={"If-None-Match": etag1})
        self.assertEqual(st_new, 200) # Не 304!
        etag2 = hdrs_new.get("ETag") or hdrs_new.get("etag")
        self.assertNotEqual(etag1, etag2)
        self.assertIn("timeout=42s", base64.b64decode(body_new).decode("utf-8"))

        # 5. Отключение WebDAV у пользователя: подписка становится пустой (204 No Content)
        self.api_request("PUT", "/api/users/wd_alice/webdav", {"enabled": False})
        st_no_c, _, _ = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(st_no_c, 204)

        # Включаем обратно
        self.api_request("PUT", "/api/users/wd_alice/webdav", {"enabled": True})

    # --------------------------------------------------------------------------
    # ТЕСТ 46: Миграция и откат базы данных (repair_webdav.py)
    # --------------------------------------------------------------------------
    def test_46_webdav_migration_and_rollback(self):
        self.app.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        copy_db = os.path.join(self.test_dir, "mig_test.db")
        shutil.copy2(self.db_path, copy_db)

        # 1. Dry-run миграции
        ok, msg, rep = migrate_webdav_database(copy_db, dry_run=True, backup=False)
        self.assertTrue(ok, msg)
        self.assertTrue(rep["dry_run"])

        # 2. Применение миграции
        ok_app, msg_app, rep_app = migrate_webdav_database(copy_db, dry_run=False, backup=True)
        self.assertTrue(ok_app, msg_app)
        self.assertIsNotNone(rep_app["backup_file"])
        self.assertTrue(os.path.isfile(rep_app["backup_file"]))

        # 3. Идемпотентность: повторный запуск
        ok_idem, msg_idem, rep_idem = migrate_webdav_database(copy_db, dry_run=False, backup=False)
        self.assertTrue(ok_idem, msg_idem)
        self.assertEqual(rep_idem["tables_created"], [])

        # 4. Откат из созданного бэкапа
        ok_rb, msg_rb = rollback_webdav_database(rep_app["backup_file"], copy_db)
        self.assertTrue(ok_rb, msg_rb)

    # --------------------------------------------------------------------------
    # ТЕСТ 47: Регрессия всех существующих протоколов, OpenFlux v2 и WebDAV
    # --------------------------------------------------------------------------
    def test_47_regression_existing_protocols_and_openflux_v2(self):
        # 1. Создаем пользователя со всеми протоколами
        user_data = {
            "nickname": "wd_omni_user",
            "snell": "snell://192.0.2.1:10001?psk=test_psk&obfs=http",
            "mieru": "mieru://192.0.2.2:10002?username=m_user&password=m_pass",
            "custom": "custom://test-custom-link"
        }
        st, _, b = self.api_request("POST", "/api/users", user_data)
        self.assertEqual(st, 201)
        omni = json.loads(b.decode())
        u_token = omni["token"]
        u_id = omni["id"]

        # 2. Создаем OpenFlux группу и включаем для пользователя
        st_of, _, b_of = self.api_request("POST", "/api/openflux/groups", {
            "name": "Omni-OF-Group",
            "transport": "mailru",
            "mode": "multistream",
            "codec": "batched",
            "urls": ["https://cloud.mail.ru/public/omni1"]
        })
        self.assertEqual(st_of, 201)
        of_id = json.loads(b_of.decode())["id"]

        st_put_of, _, b_put_of = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "mode": "multistream",
            "group_ids": [of_id]
        })
        self.assertEqual(st_put_of, 200)

        # 3. Создаем WebDAV подключение и включаем для пользователя
        st_wd, _, b_wd = self.api_request("POST", "/api/webdav/connections", {
            "name": "Omni-WD-Conn",
            "url": "https://webdav.cloud.mail.ru/",
            "username": "omni_user",
            "password": "omni_password",
            "backends": []
        })
        self.assertEqual(st_wd, 201)
        wd_id = json.loads(b_wd.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/webdav", {
            "enabled": True,
            "connection_ids": [wd_id]
        })

        # 4. Проверяем GET /api/users/<id>
        st_u, _, b_u = self.api_request("GET", f"/api/users/{u_id}")
        self.assertEqual(st_u, 200)
        u_info = json.loads(b_u.decode())
        self.assertTrue(u_info["openflux_enabled"])
        self.assertEqual(u_info["openflux_groups_count"], 1)
        self.assertTrue(u_info["webdav_enabled"])
        self.assertEqual(u_info["webdav_connections_count"], 1)
        # Snell (1) + Mieru (1) + Custom (1) + OpenFlux (1) + WebDAV (1) = 5
        self.assertEqual(u_info["total_uris"], 5)

        # 5. Проверяем выдачу подписки: порядок Snell -> Mieru -> Custom -> OpenFlux -> WebDAV
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{u_token}")
        self.assertEqual(st_sub, 200)
        emitted_lines = [l.strip() for l in base64.b64decode(b_sub).decode("utf-8").splitlines() if l.strip()]
        self.assertEqual(len(emitted_lines), 5)
        self.assertTrue(emitted_lines[0].startswith("snell://"))
        self.assertTrue(emitted_lines[1].startswith("mieru://"))
        self.assertTrue(emitted_lines[2].startswith("custom://"))
        self.assertTrue(emitted_lines[3].startswith("openflux-bundle://v2/"))
        self.assertTrue(emitted_lines[4].startswith("webdavs://"))


if __name__ == "__main__":
    unittest.main()
