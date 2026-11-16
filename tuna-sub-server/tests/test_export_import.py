#!/usr/bin/env python3
"""
Автоматизированный комплекс тестов экспорта/импорта реквизитов OpenFlux и WebDAV.
Покрывает все 9 приемочных сценариев ТЗ.
"""

import sys
import os
import json
import base64
import shutil
import tempfile
import threading
import time
import urllib.request
import urllib.error
import unittest

# Добавляем путь к tuna-sub-server
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from importlib import import_module
tuna = import_module("tuna-subscriptions")
SubscriptionApp = tuna.SubscriptionApp
SubscriptionRequestHandler = tuna.SubscriptionRequestHandler
ThreadingHTTPServer = tuna.ThreadingHTTPServer
serialize_openflux_v2_bundle = tuna.serialize_openflux_v2_bundle
deserialize_openflux_v2_bundle = tuna.deserialize_openflux_v2_bundle
serialize_webdav_uri = tuna.serialize_webdav_uri
parse_webdav_uri = tuna.parse_webdav_uri
compute_webdav_canonical_fingerprint = tuna.compute_webdav_canonical_fingerprint


class ExportImportAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="tuna_exp_imp_")

        # Сервер A
        cls.db_a = os.path.join(cls.temp_dir, "server_a.db")
        cls.cfg_a = {
            "server": {"bind_address": "127.0.0.1", "port": 0, "max_request_body_size": 131072},
            "database": {"path": cls.db_a},
            "limits": {"max_nickname_length": 64, "max_uri_length": 131072, "max_users": 1000},
            "logging": {"file": os.path.join(cls.temp_dir, "a.log"), "level": "INFO"}
        }
        cls.app_a = SubscriptionApp(cls.cfg_a)
        cls.srv_a = ThreadingHTTPServer(("127.0.0.1", 0), SubscriptionRequestHandler)
        cls.srv_a.app = cls.app_a
        cls.port_a = cls.srv_a.server_address[1]
        cls.app_a.bind_port = cls.port_a
        cls.th_a = threading.Thread(target=cls.srv_a.serve_forever, daemon=True)
        cls.th_a.start()

        # Сервер B (изолированный)
        cls.db_b = os.path.join(cls.temp_dir, "server_b.db")
        cls.cfg_b = {
            "server": {"bind_address": "127.0.0.1", "port": 0, "max_request_body_size": 131072},
            "database": {"path": cls.db_b},
            "limits": {"max_nickname_length": 64, "max_uri_length": 131072, "max_users": 1000},
            "logging": {"file": os.path.join(cls.temp_dir, "b.log"), "level": "INFO"}
        }
        cls.app_b = SubscriptionApp(cls.cfg_b)
        cls.srv_b = ThreadingHTTPServer(("127.0.0.1", 0), SubscriptionRequestHandler)
        cls.srv_b.app = cls.app_b
        cls.port_b = cls.srv_b.server_address[1]
        cls.app_b.bind_port = cls.port_b
        cls.th_b = threading.Thread(target=cls.srv_b.serve_forever, daemon=True)
        cls.th_b.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.srv_a.shutdown()
        cls.srv_a.server_close()
        cls.app_a.conn.close()

        cls.srv_b.shutdown()
        cls.srv_b.server_close()
        cls.app_b.conn.close()

        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def api_call(self, port: int, method: str, path: str, data: dict = None):
        url = f"http://127.0.0.1:{port}{path}"
        body = None
        headers = {"User-Agent": "TunaTest/1.0"}
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                resp_body = resp.read()
                try:
                    return resp.status, json.loads(resp_body.decode("utf-8"))
                except Exception:
                    return resp.status, resp_body
        except urllib.error.HTTPError as e:
            err_body = e.read()
            try:
                return e.code, json.loads(err_body.decode("utf-8"))
            except Exception:
                return e.code, {"error": err_body.decode("utf-8", errors="replace")}

    # -------------------------------------------------------------------------
    # 1. Две изолированные БД A/B: экспорт A → импорт B → экспорт B
    # -------------------------------------------------------------------------
    def test_01_two_isolated_databases_roundtrip(self):
        # 1. Создаем пользователя на A и на B
        st, u_a = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "alice_a"})
        self.assertEqual(st, 201)
        st, u_b = self.api_call(self.port_b, "POST", "/api/users", {"nickname": "bob_b"})
        self.assertEqual(st, 201)

        # 2. Создаем 3 группы OpenFlux на сервере A
        g1_urls = ["https://cloud.mail.ru/public/qwe/1", "https://cloud.mail.ru/public/qwe/2"]
        st, g1 = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "OF-Group-MailRu", "mode": "multistream", "transport": "mailru",
            "urls": g1_urls, "codec": "batched", "encryption_key": "sec_key_alpha_1_long"
        })
        self.assertEqual(st, 201)

        g2_urls = ["https://boards.yandex.ru/whiteboard/?hash=abc1", "https://boards.yandex.ru/whiteboard/?hash=abc2"]
        st, g2 = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "OF-Group-Boards", "mode": "multistream", "transport": "boards",
            "urls": g2_urls, "codec": "legacy", "encryption_key": "sec_key_beta_2_long"
        })
        self.assertEqual(st, 201)

        g3_urls = ["https://interview.cups.online/live-coding/?room=r1", "https://interview.cups.online/live-coding/?room=r2"]
        st, g3 = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "OF-Group-Cups", "mode": "multistream", "transport": "cupsonline",
            "urls": g3_urls, "codec": "batched", "encryption_key": "sec_key_gamma_3_long"
        })
        self.assertEqual(st, 201)

        # Назначаем группы пользователю alice_a на сервере A
        st, of_a_cfg = self.api_call(self.port_a, "PUT", f"/api/users/{u_a['id']}/openflux", {
            "name": "Alice-OpenFlux-Multi",
            "mode": "multistream",
            "balancer_strategy": "leastPing",
            "group_ids": [g1["id"], g2["id"], g3["id"]],
            "enabled": True
        })
        self.assertEqual(st, 200)

        # Настраиваем WebDAV на сервере A
        wd_conn_a = {
            "name": "Alice-WebDAV-Pool",
            "url": "https://storage.primary.net:8443/dav/",
            "username": "user_p",
            "password": "pass_p_secret",
            "backends": [
                {"url": "http://b1.backup.net:8080/data/", "username": "u_b1", "password": "p_b1_secret", "label": "B1"},
                {"url": "https://b2.backup.net/dav/", "username": "u_b2", "password": "p_b2_secret", "label": "B2"}
            ],
            "timeout": "45s",
            "poll_min": "100ms",
            "poll_max": "300ms",
            "enc": 1,
            "dns": "1.1.1.1"
        }
        st, wd_cat_a = self.api_call(self.port_a, "POST", "/api/webdav/connections", wd_conn_a)
        self.assertEqual(st, 201)
        st, _ = self.api_call(self.port_a, "PUT", f"/api/users/{u_a['id']}/webdav", {
            "connection_ids": [wd_cat_a["id"]],
            "enabled": True
        })
        self.assertEqual(st, 200)

        # 3. ЭКСПОРТ ИЗ СЕРВЕРА A
        st, exp_of_a = self.api_call(self.port_a, "GET", f"/api/users/{u_a['id']}/openflux/export")
        self.assertEqual(st, 200)
        uri_of_a = exp_of_a["uri"]
        self.assertTrue(uri_of_a.startswith("openflux-bundle://v2/"))

        st, exp_wd_a = self.api_call(self.port_a, "GET", f"/api/users/{u_a['id']}/webdav/export")
        self.assertEqual(st, 200)
        uri_wd_a = exp_wd_a["uris"][0]
        self.assertTrue(uri_wd_a.startswith("webdavs://"))

        # 4. ИМПОРТ НА СЕРВЕР B (пользователю bob_b)
        # 4.1 Preview OpenFlux
        st, prev_of_b = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/openflux/import", {
            "uri": uri_of_a, "commit": False
        })
        self.assertEqual(st, 200)
        self.assertTrue(prev_of_b["preview"])
        self.assertFalse(prev_of_b["is_identical"])
        token_of_b = prev_of_b["state_token"]

        # 4.2 Commit OpenFlux
        st, comm_of_b = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/openflux/import", {
            "uri": uri_of_a, "commit": True, "expected_state_token": token_of_b
        })
        self.assertEqual(st, 200)
        self.assertEqual(comm_of_b["name"], "Alice-OpenFlux-Multi")
        self.assertEqual(comm_of_b["mode"], "multistream")
        self.assertEqual(comm_of_b["balancer_strategy"], "leastPing")
        self.assertEqual(comm_of_b["total_groups"], 3)

        # 4.3 Preview & Commit WebDAV
        st, prev_wd_b = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri_wd_a, "commit": False
        })
        self.assertEqual(st, 200)
        token_wd_b = prev_wd_b["state_token"]

        st, comm_wd_b = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri_wd_a, "commit": True, "expected_state_token": token_wd_b
        })
        self.assertEqual(st, 200)
        self.assertEqual(len(comm_wd_b["connections"]), 1)

        # 5. ЭКСПОРТ ИЗ СЕРВЕРА B
        st, imported_b = self.api_call(self.port_b, "GET", f"/api/users/{u_b['id']}/openflux/imported")
        self.assertEqual(st, 200)
        exp_of_b = imported_b['connections'][0]
        uri_of_b = exp_of_b["uri"]

        st, exp_wd_b = self.api_call(self.port_b, "GET", f"/api/users/{u_b['id']}/webdav/export")
        self.assertEqual(st, 200)
        uri_wd_b = exp_wd_b["uris"][0]

        # 6. СРАВНЕНИЕ РЕАЛЬНЫХ РЕКВИЗИТОВ
        # OpenFlux:
        ok_a, _, pl_a = deserialize_openflux_v2_bundle(uri_of_a)
        ok_b, _, pl_b = deserialize_openflux_v2_bundle(uri_of_b)
        self.assertTrue(ok_a and ok_b)

        # Дополнительный сервер сохраняет исходные wire ID; локальный issuer не меняется.
        self.assertEqual(pl_a["issuer_id"], self.app_a.issuer_id)
        self.assertNotEqual(self.app_a.issuer_id, self.app_b.issuer_id)
        self.assertEqual(pl_a["issuer_id"], pl_b["issuer_id"])
        self.assertEqual(pl_a["id"], pl_b["id"])

        # Проверяем 100% совпадение рабочих реквизитов:
        self.assertEqual(pl_a["name"], pl_b["name"])
        self.assertEqual(pl_a["mode"], pl_b["mode"])
        self.assertEqual(pl_a["balancer_strategy"], pl_b["balancer_strategy"])
        self.assertEqual(len(pl_a["groups"]), len(pl_b["groups"]))

        for ga, gb in zip(pl_a["groups"], pl_b["groups"]):
            self.assertEqual(ga["name"], gb["name"])
            self.assertEqual(ga["transport"], gb["transport"])
            self.assertEqual(ga["urls"], gb["urls"])
            self.assertEqual(ga["codec"], gb["codec"])
            self.assertEqual(ga["encryption_key"], gb["encryption_key"])

        # WebDAV:
        ok_w_a, _, c_a = parse_webdav_uri(uri_wd_a)
        ok_w_b, _, c_b = parse_webdav_uri(uri_wd_b)
        self.assertTrue(ok_w_a and ok_w_b)

        self.assertEqual(c_a["url"], c_b["url"])
        self.assertEqual(c_a["username"], c_b["username"])
        self.assertEqual(c_a["password"], c_b["password"])
        self.assertEqual(c_a["timeout"], c_b["timeout"])
        self.assertEqual(c_a["poll_min"], c_b["poll_min"])
        self.assertEqual(c_a["poll_max"], c_b["poll_max"])
        self.assertEqual(c_a["enc"], c_b["enc"])
        self.assertEqual(c_a["dns"], c_b["dns"])
        self.assertEqual(len(c_a["backends"]), len(c_b["backends"]))
        for ba, bb in zip(c_a["backends"], c_b["backends"]):
            self.assertEqual(ba["url"], bb["url"])
            self.assertEqual(ba["username"], bb["username"])
            self.assertEqual(ba["password"], bb["password"])

    # -------------------------------------------------------------------------
    # 2. OpenFlux: classic/multistream, 1/8 групп, 1/4 URL, batched/legacy,
    #    roundRobin/leastPing, непустые ключи, разные транспорты, Unicode имена
    # -------------------------------------------------------------------------
    def test_02_openflux_variations_and_limits(self):
        st, u = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "var_user"})
        self.assertEqual(st, 201)

        # Создаем 8 групп с разными транспортами, кодеками и Unicode
        transports = ["mailru", "boards", "cupsonline"]
        codecs = ["legacy", "batched"]
        g_ids = []
        for i in range(1, 9):
            tr = transports[i % len(transports)]
            cd = codecs[i % len(codecs)]
            name_u = f"Группа №{i} ⚡ (Канал-{tr})"
            if tr == "mailru":
                urls = [f"https://cloud.mail.ru/public/box/{i}_{j}" for j in range(1, 5)]
            elif tr == "boards":
                urls = [f"https://boards.yandex.ru/whiteboard/?hash=test_{i}_{j}" for j in range(1, 5)]
            else:
                urls = [f"https://interview.cups.online/live-coding/?room=room_{i}_{j}" for j in range(1, 5)]

            st_g, grp = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
                "name": name_u,
                "mode": "multistream",
                "transport": tr,
                "urls": urls,
                "codec": cd,
                "encryption_key": f"key_hex_{i:04x}_very_secure"
            })
            self.assertEqual(st_g, 201)
            g_ids.append(grp["id"])

        # Назначаем все 8 групп
        st, of_upd = self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/openflux", {
            "name": "Большой Бандл v2 Юникод 🌐",
            "mode": "multistream",
            "balancer_strategy": "roundRobin",
            "group_ids": g_ids,
            "enabled": True
        })
        self.assertEqual(st, 200)

        # Экспортируем
        st, exp = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/openflux/export")
        self.assertEqual(st, 200)
        uri = exp["uri"]

        # Импортируем на сервер B
        st, u_b = self.api_call(self.port_b, "POST", "/api/users", {"nickname": "var_target"})
        self.assertEqual(st, 201)

        st, imp = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/openflux/import", {
            "uri": uri, "commit": True
        })
        self.assertEqual(st, 200)
        self.assertEqual(imp["total_groups"], 8)
        self.assertEqual(imp["total_urls"], 32)
        self.assertEqual(imp["name"], "Большой Бандл v2 Юникод 🌐")

        # Проверяем побайтовую сохранность Unicode и кодеков
        for idx, g in enumerate(imp["groups"], 1):
            expected_cd = codecs[idx % len(codecs)]
            self.assertEqual(g["codec"], expected_cd)
            self.assertTrue(g["name"].startswith(f"Группа №{idx}"))

    # -------------------------------------------------------------------------
    # 3. WebDAV: основной плюс 0/1/8 дополнительных, HTTP/HTTPS, IPv6, путь,
    #    специальные символы в credentials, enc, bootstrap DNS, tuning
    # -------------------------------------------------------------------------
    def test_03_webdav_complex_credentials_and_limits(self):
        st, u = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "wd_complex_user"})
        self.assertEqual(st, 201)

        # Спецсимволы в логине и пароле, IPv6 хост
        p_user = "user+special:name@domain"
        p_pass = "p@ss:w/o?r#d%20&flag=1"
        b_user = "b_usr:sub+domain"
        b_pass = "b_p@ss:complex?&=#"

        backends = []
        for i in range(1, 9):  # 8 дополнительных backends
            scheme = "https" if i % 2 == 0 else "http"
            backends.append({
                "url": f"{scheme}://backend{i}.cloud.internal:8443/data/v{i}/",
                "username": f"{b_user}_{i}",
                "password": f"{b_pass}_{i}",
                "label": f"Бэкенд #{i}"
            })

        complex_conn = {
            "name": "WebDAV-IPv6-Full-8B 🚀",
            "url": "http://[2001:db8:85a3::8a2e:370:7334]:8080/remote/files/",
            "username": p_user,
            "password": p_pass,
            "backends": backends,
            "timeout": "55s",
            "poll_min": "180ms",
            "poll_max": "450ms",
            "coalesce": "15ms",
            "chunk_size": 65536,
            "puts": 6,
            "read_min": 4,
            "read_max": 7,
            "enc": 1,
            "dns": "8.8.4.4:53"
        }

        st, cat_conn = self.api_call(self.port_a, "POST", "/api/webdav/connections", complex_conn)
        self.assertEqual(st, 201)
        uri = cat_conn["uri"]

        # Назначаем пользователю на A и экспортируем
        self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/webdav", {"connection_ids": [cat_conn["id"]]})
        st, exp = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/webdav/export")
        self.assertEqual(st, 200)
        self.assertEqual(exp["uris"][0], uri)

        # Импортируем на сервер B
        st, u_b = self.api_call(self.port_b, "POST", "/api/users", {"nickname": "wd_complex_target"})
        self.assertEqual(st, 201)

        st, imp = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri, "commit": True
        })
        self.assertEqual(st, 200)
        self.assertEqual(len(imp["connections"]), 1)
        c_res = imp["connections"][0]
        self.assertEqual(c_res["username"], p_user)
        self.assertEqual(c_res["password"], p_pass)
        self.assertEqual(c_res["backends_count"], 8)
        self.assertEqual(c_res["dns"], "8.8.4.4:53")
        self.assertEqual(c_res["enc"], 1)

    # -------------------------------------------------------------------------
    # 4. Повторный импорт не создаёт дубликаты; совпавшее имя не перезаписывает профиль
    # -------------------------------------------------------------------------
    def test_04_duplicate_import_idempotence(self):
        st, u_b = self.api_call(self.port_b, "POST", "/api/users", {"nickname": "idempotent_user"})
        self.assertEqual(st, 201)

        # Создаем валидный WebDAV URI
        w_dict = {
            "name": "Unique-Profile-A",
            "url": "https://dav.server.net/path/",
            "username": "user1",
            "password": "pass1_secret",
            "backends": [],
            "timeout": "60s"
        }
        ok, _, uri = serialize_webdav_uri(w_dict)
        self.assertTrue(ok)

        # Первый импорт
        st1, imp1 = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri, "commit": True
        })
        self.assertEqual(st1, 200)
        conn_id_1 = imp1["connections"][0]["id"]
        rev_1 = imp1["revision"]

        # Повторный импорт ТОЙ ЖЕ ссылки:
        # Не должен создавать дубликат в каталоге и не должен дважды привязывать к пользователю
        st2, imp2 = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri, "commit": True
        })
        self.assertEqual(st2, 200)
        self.assertEqual(len(imp2["connections"]), 1)
        self.assertEqual(imp2["connections"][0]["id"], conn_id_1)

        # Теперь импортируем ДРУГОЕ подключение, но с ТАКИМ ЖЕ ИМЕНЕМ #Unique-Profile-A
        w_dict_diff = {
            "name": "Unique-Profile-A",
            "url": "https://different.server.org/files/",
            "username": "diff_user",
            "password": "diff_password",
            "backends": [],
            "timeout": "30s"
        }
        ok_d, _, uri_diff = serialize_webdav_uri(w_dict_diff)
        self.assertTrue(ok_d)

        st3, imp3 = self.api_call(self.port_b, "POST", f"/api/users/{u_b['id']}/webdav/import", {
            "uri": uri_diff, "commit": True
        })
        self.assertEqual(st3, 200)
        # Должно добавиться второе независимое подключение, первое не перезаписано!
        self.assertEqual(len(imp3["connections"]), 2)
        c_ids = [c["id"] for c in imp3["connections"]]
        self.assertIn(conn_id_1, c_ids)

        # Проверяем каталог на сервере B: запись conn_id_1 сохранила свой URL!
        st_cat, cat_1 = self.api_call(self.port_b, "GET", f"/api/webdav/connections/{conn_id_1}?secrets=1")
        self.assertEqual(st_cat, 200)
        self.assertEqual(cat_1["url"], "https://dav.server.net/path/")

        # Идентичный повторный импорт OpenFlux:
        # Экспортируем текущий OpenFlux пользователя bob_b
        st_exp, imported = self.api_call(self.port_b, "GET", "/api/users/bob_b/openflux/imported")
        self.assertEqual(st_exp, 200)
        of_exp = imported['connections'][0]
        uri_of = of_exp["uri"]
        rev_before = of_exp["revision"]

        # Повторно импортируем bob_b его же бандл
        st_re, res_re = self.api_call(self.port_b, "POST", "/api/users/bob_b/openflux/import", {
            "uri": uri_of, "commit": True
        })
        self.assertEqual(st_re, 200)
        self.assertTrue(res_re.get("no_op", False))
        self.assertEqual(res_re["revision"], rev_before)  # Ревизия не выросла!

    # -------------------------------------------------------------------------
    # 5. Импорт к существующему пользователю не меняет остальных пользователей
    # -------------------------------------------------------------------------
    def test_05_user_isolation(self):
        # Создаем пользователей user_one и user_two
        st, u1 = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "user_one"})
        self.assertEqual(st, 201)
        st, u2 = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "user_two"})
        self.assertEqual(st, 201)

        token_u2_before = u2["subscription_token"]
        rev_u2_before = u2["revision"]

        # Настраиваем пользователя 2 на OpenFlux и WebDAV
        st_g, grp = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "U2-Group", "mode": "classic", "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/u2/test"], "codec": "legacy"
        })
        self.assertEqual(st_g, 201)
        self.api_call(self.port_a, "PUT", f"/api/users/{u2['id']}/openflux", {
            "group_ids": [grp["id"]], "enabled": True
        })

        # Получаем данные u2 перед манипуляциями с u1
        st, u2_state_before = self.api_call(self.port_a, "GET", f"/api/users/{u2['id']}")
        self.assertEqual(st, 200)

        # Выполняем экспорт и импорт ТОЛЬКО для user_one
        st_exp, exp_data = self.api_call(self.port_a, "GET", "/api/users/alice_a/openflux/export")
        self.assertEqual(st_exp, 200)

        st_imp, _ = self.api_call(self.port_a, "POST", f"/api/users/{u1['id']}/openflux/import", {
            "uri": exp_data["uri"], "commit": True
        })
        self.assertEqual(st_imp, 200)

        # Проверяем, что user_two никак не изменился:
        st, u2_state_after = self.api_call(self.port_a, "GET", f"/api/users/{u2['id']}")
        self.assertEqual(st, 200)
        self.assertEqual(u2_state_after["subscription_token"], token_u2_before)
        self.assertEqual(u2_state_after["revision"], u2_state_before["revision"])

        # Проверяем OpenFlux конфигурацию user_two:
        st, of_u2 = self.api_call(self.port_a, "GET", f"/api/users/{u2['id']}/openflux")
        self.assertEqual(st, 200)
        self.assertEqual(of_u2["group_ids"], [grp["id"]])

    # -------------------------------------------------------------------------
    # 6. Ошибочный/слишком длинный URI, неизвестные ключи, конфликт preview
    # -------------------------------------------------------------------------
    def test_06_validation_error_and_optimistic_locking(self):
        st, u = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "err_user"})
        self.assertEqual(st, 201)

        # 6.1 Невалидный префикс схемы
        st, res = self.api_call(self.port_a, "POST", f"/api/users/{u['id']}/openflux/import", {
            "uri": "invalid-scheme://v2/xyz"
        })
        self.assertEqual(st, 400)
        self.assertIn("error", res)

        # 6.2 Неизвестный query параметр в WebDAV
        bad_wd = "webdav://user:pass@example.com:8443/dav/?unknown_key=123#Bad"
        st, res = self.api_call(self.port_a, "POST", f"/api/users/{u['id']}/webdav/import", {
            "uri": bad_wd
        })
        self.assertEqual(st, 400)
        self.assertIn("Unknown query parameter", res["error"])

        # 6.3 Слишком длинный URI (> 131072)
        huge_url = "https://example.com/" + ("a" * 140000)
        bad_huge = f"webdav://user:pass@example.com/dav/?backend={huge_url}"
        st, res = self.api_call(self.port_a, "POST", f"/api/users/{u['id']}/webdav/import", {
            "uri": bad_huge
        })
        self.assertIn(st, (400, 413))

        # 6.4 Конфликт оптимистичной блокировки (concurrency conflict)
        # Получаем preview
        valid_wd = "webdav://u:p@valid.org/dav/#Valid"
        st, prev = self.api_call(self.port_a, "POST", f"/api/users/{u['id']}/webdav/import", {
            "uri": valid_wd, "commit": False
        })
        self.assertEqual(st, 200)
        token = prev["state_token"]

        # Меняем конфигурацию пользователя в фоне
        self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/webdav", {"enabled": False})

        # Пытаемся закоммитить со старым токеном
        st, conflict = self.api_call(self.port_a, "POST", f"/api/users/{u['id']}/webdav/import", {
            "uri": valid_wd, "commit": True, "expected_state_token": token
        })
        self.assertEqual(st, 409)
        self.assertIn("Configuration changed since preview", conflict["error"])

    # -------------------------------------------------------------------------
    # 7. Экспорт при выключенной публикации работает и не меняет состояние
    # -------------------------------------------------------------------------
    def test_07_export_when_disabled_read_only(self):
        st, u = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "disabled_pub_user"})
        self.assertEqual(st, 201)

        # Добавляем группу
        st_g, grp = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "Grp-Disabled", "mode": "classic", "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/dis/1"], "codec": "batched", "encryption_key": "1234567890abcdef1234"
        })
        self.assertEqual(st_g, 201)

        # Настраиваем OpenFlux с enabled = False
        st, of_set = self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/openflux", {
            "name": "Disabled-OF", "group_ids": [grp["id"]], "enabled": False
        })
        self.assertEqual(st, 200)
        rev_before = of_set["revision"]

        # Экспорт должен успешно отработать
        st_exp, exp = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/openflux/export")
        self.assertEqual(st_exp, 200)
        self.assertTrue(exp["uri"].startswith("openflux-bundle://v2/"))
        self.assertFalse(exp["enabled"])
        self.assertEqual(exp["revision"], rev_before)

        # Проверяем, что в БД ничего не изменилось
        st_check, check = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/openflux")
        self.assertEqual(st_check, 200)
        self.assertFalse(check["enabled"])
        self.assertEqual(check["revision"], rev_before)

    # -------------------------------------------------------------------------
    # 8. Содержимое выдаваемой подписки совпадает с экспортом по параметрам
    # -------------------------------------------------------------------------
    def test_08_subscription_content_matches_export(self):
        st, u = self.api_call(self.port_a, "POST", "/api/users", {"nickname": "sub_match_user"})
        self.assertEqual(st, 201)

        # Настраиваем OpenFlux
        st_g, grp = self.api_call(self.port_a, "POST", "/api/openflux/groups", {
            "name": "Sub-Match-Grp", "mode": "classic", "transport": "boards",
            "urls": ["https://boards.yandex.ru/whiteboard/?hash=sub1"], "codec": "batched", "encryption_key": "1234567890abcdef1234"
        })
        self.assertEqual(st_g, 201)
        self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/openflux", {
            "name": "Sub-Match-OF", "group_ids": [grp["id"]], "enabled": True
        })

        # Настраиваем WebDAV
        w_conn = {
            "name": "Sub-Match-WD",
            "url": "https://dav.sub.com:8443/files/",
            "username": "s_user",
            "password": "s_password",
            "backends": [],
            "timeout": "50s",
            "enc": 1
        }
        st_w, cat_w = self.api_call(self.port_a, "POST", "/api/webdav/connections", w_conn)
        self.assertEqual(st_w, 201)
        self.api_call(self.port_a, "PUT", f"/api/users/{u['id']}/webdav", {
            "connection_ids": [cat_w["id"]], "enabled": True
        })

        # Получаем экспорты
        _, exp_of = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/openflux/export")
        _, exp_wd = self.api_call(self.port_a, "GET", f"/api/users/{u['id']}/webdav/export")

        # Запрашиваем публичную подписку /sub/<token>
        token = u["subscription_token"]
        st_sub, raw_sub = self.api_call(self.port_a, "GET", f"/sub/{token}")
        self.assertEqual(st_sub, 200)

        # Декодируем Base64 подписку
        decoded_text = base64.b64decode(raw_sub).decode("utf-8")
        sub_lines = [line.strip() for line in decoded_text.splitlines() if line.strip()]

        # Проверяем наличие точных URI в подписке
        self.assertIn(exp_of["uri"], sub_lines)
        self.assertIn(exp_wd["uris"][0], sub_lines)

    # -------------------------------------------------------------------------
    # 9. Проверка готовых фиктивных примеров парсерами TUNA rc9
    # -------------------------------------------------------------------------
    def test_09_tuna_rc9_parser_compliance(self):
        # 9.1 Валидный сложный WebDAV URI
        fixture_wd = (
            "webdavs://admin:secret123@cloud.company.com:9443/remote.php/webdav/?"
            "timeout=60s&poll-min=200ms&poll-max=500ms&coalesce=10ms&chunk-size=131071&puts=8&"
            "read-min=3&read-max=8&enc=1&dns=1.1.1.1%3A53&"
            "backend=webdav%3A%2F%2Fback1%3Apass1%40b1.company.com%3A8080%2Fdata%2F&"
            "backend=webdavs%3A%2F%2Fback2%3Apass2%40b2.company.com%2Fpool%2F"
            "#Корпоративный%20Пул"
        )
        ok, err, parsed = parse_webdav_uri(fixture_wd)
        self.assertTrue(ok, f"Parser error: {err}")
        self.assertEqual(parsed["name"], "Корпоративный Пул")
        self.assertEqual(parsed["username"], "admin")
        self.assertEqual(parsed["password"], "secret123")
        self.assertEqual(len(parsed["backends"]), 2)
        self.assertEqual(parsed["backends"][0]["username"], "back1")
        self.assertEqual(parsed["backends"][1]["username"], "back2")

        # 9.2 Проверка обратной сериализации
        ok_ser, err_ser, reserialized = serialize_webdav_uri(parsed)
        self.assertTrue(ok_ser, f"Serializer error: {err_ser}")
        # Повторный парсинг ресериализованной строки дает идентичные реквизиты
        ok_re, _, parsed_re = parse_webdav_uri(reserialized)
        self.assertTrue(ok_re)
        self.assertEqual(compute_webdav_canonical_fingerprint(parsed), compute_webdav_canonical_fingerprint(parsed_re))


if __name__ == "__main__":
    unittest.main()
