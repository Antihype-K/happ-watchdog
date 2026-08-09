#!/usr/bin/env python3
"""Тесты сторожа. Сеть и настоящий VPN не трогаются: пробы подменяются.

    python3 -m unittest discover -v

Изолируется всё, что пишет на диск: XDG_STATE_HOME подменяется до импорта
модуля, иначе тесты будут писать в настоящий журнал и файл состояния.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_SANDBOX = tempfile.mkdtemp(prefix="happ-watchdog-tests-")
os.environ["XDG_STATE_HOME"] = _SANDBOX
os.environ["XDG_CONFIG_HOME"] = _SANDBOX

sys.path.insert(0, str(Path(__file__).resolve().parent))
import happ_watchdog as w  # noqa: E402  — импорт только после подмены окружения


def default_cfg() -> dict:
    return {k: dict(v) for k, v in w.DEFAULTS.items()}


class ParseServerRef(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(w.parse_server_ref(" 1.2.3.4:443 "), ("1.2.3.4", 443, "1.2.3.4"))

    def test_vless_with_name(self):
        ref = "vless://uuid@vpn.example.com:8443?type=tcp#%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D1%8F"
        self.assertEqual(w.parse_server_ref(ref), ("vpn.example.com", 8443, "Россия"))

    def test_vmess_base64_json(self):
        payload = base64.b64encode(json.dumps(
            {"add": "vmess.example.com", "port": "10086", "ps": "Узел"}).encode()).decode()
        self.assertEqual(w.parse_server_ref(f"vmess://{payload}"),
                         ("vmess.example.com", 10086, "Узел"))

    def test_ss_base64_userinfo(self):
        body = base64.b64encode(b"aes-256-gcm:secret@ss.example.com:8388").decode()
        self.assertEqual(w.parse_server_ref(f"ss://{body}#SS"), ("ss.example.com", 8388, "SS"))

    def test_garbage_and_empty(self):
        for ref in ("", "   ", "просто строка", "host-без-порта", "1.2.3.4:порт", "ss://!!!"):
            with self.subTest(ref=ref):
                self.assertIsNone(w.parse_server_ref(ref))

    def test_subscription_stub_is_parsed_but_filtered_by_caller(self):
        # Провайдеры отдают такую заглушку без правильного X-HWID.
        self.assertEqual(w.parse_server_ref("vless://x@0.0.0.0:1#Не поддерживается"),
                         ("0.0.0.0", 1, "Не поддерживается"))


class DnsParsing(unittest.TestCase):
    @staticmethod
    def response(ip: str, *, ancount: int = 1, rcode: int = 0) -> bytes:
        header = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, ancount, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        return header + question + (answer if ancount else b"")

    def test_reads_a_record(self):
        self.assertEqual(w._first_a_record(self.response("93.184.216.34")), "93.184.216.34")

    def test_truncated_packet_returns_none(self):
        self.assertIsNone(w._first_a_record(self.response("1.2.3.4")[:20]))

    def test_no_answers(self):
        self.assertIsNone(w._first_a_record(self.response("1.2.3.4", ancount=0)))


class Durations(unittest.TestCase):
    def test_units(self):
        self.assertEqual(w.parse_duration("90s"), 90)
        self.assertEqual(w.parse_duration("30m"), 1800)
        self.assertEqual(w.parse_duration("2h"), 7200)
        self.assertEqual(w.parse_duration("1d"), 86400)

    def test_bare_number_means_minutes(self):
        self.assertEqual(w.parse_duration("45"), 2700)

    def test_bad_input(self):
        for text in ("", "полчаса", "10x", "-5m"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    w.parse_duration(text)


class ConfigLoading(unittest.TestCase):
    def write(self, body: str) -> Path:
        path = Path(tempfile.mkdtemp()) / "config.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_user_values_override_defaults_others_kept(self):
        cfg = w.load_config(self.write("[general]\ninterval = 3\n"))
        self.assertEqual(cfg["general"]["interval"], 3)
        self.assertEqual(cfg["general"]["failures_before_restart"],
                         w.DEFAULTS["general"]["failures_before_restart"])

    def test_typo_is_reported_and_does_not_change_behaviour(self):
        cfg = w.load_config(self.write("[general]\ninteval = 5\n\n[cheks]\nx = 1\n"))
        self.assertEqual(cfg["general"]["interval"], w.DEFAULTS["general"]["interval"])
        messages = w.unknown_keys({"general": {"inteval": 5}, "cheks": {"x": 1}})
        self.assertEqual(len(messages), 2)
        self.assertIn("general.inteval", messages[0])
        self.assertIn("[cheks]", messages[1])

    def test_shipped_template_has_no_unknown_keys(self):
        # Шаблон и DEFAULTS обязаны сходиться, иначе свежий конфиг сразу ругается.
        path = self.write(w.CONFIG_TEMPLATE)
        import tomllib
        with path.open("rb") as fh:
            self.assertEqual(w.unknown_keys(tomllib.load(fh)), [])

    def test_missing_config_is_created(self):
        path = Path(tempfile.mkdtemp()) / "new" / "config.toml"
        w.load_config(path)
        self.assertTrue(path.exists())


class Escalation(unittest.TestCase):
    def setUp(self):
        self.cfg = default_cfg()
        self.state = {"ladder": 0, "restarts": [], "escalations": []}
        self.recovery = w.Recovery(self.cfg, w.Happ(self.cfg), self.state)

    def test_ladder_order(self):
        self.assertEqual(self.recovery.plan(0)[0], "soft")
        self.assertEqual(self.recovery.plan(1)[0], "cycle")
        self.assertEqual(self.recovery.plan(2)[0], "gui")

    def test_daemon_step_requires_permission(self):
        self.assertEqual(self.recovery.plan(3)[0], "cycle")   # allow_daemon_restart = false
        self.cfg["recovery"]["allow_daemon_restart"] = True
        self.assertEqual(self.recovery.plan(3)[0], "daemon")

    def test_beyond_ladder_stays_soft_forever(self):
        # Сторож не имеет права опустить руки: дальше лестницы — мягкие попытки.
        for ladder in (4, 9, 99):
            self.assertEqual(self.recovery.plan(ladder)[0], "cycle")

    def test_quota_counts_only_hard_steps(self):
        limit = self.cfg["recovery"]["max_escalations_per_hour"]
        self.state["escalations"] = [time.time()] * limit
        self.assertTrue(self.recovery.escalations_limited())
        self.state["escalations"] = [time.time() - 3700] * limit    # старше часа
        self.assertFalse(self.recovery.escalations_limited())

    def test_stop_prevents_treatment(self):
        stop = threading.Event()
        stop.set()
        recovery = w.Recovery(self.cfg, w.Happ(self.cfg, stop), self.state, stop)
        self.assertFalse(recovery.perform("тест"))
        self.assertEqual(self.state["restarts"], [])              # история не тронута


class CrashDetection(unittest.TestCase):
    """Падение Happ отличается от выхода по кнопке следами работавшего туннеля."""

    def setUp(self):
        self.cfg = default_cfg()
        self.saved = (w.XRAY_PATH_HINT, w.SINGBOX_PATH_HINT, w.iface_exists)
        w.XRAY_PATH_HINT = "нет-такого-процесса-xray"
        w.SINGBOX_PATH_HINT = "нет-такого-процесса-singbox"
        w.iface_exists = lambda name: False

    def tearDown(self):
        w.XRAY_PATH_HINT, w.SINGBOX_PATH_HINT, w.iface_exists = self.saved

    def test_clean_exit_leaves_nothing(self):
        self.assertEqual(w.leftovers_after_gui(self.cfg), [])

    def test_live_tun_is_evidence_of_a_crash(self):
        w.iface_exists = lambda name: name == self.cfg["happ"]["tun_interface"]
        self.assertEqual(w.leftovers_after_gui(self.cfg), ["интерфейс tun0 на месте"])

    def test_quota_stops_endless_resurrection(self):
        # Happ, падающий сразу после старта, нельзя поднимать по кругу.
        state = {"escalations": [time.time()] * self.cfg["recovery"]["max_escalations_per_hour"]}
        happ = w.Happ(self.cfg)
        happ.start_gui = lambda: self.fail("поднимать Happ было нельзя")
        recovery = w.Recovery(self.cfg, happ, state)
        self.assertFalse(recovery.restart_crashed_gui("ядро xray живо"))
        self.assertTrue(state["crash_notice"])

    def test_stop_prevents_resurrection(self):
        stop = threading.Event()
        stop.set()
        happ = w.Happ(self.cfg, stop)
        happ.start_gui = lambda: self.fail("поднимать Happ было нельзя")
        recovery = w.Recovery(self.cfg, happ, {}, stop)
        self.assertFalse(recovery.restart_crashed_gui("ядро xray живо"))

    def test_resurrection_counts_as_a_hard_step(self):
        state: dict = {}
        happ = w.Happ(self.cfg)
        happ.start_gui = lambda: True
        happ.connect = lambda: True
        recovery = w.Recovery(self.cfg, happ, state)
        recovery.verify = lambda: True
        self.assertTrue(recovery.restart_crashed_gui("ядро xray живо"))
        self.assertEqual(len(state["escalations"]), 1)


class LeakDetection(unittest.TestCase):
    def setUp(self):
        self.cfg = default_cfg()
        self.original = w.exit_ip

    def tearDown(self):
        w.exit_ip = self.original

    def fake_measurements(self, pairs):
        it = iter(pairs)
        w.exit_ip = lambda cfg, *, via_socks: next(it)

    def test_prefixes(self):
        self.assertEqual(w.ip_prefix("45.144.53.130"), "45.144.53")
        self.assertEqual(w.ip_prefix("2a0b:4143:0:5fa::2"), "2a0b:4143:0")

    def test_same_exit_is_healthy(self):
        self.fake_measurements([("45.144.53.130", ""), ("45.144.53.130", "")])
        self.assertTrue(w.check_leak(self.cfg).ok)

    def test_provider_pool_is_not_a_leak(self):
        self.fake_measurements([("45.144.53.130", ""), ("45.144.53.201", "")])
        self.assertTrue(w.check_leak(self.cfg).ok)

    def test_traffic_outside_tunnel_is_caught(self):
        self.fake_measurements([("45.144.53.130", ""), ("178.66.12.7", "")] * 2)
        check = w.check_leak(self.cfg)
        self.assertFalse(check.ok)
        self.assertTrue(check.critical)
        self.assertIn("мимо VPN", check.detail)

    def test_server_switch_between_measurements_is_forgiven(self):
        self.fake_measurements([("45.144.53.130", ""), ("178.66.12.7", ""),
                                ("91.7.7.7", ""), ("91.7.7.9", "")])
        self.assertTrue(w.check_leak(self.cfg).ok)

    def test_unmeasurable_is_not_critical(self):
        self.fake_measurements([(None, "ConnectionRefusedError"), ("45.144.53.130", "")])
        check = w.check_leak(self.cfg)
        self.assertTrue(check.ok)
        self.assertFalse(check.critical)

    def test_disabled(self):
        self.cfg["checks"]["leak_check"] = False
        self.assertFalse(w.check_leak(self.cfg).critical)

    def test_ipv6_leak_is_reported_even_when_exit_ip_matches(self):
        self.fake_measurements([("45.144.53.130", ""), ("45.144.53.130", "")])
        original = w.ipv6_leaks_outside_tunnel
        w.ipv6_leaks_outside_tunnel = lambda cfg: "IPv6 идёт через wlo1 мимо tun0"
        try:
            check = w.check_leak(self.cfg)
        finally:
            w.ipv6_leaks_outside_tunnel = original
        self.assertFalse(check.ok)
        self.assertIn("IPv6", check.detail)


class IPv6Routing(unittest.TestCase):
    """IPv6 проверяется маршрутами: сниффинг Happ подменяет адрес назначения
    доменом из SNI, и пробой семейство не зафиксировать."""

    def setUp(self):
        self.cfg = default_cfg()
        self.saved = (w.iface_exists, w.global_ipv6_interfaces, w.ipv6_default_routes)
        w.iface_exists = lambda name: name == "tun0"

    def tearDown(self):
        w.iface_exists, w.global_ipv6_interfaces, w.ipv6_default_routes = self.saved

    def test_no_global_ipv6_means_nothing_can_leak(self):
        w.global_ipv6_interfaces = lambda: []
        w.ipv6_default_routes = lambda: []
        self.assertIsNone(w.ipv6_leaks_outside_tunnel(self.cfg))

    def test_ipv6_through_tunnel_is_fine(self):
        w.global_ipv6_interfaces = lambda: ["tun0"]
        w.ipv6_default_routes = lambda: [("tun0", 1024)]
        self.assertIsNone(w.ipv6_leaks_outside_tunnel(self.cfg))

    def test_ipv6_through_physical_interface_is_a_leak(self):
        w.global_ipv6_interfaces = lambda: ["wlo1"]
        w.ipv6_default_routes = lambda: [("wlo1", 1024)]
        problem = w.ipv6_leaks_outside_tunnel(self.cfg)
        self.assertIsNotNone(problem)
        self.assertIn("wlo1", problem)

    def test_no_tunnel_means_nothing_to_compare(self):
        w.iface_exists = lambda name: False
        w.global_ipv6_interfaces = lambda: ["wlo1"]
        w.ipv6_default_routes = lambda: [("wlo1", 1024)]
        self.assertIsNone(w.ipv6_leaks_outside_tunnel(self.cfg))

    def test_route_table_is_parsed_and_lo_stubs_dropped(self):
        # Как в /proc/net/ipv6_route: сначала ::/0 через lo (заглушка
        # unreachable с максимальной метрикой), затем настоящий через tun0.
        zero = "0" * 32
        rows = [f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo",
                f"{zero} 00 {zero} 00 {zero} 00000400 00000000 00000000 00000003 tun0"]
        path = Path(tempfile.mkdtemp()) / "ipv6_route"
        path.write_text("\n".join(rows) + "\n")
        self.assertEqual(w.ipv6_default_routes(path), [("tun0", 1024)])

    def test_interface_table_keeps_only_global_scope(self):
        rows = ["fe80000000000000aabbccddeeff0011 03 40 20 80 wlo1",   # link-local
                "2a00000000000000aabbccddeeff0011 04 40 00 80 tun0"]   # глобальный
        path = Path(tempfile.mkdtemp()) / "if_inet6"
        path.write_text("\n".join(rows) + "\n")
        self.assertEqual(w.global_ipv6_interfaces(path), ["tun0"])


class ExpectedCodes(unittest.TestCase):
    def setUp(self):
        self.cfg = default_cfg()
        self.original = w.http_probe
        w.http_probe = lambda host, path, timeout, **kw: (False, f"{host}: TimeoutError", 5000.0)

    def tearDown(self):
        w.http_probe = self.original

    def test_shipped_block_does_not_condemn_the_tunnel(self):
        checks = w.check_expected(self.cfg)
        self.assertFalse(checks[0].ok)
        self.assertFalse(checks[0].critical)
        self.assertTrue(w.Health(checks=checks).ok)

    def test_critical_by_default(self):
        self.cfg["checks"]["expect"] = [{"host": "example.com", "path": "/", "code": 200}]
        checks = w.check_expected(self.cfg)
        self.assertTrue(checks[0].critical)
        self.assertFalse(w.Health(checks=checks).ok)


class GuardedChecks(unittest.TestCase):
    def test_exception_becomes_non_critical_check(self):
        def boom():
            raise RuntimeError("сломано")
        check = w._guarded("Проба", boom)()
        self.assertFalse(check.ok)
        self.assertFalse(check.critical)          # баг сторожа ≠ повод дёргать VPN
        self.assertIn("RuntimeError", check.detail)

    def test_crashing_check_does_not_break_run_health(self):
        patched = ("check_dns", "check_processes", "check_proxy", "check_system_dns",
                   "check_leak", "check_expected", "check_happ_logs")
        originals = {name: getattr(w, name) for name in patched}
        try:
            for name in patched:
                setattr(w, name, lambda *a, **k: w.Check("заглушка", True))
            w.check_dns = lambda cfg: (_ for _ in ()).throw(RuntimeError("сломано"))
            cfg = default_cfg()
            cfg["uplink"]["check"] = False
            health = w.run_health(cfg)
            self.assertTrue(any("RuntimeError" in ch.detail for ch in health.checks))
            self.assertTrue(health.ok)        # баг сторожа не считается сбоем туннеля
        finally:
            for name, func in originals.items():
                setattr(w, name, func)


class ParallelRuns(unittest.TestCase):
    def test_results_keep_order(self):
        tasks = [lambda i=i: i for i in range(6)]
        self.assertEqual(w._parallel(tasks), list(range(6)))

    def test_empty_and_single(self):
        self.assertEqual(w._parallel([]), [])
        self.assertEqual(w._parallel([lambda: "один"]), ["один"])

    def test_waits_run_simultaneously(self):
        started = time.monotonic()
        w._parallel([lambda: time.sleep(0.3) for _ in range(5)])
        self.assertLess(time.monotonic() - started, 0.9)   # последовательно было бы 1,5 с


class HappLogScan(unittest.TestCase):
    def setUp(self):
        self.cfg = default_cfg()
        self.dir = Path(tempfile.mkdtemp())
        self.original = w.HAPP_LOG_DIR
        w.HAPP_LOG_DIR = self.dir

    def tearDown(self):
        w.HAPP_LOG_DIR = self.original

    def test_stale_logs_are_reported_honestly(self):
        path = self.dir / "core_log.txt"
        path.write_text("connection refused\n")
        old = time.time() - 10000
        os.utime(path, (old, old))
        check = w.check_happ_logs(self.cfg)
        self.assertTrue(check.ok)
        self.assertIn("не обновляются", check.detail)

    def test_burst_of_errors_fails(self):
        threshold = self.cfg["checks"]["log_error_threshold"]
        (self.dir / "tun_log.txt").write_text("i/o timeout\n" * (threshold + 1))
        check = w.check_happ_logs(self.cfg)
        self.assertFalse(check.ok)
        self.assertIn("ошибок", check.detail)

    def test_fresh_and_quiet(self):
        (self.dir / "tun_log.txt").write_text("всё хорошо\n")
        check = w.check_happ_logs(self.cfg)
        self.assertTrue(check.ok)
        self.assertIn("0 ошибок", check.detail)


class SessionEnvironment(unittest.TestCase):
    def setUp(self):
        self.runtime = Path(tempfile.mkdtemp())
        self.saved = {k: os.environ.get(k) for k in ("XAUTHORITY", "XDG_RUNTIME_DIR")}
        os.environ["XDG_RUNTIME_DIR"] = str(self.runtime)

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_live_value_is_kept(self):
        alive = self.runtime / ".mutter-Xwaylandauth.ALIVE"
        alive.touch()
        os.environ["XAUTHORITY"] = str(alive)
        self.assertEqual(w.session_env()["XAUTHORITY"], str(alive))

    def test_stale_value_is_replaced_by_fresh_file(self):
        fresh = self.runtime / ".mutter-Xwaylandauth.FRESH"
        fresh.touch()
        os.environ["XAUTHORITY"] = str(self.runtime / ".mutter-Xwaylandauth.МЁРТВЫЙ")
        self.assertEqual(w.session_env()["XAUTHORITY"], str(fresh))

    def test_nothing_found_drops_the_variable(self):
        os.environ["XAUTHORITY"] = str(self.runtime / "нет-такого")
        env = w.session_env()
        # Пустой каталог: подхватить нечего, и мёртвый путь оставлять нельзя.
        self.assertNotEqual(env.get("XAUTHORITY"), str(self.runtime / "нет-такого"))


SAMPLE_HAPP_CONF = """\
[General]
lang=ru

[Preferences]
AdvancedSettings\\tun=true
AdvancedSettings\\tunDnsEnable=true
PingSettings\\pingTestUrl=https://cp.cloudflare.com/generate_204

[Vacancy]
seen=1
"""


class HappSettingsHealing(unittest.TestCase):
    def setUp(self):
        self.cfg = default_cfg()
        self.dir = Path(tempfile.mkdtemp())
        self.conf = self.dir / "Happ.conf"
        self.conf.write_text(SAMPLE_HAPP_CONF, encoding="utf-8")
        self.saved = (w.HAPP_SETTINGS_PATH, w.HAPP_SETTINGS_BACKUP)
        w.HAPP_SETTINGS_PATH = self.conf
        w.HAPP_SETTINGS_BACKUP = self.dir / "Happ.conf.bak"

    def tearDown(self):
        w.HAPP_SETTINGS_PATH, w.HAPP_SETTINGS_BACKUP = self.saved

    def test_reads_only_preferences_section(self):
        values = w.read_happ_settings()
        self.assertEqual(values["AdvancedSettings\\tunDnsEnable"], "true")
        self.assertNotIn("lang", values)          # [General] — чужая секция
        self.assertNotIn("seen", values)

    def test_problems_list_names_current_values(self):
        problems = w.happ_settings_problems(self.cfg)
        self.assertTrue(any("tunDnsEnable=false (сейчас true)" in p for p in problems))
        self.assertTrue(any("xrayCoreLogLevel=info (сейчас не задано)" in p for p in problems))

    def test_existing_key_is_corrected_and_missing_one_added(self):
        w.apply_happ_settings(w.desired_happ_settings(self.cfg))
        values = w.read_happ_settings()
        self.assertEqual(values["AdvancedSettings\\tunDnsEnable"], "false")
        self.assertEqual(values["LogSettings\\xrayCoreLogLevel"], "info")
        self.assertEqual(w.happ_settings_problems(self.cfg), [])

    def test_other_sections_survive_and_backup_is_written(self):
        w.apply_happ_settings(w.desired_happ_settings(self.cfg))
        text = self.conf.read_text(encoding="utf-8")
        self.assertIn("[General]\nlang=ru", text)
        self.assertIn("[Vacancy]\nseen=1", text)
        self.assertEqual(w.HAPP_SETTINGS_BACKUP.read_text(encoding="utf-8"), SAMPLE_HAPP_CONF)

    def test_running_happ_is_left_alone(self):
        # Happ перезаписывает файл своим состоянием из памяти — правка пропала бы.
        happ = w.Happ(self.cfg)
        happ.gui_running = lambda: True
        state: dict = {}
        self.assertEqual(w.selfheal_settings(self.cfg, happ, state), [])
        self.assertIn("tunDnsEnable=true", self.conf.read_text(encoding="utf-8"))
        self.assertTrue(state["settings_notice"])          # предупредили один раз

    def test_closed_happ_gets_fixed(self):
        happ = w.Happ(self.cfg)
        happ.gui_running = lambda: False
        fixed = w.selfheal_settings(self.cfg, happ, {})
        self.assertEqual(len(fixed), 2)
        self.assertIn("tunDnsEnable=false", self.conf.read_text(encoding="utf-8"))

    def test_nothing_to_do_is_silent(self):
        w.apply_happ_settings(w.desired_happ_settings(self.cfg))
        happ = w.Happ(self.cfg)
        happ.gui_running = lambda: False
        self.assertEqual(w.selfheal_settings(self.cfg, happ, {}), [])

    def test_disabled_switches_are_respected(self):
        self.cfg["selfheal"]["fix_tun_dns"] = False
        self.cfg["selfheal"]["fix_core_log_level"] = False
        self.assertEqual(w.desired_happ_settings(self.cfg), {})
        self.assertEqual(w.happ_settings_problems(self.cfg), [])


class OrphanCores(unittest.TestCase):
    """Ядро, пережившее свой GUI, проверяется на настоящем процессе."""

    def setUp(self):
        import subprocess
        self.cfg = default_cfg()
        self.cfg["selfheal"]["orphan_grace"] = 0.5
        self.proc = subprocess.Popen(["sleep", "47"])
        self.saved = (w.XRAY_PATH_HINT, w.SINGBOX_PATH_HINT)
        w.XRAY_PATH_HINT = "sleep 47"
        w.SINGBOX_PATH_HINT = "нет-такого-процесса"
        self.happ = w.Happ(self.cfg)
        self.happ.gui_running = lambda: False

    def tearDown(self):
        w.XRAY_PATH_HINT, w.SINGBOX_PATH_HINT = self.saved
        self.proc.kill()
        self.proc.wait()

    def test_first_sighting_only_starts_the_clock(self):
        state: dict = {}
        self.assertEqual(w.selfheal_orphan_cores(self.cfg, self.happ, state), [])
        self.assertIn("orphan_since", state)
        self.assertIsNone(self.proc.poll())              # процесс цел

    def test_orphan_is_killed_after_grace(self):
        state = {"orphan_since": time.time() - 5}
        done = w.selfheal_orphan_cores(self.cfg, self.happ, state)
        self.assertTrue(any("осиротевший xray" in line for line in done))
        self.proc.wait(timeout=5)
        self.assertIsNotNone(self.proc.poll())           # действительно снят

    def test_living_gui_means_no_orphans(self):
        self.happ.gui_running = lambda: True
        state = {"orphan_since": time.time() - 5}
        self.assertEqual(w.selfheal_orphan_cores(self.cfg, self.happ, state), [])
        self.assertNotIn("orphan_since", state)          # счётчик сброшен
        self.assertIsNone(self.proc.poll())

    def test_switch_off_disables_killing(self):
        self.cfg["selfheal"]["kill_orphan_cores"] = False
        state = {"orphan_since": time.time() - 5}
        self.assertEqual(w.selfheal_orphan_cores(self.cfg, self.happ, state), [])
        self.assertIsNone(self.proc.poll())


class LogSummary(unittest.TestCase):
    @staticmethod
    def events(pairs):
        base = time.time() - 3600
        return [(base + offset, "WARN", msg) for offset, msg in pairs]

    def test_episode_from_first_failure_to_recovery(self):
        summary = w.summarize_log(self.events([
            (0, "сбой 1/3: SOCKS 127.0.0.1:10808: таймаут"),
            (10, "сбой 2/3: SOCKS 127.0.0.1:10808: таймаут"),
            (30, "VPN восстановлен после «мягкое переподключение (happ://connect)»"),
        ]))
        self.assertEqual(len(summary["episodes"]), 1)
        start, end = summary["episodes"][0]
        self.assertEqual(end - start, 30)
        self.assertEqual(summary["recovered"], 1)

    def test_self_healing_closes_episode(self):
        summary = w.summarize_log(self.events([
            (0, "сбой 1/3: DNS: пустой ответ"),
            (20, "связь восстановилась сама, счётчик сбоев сброшен"),
        ]))
        self.assertEqual(summary["self_healed"], 1)
        self.assertEqual(len(summary["episodes"]), 1)

    def test_watchdog_restart_closes_open_episode(self):
        summary = w.summarize_log(self.events([
            (0, "сбой 1/3: DNS: пустой ответ"),
            (15, "остановлен"),
        ]))
        self.assertEqual(len(summary["episodes"]), 1)

    def test_step_with_arrow_in_its_name(self):
        # «полный цикл disconnect → connect» — стрелка внутри названия шага,
        # а в причине сбоя есть своя: резать строку по стрелке нельзя.
        summary = w.summarize_log(self.events([
            (0, "сбой 1/3: api.anthropic.com → ждём 404: пришло 403"),
            (5, "VPN сбоит: api.anthropic.com → ждём 404: пришло 403 "
                "→ полный цикл disconnect → connect"),
        ]))
        self.assertEqual(summary["steps"], {"полный цикл disconnect → connect": 1})

    def test_culprits_counted_without_double_counting_dns(self):
        counter: dict[str, int] = {}
        w.count_failed_checks("Системный DNS (браузер): не резолвится; DNS: пустой ответ",
                              counter)
        self.assertEqual(counter, {"Системный DNS (браузер)": 1, "DNS": 1})

    def test_culprits_include_expected_code_blocks(self):
        counter: dict[str, int] = {}
        w.count_failed_checks("api.anthropic.com → ждём 404: пришло 403", counter)
        self.assertEqual(counter, {"api.anthropic.com → ждём 404": 1})


class HealthSemantics(unittest.TestCase):
    def test_non_critical_failure_keeps_health_ok(self):
        health = w.Health(checks=[w.Check("важная", True), w.Check("справочная", False,
                                                                   critical=False)])
        self.assertTrue(health.ok)

    def test_reason_lists_only_failures(self):
        health = w.Health(checks=[w.Check("живая", True, "ок"),
                                  w.Check("мёртвая", False, "таймаут")])
        self.assertEqual(health.reason(), "мёртвая: таймаут")


if __name__ == "__main__":
    unittest.main(verbosity=2)
