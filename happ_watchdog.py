#!/usr/bin/env python3
"""happ-watchdog — сторож для Happ VPN (Linux).

Постоянно проверяет здоровье туннеля (процессы, SOCKS, системный путь через tun,
DNS, логи ядра) и автоматически перезапускает VPN через deeplink-и Happ
(happ://connect, happ://disconnect), если что-то сломалось.

Зависимостей нет — только стандартная библиотека Python 3.11+.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tomllib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

APP = "happ-watchdog"
VERSION = "1.0.0"

HOME = Path.home()
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config")) / APP
CONFIG_PATH = CONFIG_DIR / "config.toml"
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / APP
STATE_PATH = STATE_DIR / "state.json"
LOG_PATH = STATE_DIR / "watchdog.log"
LOG_MAX_BYTES = 2 * 1024 * 1024

HAPP_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", HOME / ".local/share")) / "Happ"
HAPP_LOG_DIR = HAPP_DATA_DIR / "logs"
HAPP_SUB_LOG = HAPP_LOG_DIR / "subscription_log.txt"

XRAY_PATH_HINT = "/opt/happ/bin/core/xray"
SINGBOX_PATH_HINT = "/opt/happ/bin/tun/sing-box"


# --------------------------------------------------------------------------
# конфигурация
# --------------------------------------------------------------------------

DEFAULTS: dict = {
    "general": {
        "interval": 10,
        "failures_before_restart": 3,
        "verify_timeout": 45,
        "startup_grace": 45,
        "notify": True,
        "quiet_when_healthy": True,
        "only_when_gui_running": True,
    },
    "happ": {
        "binary": "/opt/happ/bin/Happ",
        "socks_host": "127.0.0.1",
        "socks_port": 10808,
        "tun_interface": "tun0",
        "require_tun": True,
        "require_singbox": True,
    },
    "checks": {
        "probe_hosts": ["cp.cloudflare.com", "www.gstatic.com"],
        "probe_path": "/generate_204",
        "probe_quorum": 1,
        "check_direct_path": True,
        "dns_domains": ["cloudflare.com", "github.com"],
        "dns_servers": ["1.1.1.1", "8.8.8.8"],
        "system_dns_domains": ["www.youtube.com"],
        "leak_check": True,
        "leak_host": "cp.cloudflare.com",
        "leak_path": "/cdn-cgi/trace",
        "expect": [{"host": "api.anthropic.com", "path": "/", "code": 404,
                    "critical": False}],
        "dns_timeout": 4.0,
        "tcp_timeout": 8.0,
        "scan_logs": True,
        "log_error_patterns": [
            "context deadline exceeded",
            "connection refused",
            "i/o timeout",
            "no route to host",
            "handshake failed",
            "network is unreachable",
        ],
        "log_error_threshold": 40,
        "log_window": 120,
    },
    "geo": {
        "autofix": True,
        "check_interval": 1800,
        "required_codes": ["APPLE", "GOOGLE", "NETFLIX", "TELEGRAM"],
    },
    "uplink": {
        "check": True,
        "gateway_ports": [80, 443, 53],
        "timeout": 2.0,
    },
    "recovery": {
        "max_escalations_per_hour": 4,
        "soft_retry_interval": 300,
        "backoff": [10, 30, 60, 120],
        "allow_gui_restart": True,
        "allow_daemon_restart": False,
        "daemon_service": "happd",
    },
    "servers": {
        "list": [],
        "subscriptions": [],
        "user_agent": "Happ/2.11.1",
        "hwid": "",
        "ping_timeout": 3.0,
        "ping_concurrency": 16,
        "subscription_cache_ttl": 3600,
        "auto_discover": True,
        "discover_min_share": 0.5,
        "discover_min_conns": 2,
        "ping_interval": 300,
        "restart_if_active_server_dead": True,
    },
}

CONFIG_TEMPLATE = """\
# happ-watchdog — конфигурация
# После правки перезапустить: systemctl --user restart happ-watchdog

[general]
interval = 10                 # секунд между проверками (пробы идут параллельно,
                              # так что цикл укладывается в интервал даже на таймаутах)
failures_before_restart = 3   # сколько проверок подряд должны упасть до перезапуска
                              # (interval × это число — как быстро сторож вмешается)
verify_timeout = 45           # сколько ждать восстановления после перезапуска
startup_grace = 45            # после запуска Happ дать туннелю подняться, не вмешиваясь
notify = true                 # уведомления через notify-send
quiet_when_healthy = true     # не писать в лог каждую успешную проверку
only_when_gui_running = true  # если Happ закрыт — считать, что VPN выключен намеренно

[happ]
binary = "/opt/happ/bin/Happ"
socks_host = "127.0.0.1"
socks_port = 10808
tun_interface = "tun0"
require_tun = true            # исчезнувший tun0 считается падением
require_singbox = true

[checks]
probe_hosts = ["cp.cloudflare.com", "www.gstatic.com"]
probe_path = "/generate_204"
probe_quorum = 1              # сколько проб должно ответить 204
check_direct_path = true      # проверять весь системный трафик (через tun), не только SOCKS
dns_domains = ["cloudflare.com", "github.com"]
dns_servers = ["1.1.1.1", "8.8.8.8"]
# Домен, который режет провайдер. Проверяется через системный резолвер — тот же
# путь, которым ходит браузер. Если DNS уйдёт мимо туннеля, в браузере
# перестанут открываться сайты, хотя туннель будет выглядеть живым.
system_dns_domains = ["www.youtube.com"]

# Утечка мимо туннеля. Внешний IP спрашивается дважды — через SOCKS и через
# системный маршрут; разные сети означают, что трафик системы идёт открыто,
# хотя туннель при этом выглядит живым (204 приходит по обоим путям одинаково).
leak_check = true
leak_host = "cp.cloudflare.com"
leak_path = "/cdn-cgi/trace"

dns_timeout = 4.0
tcp_timeout = 8.0
scan_logs = true              # искать всплески ошибок в логах Happ
log_error_patterns = [
    "context deadline exceeded",
    "connection refused",
    "i/o timeout",
    "no route to host",
    "handshake failed",
    "network is unreachable",
]
log_error_threshold = 40      # ошибок за окно, чтобы счесть туннель сбойным
log_window = 120              # окно в секундах

# Адреса, у которых признаком здоровья считается конкретный код ответа.
# api.anthropic.com на GET / штатно отвечает 404 — другой код означает, что
# в середину кто-то вмешался. Блоков можно добавить сколько угодно.
#
# critical = false: один внешний адрес не должен в одиночку означать «VPN
# сломан». Такая проба зависит от чужой доступности и способна моргнуть сама
# по себе — в выводе и журнале она видна, но перезапуск VPN не запускает.
[[checks.expect]]
host = "api.anthropic.com"
path = "/"
code = 404
critical = false

[geo]
# Профиль маршрутизации приносит урезанные geo-файлы, и ядро xray не стартует,
# если конфиг сервера из подписки ссылается на отсутствующий код (geosite:apple).
# Happ периодически перекачивает эти файлы — тогда починку надо повторять.
autofix = true
check_interval = 1800
required_codes = ["APPLE", "GOOGLE", "NETFLIX", "TELEGRAM"]

[uplink]
check = true                  # не дёргать VPN, если физический интернет лежит
gateway_ports = [80, 443, 53]
timeout = 2.0

[recovery]
# Мягкие попытки (connect, disconnect+connect) не ограничены: бросать VPN
# лежащим сторож не должен. Квота — только на жёсткие шаги, которые убивают
# процесс Happ или демон; исчерпав её, сторож продолжает мягкими попытками.
max_escalations_per_hour = 4
soft_retry_interval = 300     # пауза между попытками, когда лестница пройдена
backoff = [10, 30, 60, 120]   # пауза перед следующей попыткой, по ступеням
allow_gui_restart = true      # 3-я ступень: перезапуск процесса Happ
allow_daemon_restart = false  # 4-я ступень: sudo -n systemctl restart happd
daemon_service = "happd"

[servers]
# Список серверов для `happ-watchdog ping`.
# Можно host:port или целиком ссылки vless:// / vmess:// / trojan:// / ss://
list = []
# URL подписок. Многие провайдеры отдают заглушку без правильного X-HWID —
# тогда список останется пустым, используйте list или auto_discover.
subscriptions = []
user_agent = "Happ/2.11.1"
hwid = ""
ping_timeout = 3.0
ping_concurrency = 16
subscription_cache_ttl = 3600 # кэш ответа подписки, секунд
auto_discover = true          # определять активный сервер по соединениям xray
discover_min_share = 0.5      # доля соединений, чтобы счесть адрес сервером VPN, а не прямым коннектом
discover_min_conns = 2
ping_interval = 300           # как часто пинговать серверы в режиме run (0 — выключить)
restart_if_active_server_dead = true
"""


def load_config(path: Path = CONFIG_PATH) -> dict:
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        return cfg
    with path.open("rb") as fh:
        user = tomllib.load(fh)
    for section, values in user.items():
        if section in cfg and isinstance(values, dict):
            cfg[section].update(values)
        else:
            cfg[section] = values
    for message in unknown_keys(user):
        log(message, level="warn")
    return cfg


def unknown_keys(user: dict) -> list[str]:
    """Ключи, которых нет в DEFAULTS.

    Молчаливо проигнорированная опечатка — худший вид ошибки в конфиге сторожа:
    `inteval = 5` не поменяет ничего, а выглядит как рабочая настройка.
    """
    messages = []
    for section, values in user.items():
        if section not in DEFAULTS:
            messages.append(f"конфиг: неизвестная секция [{section}] — она ни на что не влияет")
            continue
        if not isinstance(values, dict):
            continue
        for key in values:
            if key not in DEFAULTS[section]:
                messages.append(f"конфиг: неизвестный ключ {section}.{key} — "
                                "он ни на что не влияет (опечатка?)")
    return messages


# --------------------------------------------------------------------------
# логирование / вывод
# --------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    codes = {"green": "32", "red": "31", "yellow": "33", "grey": "90", "bold": "1", "cyan": "36"}
    return f"\033[{codes[color]}m{text}\033[0m"


_log_lock = threading.Lock()


def log(msg: str, *, level: str = "info", echo: bool = True) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] [{level.upper()}] {msg}"
    with _log_lock:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
                LOG_PATH.replace(LOG_PATH.with_suffix(".log.1"))
            with LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    if echo:
        colors = {"error": "red", "warn": "yellow", "ok": "green", "info": "grey"}
        print(c(line, colors.get(level, "grey")) if level in colors else line, flush=True)


def notify(title: str, body: str, urgency: str = "normal") -> None:
    if not shutil.which("notify-send"):
        return
    try:
        subprocess.run(
            ["notify-send", "-a", "Happ Watchdog", "-u", urgency, title, body],
            timeout=5, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass


# --------------------------------------------------------------------------
# низкоуровневые сетевые примитивы
# --------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    ms: float | None = None
    critical: bool = True

    def line(self) -> str:
        mark = c("OK  ", "green") if self.ok else c("СБОЙ", "red")
        lat = f"{self.ms:.0f} ms" if self.ms is not None else ""
        return f"  {self.name:<34} {mark}  {lat:>8}  {self.detail}"


def socks5_connect(proxy_host: str, proxy_port: int, dst_host: str, dst_port: int,
                   timeout: float) -> socket.socket:
    """Открывает TCP через SOCKS5 Happ. Имя резолвится на стороне прокси (ATYP=3)."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise OSError(f"SOCKS5: рукопожатие отклонено ({resp.hex()})")
        host_bytes = dst_host.encode("idna")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", dst_port)
        sock.sendall(req)
        head = _recv_exact(sock, 4)
        if head[1] != 0x00:
            raise OSError(f"SOCKS5: CONNECT отклонён (код {head[1]})")
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            ln = _recv_exact(sock, 1)[0]
            _recv_exact(sock, ln + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        else:
            raise OSError(f"SOCKS5: неизвестный ATYP {atyp}")
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("соединение закрыто досрочно")
        buf += chunk
    return buf


def _https_get(host: str, path: str, timeout: float, via_socks: tuple[str, int] | None,
               port: int = 443, *, read_all: bool = False) -> tuple[str, float]:
    """TLS + GET. Возвращает (ответ, миллисекунды); при любой сетевой беде бросает.

    read_all=False читает один recv — этого хватает на строку статуса и стоит
    меньше всего. read_all=True дочитывает тело: оно нужно проверке утечки.
    """
    t0 = time.monotonic()
    sock = None
    try:
        if via_socks:
            sock = socks5_connect(via_socks[0], via_socks[1], host, port, timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock = tls
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: happ-watchdog\r\nConnection: close\r\nAccept: */*\r\n\r\n")
        tls.sendall(req.encode())
        if not read_all:
            return tls.recv(256).decode("latin-1", "replace"), (time.monotonic() - t0) * 1000
        buf = b""
        while len(buf) < 8192:
            chunk = tls.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace"), (time.monotonic() - t0) * 1000
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def http_probe(host: str, path: str, timeout: float, *, via_socks: tuple[str, int] | None,
               port: int = 443, expect_code: int | None = None) -> tuple[bool, str, float]:
    """TLS + HTTP GET. Возвращает (успех, описание, миллисекунды).

    expect_code задаёт точный ожидаемый ответ: для некоторых адресов «неудобный»
    код и есть признак здоровья. api.anthropic.com на GET / отвечает 404 — если
    вместо него пришло что-то другое, значит в середине кто-то вмешался.
    """
    t0 = time.monotonic()
    try:
        head, ms = _https_get(host, path, timeout, via_socks, port)
        status = head.split("\r\n", 1)[0]
        code = 0
        parts = status.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        if expect_code is not None:
            if code == expect_code:
                return True, f"{code} {host}", ms
            return False, f"{host}: пришло {code}, ожидался {expect_code}", ms
        if code in (200, 204, 301, 302):
            return True, f"{code} {host}", ms
        return False, f"неожиданный ответ: {status[:60]}", ms
    except Exception as exc:  # noqa: BLE001 — любая сетевая беда = проба провалена
        return False, f"{host}: {type(exc).__name__}: {exc}", (time.monotonic() - t0) * 1000


def dns_query(server: str, domain: str, timeout: float) -> tuple[bool, str, float]:
    """Минимальный DNS-запрос A-записи по UDP."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in domain.split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    t0 = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(2048)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
        ms = (time.monotonic() - t0) * 1000
        flags, _, ancount = struct.unpack(">HHH", data[2:8])
        rcode = flags & 0x0F
        if rcode != 0:
            return False, f"{domain}@{server}: RCODE={rcode}", ms
        if ancount == 0:
            return False, f"{domain}@{server}: пустой ответ", ms
        ip = _first_a_record(data)
        return True, f"{domain}→{ip or '?'} ({server})", ms
    except Exception as exc:  # noqa: BLE001
        return False, f"{domain}@{server}: {type(exc).__name__}", (time.monotonic() - t0) * 1000
    finally:
        sock.close()


def _first_a_record(data: bytes) -> str | None:
    try:
        pos = 12
        while data[pos] != 0:            # пропускаем QNAME
            if data[pos] & 0xC0:
                pos += 1
                break
            pos += data[pos] + 1
        pos += 5                          # нулевой байт + QTYPE + QCLASS
        ancount = struct.unpack(">H", data[6:8])[0]
        for _ in range(ancount):
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(data[pos:pos + 4])
            pos += rdlen
    except (IndexError, struct.error):
        return None
    return None


def tcp_ping(host: str, port: int, timeout: float) -> tuple[float | None, str]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.monotonic() - t0) * 1000, "ok"
    except ConnectionRefusedError:
        # хост жив, порт закрыт — для проверки достижимости шлюза этого достаточно
        return (time.monotonic() - t0) * 1000, "refused"
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__


# --------------------------------------------------------------------------
# состояние системы: маршруты, процессы, интерфейсы
# --------------------------------------------------------------------------

def default_route() -> tuple[str, str] | None:
    """(интерфейс, IP шлюза) из /proc/net/route — без внешних команд."""
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return None
    best = None
    for line in lines:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000":
            continue
        metric = int(f[6])
        gw = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
        if best is None or metric < best[0]:
            best = (metric, f[0], gw)
    return (best[1], best[2]) if best else None


def iface_addr(name: str) -> str | None:
    """IPv4 интерфейса без netifaces — через ioctl."""
    import fcntl
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = fcntl.ioctl(sock.fileno(), 0x8915,  # SIOCGIFADDR
                             struct.pack("256s", name[:15].encode()))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def iface_up(name: str) -> bool:
    try:
        return Path(f"/sys/class/net/{name}/operstate").read_text().strip() in ("up", "unknown")
    except OSError:
        return False


def pids_matching(needle: str) -> list[int]:
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if needle in cmdline:
            found.append(int(entry.name))
    return found


def _parse_proc_net_tcp(path: str, v6: bool) -> dict[str, tuple[str, int, str]]:
    """inode -> (удалённый IP, порт, состояние)."""
    out: dict[str, tuple[str, int, str]] = {}
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        f = line.split()
        if len(f) < 10:
            continue
        rem, state, inode = f[2], f[3], f[9]
        addr_hex, port_hex = rem.split(":")
        port = int(port_hex, 16)
        if v6:
            raw = binascii.unhexlify(addr_hex)
            grouped = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            ip = socket.inet_ntop(socket.AF_INET6, grouped)
            if ip.startswith("::ffff:"):
                ip = ip[7:]
        else:
            ip = socket.inet_ntoa(struct.pack("<I", int(addr_hex, 16)))
        out[inode] = (ip, port, state)
    return out


def _xray_conn_counts() -> dict[tuple[str, int], int]:
    """Сколько установленных соединений xray держит к каждому удалённому адресу."""
    pids = pids_matching(XRAY_PATH_HINT)
    counts: dict[tuple[str, int], int] = {}
    if not pids:
        return counts
    inode_map = _parse_proc_net_tcp("/proc/net/tcp", False)
    inode_map.update(_parse_proc_net_tcp("/proc/net/tcp6", True))
    for pid in pids:
        try:
            fds = list(Path(f"/proc/{pid}/fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            m = re.match(r"socket:\[(\d+)\]", target)
            if not m:
                continue
            entry = inode_map.get(m.group(1))
            if not entry:
                continue
            ip, port, state = entry
            if state != "01":                      # только ESTABLISHED
                continue
            if ip.startswith(("127.", "0.0.0.0")) or ip == "::1":
                continue
            counts[(ip, port)] = counts.get((ip, port), 0) + 1
    return counts


def xray_endpoints(min_share: float = 0.5, min_conns: int = 2,
                   settle: float = 1.5) -> list[tuple[str, int]]:
    """Активный сервер VPN по соединениям xray.

    xray ходит и напрямую (правила роутинга «direct»), поэтому одних только
    удалённых адресов мало. Берём два замера с паузой и оставляем адреса,
    которые держатся в обоих и собирают заметную долю всех соединений —
    так отсеиваются разовые прямые коннекты к сайтам.
    """
    first = _xray_conn_counts()
    if not first:
        return []
    time.sleep(settle)
    second = _xray_conn_counts()
    stable = {ep: min(n, second.get(ep, 0)) for ep, n in first.items()}
    stable = {ep: n for ep, n in stable.items() if n > 0}
    if not stable:
        return []
    top = max(stable.values())
    cutoff = max(min_conns, top * min_share)
    return sorted(ep for ep, n in stable.items() if n >= cutoff)


# --------------------------------------------------------------------------
# управление Happ
# --------------------------------------------------------------------------

def session_env() -> dict[str, str]:
    """Окружение для запуска Happ с живым XAUTHORITY.

    В Wayland-сессии он указывает на файл вида
    `/run/user/1000/.mutter-Xwaylandauth.XXXXXX`, имя которого генерируется
    заново при каждом входе. Замороженный в юните путь протухает после
    перезагрузки, и deeplink рискует не дойти до графического Happ — поэтому
    ищем файл в рантайме, а не полагаемся на переменную из юнита.
    """
    env = dict(os.environ)
    current = env.get("XAUTHORITY")
    if current and Path(current).exists():
        return env

    runtime = Path(env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
    candidates = [HOME / ".Xauthority"]
    try:
        candidates += list(runtime.glob(".mutter-Xwaylandauth*"))
    except OSError:
        pass
    alive = []
    for path in candidates:
        try:
            alive.append((path.stat().st_mtime, path))
        except OSError:
            continue
    if alive:
        env["XAUTHORITY"] = str(max(alive)[1])       # самый свежий — от текущей сессии
    else:
        env.pop("XAUTHORITY", None)                  # мёртвый путь хуже отсутствующего
    return env


class Happ:
    def __init__(self, cfg: dict, stop: threading.Event | None = None):
        self.binary = cfg["happ"]["binary"]
        self.cfg = cfg
        # Событие остановки: все ожидания идут через него, иначе SIGTERM не
        # прерывает паузы и systemd добивает сторожа по TimeoutStopSec.
        self.stop = stop or threading.Event()

    def deeplink(self, link: str, timeout: float = 20.0) -> bool:
        if self.stop.is_set():
            return False                 # сторожа останавливают — не дёргаем Happ
        if not Path(self.binary).exists():
            log(f"не найден бинарник Happ: {self.binary}", level="error")
            return False
        try:
            proc = subprocess.run([self.binary, link], timeout=timeout, check=False,
                                  env=session_env(),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            log(f"deeplink {link} завис (>{timeout:.0f} с)", level="warn")
            return False
        except OSError as exc:
            log(f"deeplink {link} не запустился: {exc}", level="error")
            return False

    def connect(self) -> bool:
        return self.deeplink("happ://connect")

    def disconnect(self) -> bool:
        return self.deeplink("happ://disconnect")

    def gui_running(self) -> bool:
        return bool([p for p in pids_matching(self.binary) if p != os.getpid()])

    def restart_gui(self) -> bool:
        pids = pids_matching(self.binary)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and pids_matching(self.binary):
            if self.stop.wait(0.5):
                return False
        for pid in pids_matching(self.binary):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if self.stop.wait(1.5):
            return False
        try:
            subprocess.Popen(["setsid", self.binary], env=session_env(),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        except OSError as exc:
            log(f"не удалось запустить Happ: {exc}", level="error")
            return False
        self.stop.wait(6)
        return self.gui_running()

    def restart_daemon(self) -> bool:
        service = self.cfg["recovery"]["daemon_service"]
        try:
            proc = subprocess.run(["sudo", "-n", "systemctl", "restart", service],
                                  timeout=30, check=False,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"перезапуск {service} не удался: {exc}", level="error")
            return False
        if proc.returncode != 0:
            log(f"перезапуск {service} отклонён (нужен беспарольный sudo)", level="warn")
            return False
        self.stop.wait(3)
        return True


# --------------------------------------------------------------------------
# проверки здоровья
# --------------------------------------------------------------------------

@dataclass
class Health:
    checks: list[Check] = field(default_factory=list)
    uplink_down: bool = False

    @property
    def ok(self) -> bool:
        return all(ch.ok for ch in self.checks if ch.critical)

    @property
    def failed(self) -> list[Check]:
        return [ch for ch in self.checks if not ch.ok and ch.critical]

    def reason(self) -> str:
        return "; ".join(f"{ch.name}: {ch.detail}" for ch in self.failed) or "все проверки прошли"


def _parallel(tasks: list) -> list:
    """Выполнить независимые пробы одновременно, вернув результаты по порядку.

    Пробы ждут сетевых таймаутов, а не процессора, поэтому последовательный
    прогон складывает таймауты в одно длинное окно: при мёртвом туннеле цикл
    растягивался на минуты, и сторож замечал сбой много позже, чем через
    `interval`. Параллельно цикл длится столько, сколько самая медленная проба,
    а не столько, сколько все они вместе.
    """
    if not tasks:
        return []
    if len(tasks) == 1:
        return [tasks[0]()]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(task) for task in tasks]
        return [f.result() for f in futures]


def resolve_with_timeout(domain: str, timeout: float) -> str | None:
    """`getaddrinfo` в отдельном потоке.

    `socket.setdefaulttimeout` на него не действует, а системный резолвер при
    недоступном DNS думает по своим правилам из `resolv.conf` — до десятков
    секунд. Именно он раздувал цикл проверок больше всего.
    """
    result: list[str] = []

    def worker() -> None:
        try:
            result.append(socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0])
        except (OSError, IndexError):
            pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    return result[0] if result else None


def check_uplink(cfg: dict) -> Check:
    route = default_route()
    if route is None:
        return Check("Аплинк (физическая сеть)", False, "нет маршрута по умолчанию")
    iface, gw = route
    if not iface_up(iface):
        return Check("Аплинк (физическая сеть)", False, f"{iface}: нет линка")
    timeout = float(cfg["uplink"]["timeout"])
    ports = [int(p) for p in cfg["uplink"]["gateway_ports"]]
    for ms, status in _parallel([partial(tcp_ping, gw, port, timeout) for port in ports]):
        if ms is not None:
            return Check("Аплинк (физическая сеть)", True, f"{iface} → {gw} ({status})", ms)
    if shutil.which("ping"):
        t0 = time.monotonic()
        rc = subprocess.run(["ping", "-c", "1", "-W", "2", "-n", gw], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc == 0:
            return Check("Аплинк (физическая сеть)", True, f"{iface} → {gw} (icmp)",
                         (time.monotonic() - t0) * 1000)
    return Check("Аплинк (физическая сеть)", False, f"{iface}: шлюз {gw} недоступен")


def check_processes(cfg: dict) -> Check:
    xray = pids_matching(XRAY_PATH_HINT)
    singbox = pids_matching(SINGBOX_PATH_HINT)
    tun_name = cfg["happ"]["tun_interface"]
    tun_ip = iface_addr(tun_name) if iface_exists(tun_name) else None

    problems = []
    if not xray:
        problems.append("ядро xray не запущено")
    if cfg["happ"]["require_singbox"] and not singbox:
        problems.append("sing-box (tun) не запущен")
    if cfg["happ"]["require_tun"] and not tun_ip:
        problems.append(f"интерфейс {tun_name} отсутствует")

    detail = (f"xray={xray[0] if xray else '-'} sing-box={singbox[0] if singbox else '-'} "
              f"{tun_name}={tun_ip or '-'}")
    if problems:
        return Check("Процессы и туннель", False, ", ".join(problems))
    return Check("Процессы и туннель", True, detail)


def check_proxy(cfg: dict, *, via_socks: bool) -> Check:
    hosts = list(cfg["checks"]["probe_hosts"])
    random.shuffle(hosts)
    quorum = int(cfg["checks"]["probe_quorum"])
    timeout = float(cfg["checks"]["tcp_timeout"])
    proxy = (cfg["happ"]["socks_host"], int(cfg["happ"]["socks_port"])) if via_socks else None
    name = (f"SOCKS {cfg['happ']['socks_host']}:{cfg['happ']['socks_port']}" if via_socks
            else "Системный путь (через tun)")

    results = _parallel([partial(http_probe, host, cfg["checks"]["probe_path"], timeout,
                                 via_socks=proxy) for host in hosts])

    passed, best_ms, errors, first_ok = 0, None, [], None
    for ok, detail, ms in results:
        if ok:
            passed += 1
            first_ok = first_ok or detail
            if ms is not None:
                best_ms = ms if best_ms is None else min(best_ms, ms)
        else:
            errors.append(detail)
    if passed >= quorum:
        return Check(name, True, first_ok, best_ms)
    return Check(name, False, "; ".join(errors[:2]) or "нет ответа", best_ms)


def check_dns(cfg: dict) -> Check:
    domains = list(cfg["checks"]["dns_domains"])
    servers = list(cfg["checks"]["dns_servers"])
    timeout = float(cfg["checks"]["dns_timeout"])
    if not domains:
        return Check("DNS", True, "проверка выключена в конфиге", critical=False)
    probes = [(server, domain) for server in servers for domain in domains]
    errors = []
    for ok, detail, ms in _parallel([partial(dns_query, s, d, timeout) for s, d in probes]):
        if ok:
            return Check("DNS", True, detail, ms)
        errors.append(detail)
    # запасной путь — системный резолвер (может ходить мимо DNS туннеля)
    t0 = time.monotonic()
    addr = resolve_with_timeout(domains[0], timeout)
    if addr:
        return Check("DNS", True, f"{domains[0]}→{addr} (системный резолвер)",
                     (time.monotonic() - t0) * 1000)
    return Check("DNS", False, "; ".join(errors[:2]) or "нет ответа")


def system_resolvers() -> list[str]:
    """Резолверы из /etc/resolv.conf — тот самый путь, которым ходит браузер."""
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                servers.append(parts[1])
    except OSError:
        pass
    return servers


def check_system_dns(cfg: dict) -> Check:
    """Резолвится ли через системный резолвер домен, который режет провайдер.

    Ровно эта проверка ловит поломку, из-за которой в браузере «ничего не
    работает» при живом туннеле: если DNS уходит мимо VPN, цензурируемые имена
    не резолвятся, хотя curl к нецензурируемым адресам отвечает как ни в чём
    не бывало.
    """
    domains = list(cfg["checks"]["system_dns_domains"])
    if not domains:
        return Check("Системный DNS (браузер)", True, "проверка выключена", critical=False)
    servers = system_resolvers()
    if not servers:
        return Check("Системный DNS (браузер)", True, "резолверы не определены", critical=False)
    timeout = float(cfg["checks"]["dns_timeout"])
    errors = []
    for ok, detail, ms in _parallel([partial(dns_query, servers[0], d, timeout)
                                     for d in domains]):
        if ok:
            return Check("Системный DNS (браузер)", True, detail, ms)
        errors.append(detail)
    return Check("Системный DNS (браузер)", False,
                 "; ".join(errors[:2]) + " — похоже, DNS идёт мимо туннеля")


def exit_ip(cfg: dict, *, via_socks: bool) -> tuple[str | None, str]:
    """Внешний IP, каким его видит сервер, — по SOCKS или по системному маршруту."""
    host = cfg["checks"]["leak_host"]
    path = cfg["checks"]["leak_path"]
    timeout = float(cfg["checks"]["tcp_timeout"])
    proxy = (cfg["happ"]["socks_host"], int(cfg["happ"]["socks_port"])) if via_socks else None
    try:
        body, _ = _https_get(host, path, timeout, proxy, read_all=True)
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"
    for line in body.splitlines():
        if line.startswith("ip="):
            return line[3:].strip(), ""
    return None, "в ответе нет строки ip="


def ip_prefix(ip: str) -> str:
    """Сеть, в которой живёт адрес: /24 для IPv4, /48 для IPv6.

    Провайдер VPN может выпускать трафик через пул соседних адресов, и точное
    сравнение дало бы ложную тревогу. Утечка же выглядит совсем иначе — адрес
    оказывается из сети домашнего провайдера, а это другой префикс.
    """
    if ":" in ip:
        return ":".join(ip.split(":")[:3])
    return ".".join(ip.split(".")[:3])


def check_leak(cfg: dict) -> Check:
    """Один ли выход у SOCKS и у системного маршрута.

    Самая опасная поломка — не «интернета нет», а «интернет есть мимо
    туннеля»: остальные пробы при этом зелёные, ведь 204 приходит одинаково
    что через VPN, что напрямую. Сравнение внешнего IP по двум путям ловит
    именно это и не требует знать адреса провайдера.
    """
    name = "Утечка мимо туннеля"
    if not cfg["checks"]["leak_check"]:
        return Check(name, True, "проверка выключена", critical=False)

    def measure() -> tuple[tuple[str | None, str], tuple[str | None, str]]:
        socks_res, sys_res = _parallel([partial(exit_ip, cfg, via_socks=True),
                                        partial(exit_ip, cfg, via_socks=False)])
        return socks_res, sys_res

    (socks_ip, socks_err), (sys_ip, sys_err) = measure()
    if socks_ip is None or sys_ip is None:
        # Недоступность ловят другие пробы, здесь она означает лишь «не измерили».
        return Check(name, True, f"не удалось измерить (SOCKS: {socks_err or 'ок'}; "
                                 f"система: {sys_err or 'ок'})", critical=False)
    if ip_prefix(socks_ip) == ip_prefix(sys_ip):
        return Check(name, True, f"выход {sys_ip} по обоим путям")

    # Расхождение подтверждаем вторым замером: смена сервера ровно между двумя
    # запросами выглядит так же, а перезапускать VPN из-за неё незачем.
    (socks_ip2, _), (sys_ip2, _) = measure()
    if socks_ip2 and sys_ip2 and ip_prefix(socks_ip2) == ip_prefix(sys_ip2):
        return Check(name, True, f"выход {sys_ip2} по обоим путям (расхождение не подтвердилось)")
    return Check(name, False, f"система выходит через {sys_ip2 or sys_ip}, "
                              f"а туннель через {socks_ip2 or socks_ip} — трафик идёт мимо VPN")


def check_expected(cfg: dict) -> list[Check]:
    """Адреса, у которых здоровьем считается конкретный код ответа."""
    items = list(cfg["checks"]["expect"])
    timeout = float(cfg["checks"]["tcp_timeout"])
    results = _parallel([partial(http_probe, item["host"], item.get("path", "/"), timeout,
                                 via_socks=None, expect_code=int(item["code"]))
                         for item in items])
    return [Check(f"{item['host']} → ждём {int(item['code'])}", ok, detail, ms,
                  critical=bool(item.get("critical", True)))
            for item, (ok, detail, ms) in zip(items, results)]


def check_happ_logs(cfg: dict) -> Check:
    window = int(cfg["checks"]["log_window"])
    threshold = int(cfg["checks"]["log_error_threshold"])
    patterns = [p.lower() for p in cfg["checks"]["log_error_patterns"]]
    cutoff = time.time() - window
    total = 0
    fresh = 0
    seen: list[str] = []
    for log_file in ("tun_log.txt", "core_log.txt", "application_log.txt"):
        path = HAPP_LOG_DIR / log_file
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_mtime < cutoff:
            continue                     # файл не трогали в окне — ошибок нет
        fresh += 1
        for line in _tail_lines(path, 4000):
            low = line.lower()
            if any(p in low for p in patterns):
                total += 1
                if len(seen) < 1:
                    seen.append(line.strip()[:90])
    if total >= threshold:
        return Check("Логи ядра Happ", False,
                     f"{total} ошибок за {window} с — {seen[0] if seen else ''}")
    if not fresh:
        # Happ пишет логи не всегда (и не всякая сборка вообще их пишет).
        # Тогда честнее сказать «нечего смотреть», чем зелёное «0 ошибок».
        return Check("Логи ядра Happ", True, "логи не обновляются — проверка не работает",
                     critical=False)
    return Check("Логи ядра Happ", True, f"{total} ошибок за {window} с", critical=False)


def _tail_lines(path: Path, limit: int) -> list[str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            read_bytes = min(size, limit * 160)
            fh.seek(size - read_bytes)
            data = fh.read()
        return data.decode("utf-8", "replace").splitlines()[-limit:]
    except OSError:
        return []


def _guarded(name: str, task):
    """Проверка, упавшая с исключением, — это баг сторожа, а не диагноз туннелю.

    Раньше такое исключение проходило сквозь run_health и роняло процесс:
    сторож «сам падал», а systemd поднимал его заново. Теперь проверка
    превращается в некритичную запись — VPN из-за ошибки в коде не дёргаем,
    но в журнале это видно каждый раз.
    """
    def run() -> Check:
        try:
            return task()
        except Exception as exc:  # noqa: BLE001 — падать сторож не имеет права
            log(f"проверка «{name}» упала: {type(exc).__name__}: {exc}", level="error")
            return Check(name, False, f"проверка упала: {type(exc).__name__}: {exc}",
                         critical=False)
    return run


def run_health(cfg: dict, *, include_logs: bool = True) -> Health:
    health = Health()
    if cfg["uplink"]["check"]:
        uplink = _guarded("Аплинк (физическая сеть)", partial(check_uplink, cfg))()
        health.checks.append(uplink)
        if not uplink.ok and uplink.critical:
            health.uplink_down = True
            return health                # физической сети нет — VPN дёргать бессмысленно
    # Проверки независимы друг от друга, поэтому идут одновременно: цикл должен
    # укладываться в `interval`, даже когда всё вокруг отвечает таймаутами.
    tasks = [("Процессы и туннель", partial(check_processes, cfg)),
             ("SOCKS", partial(check_proxy, cfg, via_socks=True))]
    if cfg["checks"]["check_direct_path"]:
        tasks.append(("Системный путь (через tun)", partial(check_proxy, cfg, via_socks=False)))
    tasks += [("DNS", partial(check_dns, cfg)),
              ("Системный DNS (браузер)", partial(check_system_dns, cfg)),
              ("Утечка мимо туннеля", partial(check_leak, cfg)),
              ("Ожидаемые коды ответа", partial(check_expected, cfg))]
    if include_logs and cfg["checks"]["scan_logs"]:
        tasks.append(("Логи ядра Happ", partial(check_happ_logs, cfg)))

    for result in _parallel([_guarded(name, task) for name, task in tasks]):
        if isinstance(result, list):      # check_expected возвращает список
            health.checks.extend(result)
        else:
            health.checks.append(result)
    return health


# --------------------------------------------------------------------------
# серверы подписки и их пинг
# --------------------------------------------------------------------------

def parse_server_ref(ref: str) -> tuple[str, int, str] | None:
    """host:port | vless:// | trojan:// | vmess:// | ss:// → (host, port, имя)."""
    ref = ref.strip()
    if not ref:
        return None
    if "://" not in ref:
        if ":" not in ref:
            return None
        host, _, port = ref.rpartition(":")
        return (host, int(port), host) if port.isdigit() else None

    scheme, _, rest = ref.partition("://")
    scheme = scheme.lower()
    try:
        if scheme == "vmess":
            payload = rest.split("#")[0]
            data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
            return str(data["add"]), int(data["port"]), str(data.get("ps") or data["add"])
        parsed = urllib.parse.urlparse(ref)
        name = urllib.parse.unquote(parsed.fragment) or (parsed.hostname or "")
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port, name
        if scheme == "ss":
            # ss://base64(method:pass@host:port)#name
            body = rest.split("#")[0]
            decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
            hostport = decoded.rsplit("@", 1)[-1]
            host, _, port = hostport.rpartition(":")
            return (host, int(port), name or host) if port.isdigit() else None
    except (ValueError, KeyError, binascii.Error, UnicodeDecodeError):
        return None
    return None


def discover_subscription_urls() -> list[str]:
    """Достаёт URL подписок из лога Happ (он пишет их в открытом виде)."""
    urls: list[str] = []
    for line in _tail_lines(HAPP_SUB_LOG, 2000):
        m = re.search(r"starting update from:\s*(\S+)", line)
        if m and m.group(1) not in urls:
            urls.append(m.group(1))
    return urls


SUBS_CACHE_PATH = STATE_DIR / "subscriptions_cache.json"


def _subs_cache() -> dict:
    try:
        return json.loads(SUBS_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def fetch_subscription(url: str, cfg: dict) -> list[tuple[str, int, str]]:
    """Тянет список серверов из подписки. Результат (в т.ч. пустой) кэшируется,
    чтобы не ждать таймаутов на каждом цикле пинга."""
    ttl = float(cfg["servers"].get("subscription_cache_ttl", 3600))
    cache = _subs_cache()
    entry = cache.get(url)
    if entry and time.time() - entry.get("ts", 0) < ttl:
        return [(h, p, n) for h, p, n in entry.get("servers", [])]

    import urllib.request
    headers = {"User-Agent": cfg["servers"]["user_agent"]}
    if cfg["servers"]["hwid"]:
        headers["X-HWID"] = cfg["servers"]["hwid"]
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except Exception as exc:  # noqa: BLE001
        log(f"подписка {mask_url(url)}: {type(exc).__name__}: {exc}", level="warn")
        _store_subs_cache(cache, url, [])
        return []
    text = raw.decode("utf-8", "replace")
    if "://" not in text:
        try:
            text = base64.b64decode(raw + b"=" * (-len(raw) % 4)).decode("utf-8", "replace")
        except (binascii.Error, UnicodeDecodeError):
            _store_subs_cache(cache, url, [])
            return []
    servers = []
    for line in text.splitlines():
        parsed = parse_server_ref(line)
        if parsed and parsed[0] not in ("0.0.0.0", "127.0.0.1") and parsed[1] > 1:
            servers.append(parsed)
    if not servers and "0.0.0.0:1" in text:
        log(f"подписка {mask_url(url)}: провайдер вернул заглушку "
            "(нужен правильный X-HWID) — серверы не получены", level="warn")
    _store_subs_cache(cache, url, servers)
    return servers


def _store_subs_cache(cache: dict, url: str, servers: list[tuple[str, int, str]]) -> None:
    cache[url] = {"ts": time.time(), "servers": [list(s) for s in servers]}
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SUBS_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False))
        SUBS_CACHE_PATH.chmod(0o600)
    except OSError:
        pass


def mask_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/…"


def collect_servers(cfg: dict) -> list[tuple[str, int, str]]:
    servers: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    def add(host: str, port: int, name: str) -> None:
        if (host, port) not in seen:
            seen.add((host, port))
            servers.append((host, port, name))

    for ref in cfg["servers"]["list"]:
        parsed = parse_server_ref(ref)
        if parsed:
            add(*parsed)
        else:
            log(f"не разобрал запись сервера: {ref[:40]}", level="warn")

    urls = list(cfg["servers"]["subscriptions"]) or discover_subscription_urls()
    for url in urls:
        for host, port, name in fetch_subscription(url, cfg):
            add(host, port, name)

    if cfg["servers"]["auto_discover"]:
        endpoints = xray_endpoints(float(cfg["servers"]["discover_min_share"]),
                                   int(cfg["servers"]["discover_min_conns"]))
        for host, port in endpoints:
            add(host, port, "активный сервер VPN (определён автоматически)")
    return servers


@dataclass
class PingResult:
    host: str
    port: int
    name: str
    ms: float | None
    status: str


def ping_servers(cfg: dict) -> list[PingResult]:
    servers = collect_servers(cfg)
    if not servers:
        return []
    timeout = float(cfg["servers"]["ping_timeout"])
    workers = max(1, int(cfg["servers"]["ping_concurrency"]))

    def worker(item: tuple[str, int, str]) -> PingResult:
        host, port, name = item
        ms, status = tcp_ping(host, port, timeout)
        return PingResult(host, port, name, ms, status)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(worker, servers))
    results.sort(key=lambda r: (r.ms is None, r.ms or 0))
    return results


# --------------------------------------------------------------------------
# восстановление
# --------------------------------------------------------------------------

LOCK_PATH = STATE_DIR / "run.lock"


class AlreadyRunning(RuntimeError):
    def __init__(self, pid: str):
        super().__init__(pid)
        self.pid = pid


def acquire_run_lock():
    """Один сторож на систему. Два экземпляра дерутся между собой: пока один
    делает disconnect, второй уже подключает — VPN разваливается, а общий лимит
    перезапусков выгорает за пару минут."""
    import fcntl
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    handle = LOCK_PATH.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.seek(0)
        owner = handle.read().strip() or "?"
        handle.close()
        raise AlreadyRunning(owner) from None
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle                       # держим открытым до конца процесса


PAUSE_PATH = STATE_DIR / "paused_until"


def paused_until() -> float:
    """Время, до которого сторож не вмешивается (0 — не на паузе)."""
    try:
        until = float(PAUSE_PATH.read_text().strip())
    except (OSError, ValueError):
        return 0.0
    if until <= time.time():
        PAUSE_PATH.unlink(missing_ok=True)
        return 0.0
    return until


def set_pause(seconds: float) -> float:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    until = time.time() + seconds
    PAUSE_PATH.write_text(str(until))
    return until


def parse_duration(text: str) -> float:
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", text.strip().lower())
    if not m:
        raise ValueError(f"не понял длительность: {text}")
    value = int(m.group(1))
    return value * {"": 60, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def geo_selfcheck(cfg: dict, *, apply_fix: bool = True) -> list[str]:
    """Проверяет geo-файлы профилей маршрутизации и при необходимости чинит их.

    Урезанный geosite.dat профиля — причина, по которой xray молча не стартует
    на части серверов подписки. Happ обновляет эти файлы по своему расписанию,
    поэтому проверку приходится повторять, а не делать один раз руками.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import happ_fix_geo as geo
    except ImportError:
        log("рядом нет happ_fix_geo.py — проверка geo-файлов пропущена", level="warn")
        return []

    required = {code.upper() for code in cfg["geo"]["required_codes"]}
    messages: list[str] = []
    for profile in geo.active_profiles(None):
        broken_reason = None
        target = profile / "geosite.dat"
        if not target.exists():
            broken_reason = "geosite.dat отсутствует"
        else:
            entries, truncated = geo.parse_entries(target)
            codes = {code for code, _ in entries}
            missing = sorted(required - codes)
            if truncated:
                broken_reason = "geosite.dat обрезан"
            elif missing:
                broken_reason = "нет кодов " + ", ".join(missing[:4])
        if not broken_reason:
            continue

        messages.append(f"{profile.name}: {broken_reason}")
        if not apply_fix:
            continue
        added = 0
        for name in ("geosite.dat", "geoip.dat"):
            path = profile / name
            vanilla = geo.VANILLA_DIR / name
            if not vanilla.exists():
                continue
            if not path.exists():
                shutil.copy2(vanilla, path)
                added += 1
                continue
            report = geo.merge_file(path, vanilla, dry_run=False)
            added += report["added"]
        log(f"geo-файлы профиля «{profile.name}» починены ({broken_reason}), "
            f"добавлено записей: {added}", level="ok")
    return messages


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {"restarts": [], "last_status": "unknown", "last_check": 0, "ladder": 0}


def save_state(state: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    except OSError:
        pass


class Recovery:
    def __init__(self, cfg: dict, happ: Happ, state: dict,
                 stop: threading.Event | None = None):
        self.cfg = cfg
        self.happ = happ
        self.state = state
        self.stop = stop or threading.Event()

    def escalations_limited(self) -> bool:
        """Квота считается только для разрушительных шагов — они убивают процесс
        Happ или демон, и крутить это по кругу вредно. Мягкие переподключения не
        ограничены ничем: сторож не имеет права опустить руки и оставить VPN
        лежать — ради этого он и написан."""
        limit = int(self.cfg["recovery"]["max_escalations_per_hour"])
        cutoff = time.time() - 3600
        self.state["escalations"] = [t for t in self.state.get("escalations", []) if t > cutoff]
        return len(self.state["escalations"]) >= limit

    def plan(self, ladder: int) -> tuple[str, str]:
        """Ступень лестницы → (вид шага, человеческое название)."""
        if ladder == 0:
            return "soft", "мягкое переподключение (happ://connect)"
        if ladder == 1:
            return "cycle", "полный цикл disconnect → connect"
        if ladder == 2 and self.cfg["recovery"]["allow_gui_restart"]:
            return "gui", "перезапуск процесса Happ"
        if ladder == 3 and self.cfg["recovery"]["allow_daemon_restart"]:
            return "daemon", "перезапуск демона happd"
        return "cycle", "повторный цикл disconnect → connect"

    def perform(self, reason: str) -> bool:
        if self.stop.is_set():
            return False                 # сторожа останавливают — не начинаем лечение
        ladder = int(self.state.get("ladder", 0))
        kind, step = self.plan(ladder)

        if kind in ("gui", "daemon") and self.escalations_limited():
            kind, step = "cycle", "повторный цикл disconnect → connect"
            if not self.state.get("escalation_notice"):
                log("квота жёстких перезапусков исчерпана "
                    f"({self.cfg['recovery']['max_escalations_per_hour']}/час) — "
                    "процесс Happ больше не трогаю, продолжаю мягкими попытками",
                    level="warn")
                self.state["escalation_notice"] = True

        # История нужна только за последние сутки: без чистки список рос вечно.
        cutoff = time.time() - 86400
        self.state["restarts"] = [t for t in self.state.get("restarts", []) if t > cutoff]
        self.state["restarts"].append(time.time())
        if kind in ("gui", "daemon"):
            self.state.setdefault("escalations", []).append(time.time())
        save_state(self.state)

        log(f"VPN сбоит: {reason} → {step}",
            level="error" if kind in ("gui", "daemon") else "warn")

        if kind == "soft":
            self.happ.connect()
        elif kind == "cycle":
            self.happ.disconnect()
            self.stop.wait(3)
            self.happ.connect()
        elif kind == "gui":
            self.happ.disconnect()
            self.stop.wait(2)
            self.happ.restart_gui()
            self.stop.wait(2)
            self.happ.connect()
        else:
            self.happ.restart_daemon()
            self.happ.restart_gui()
            self.stop.wait(2)
            self.happ.connect()

        recovered = self.verify()
        if recovered:
            log(f"VPN восстановлен после «{step}»", level="ok")
            if self.cfg["general"]["notify"]:
                notify("Happ: связь восстановлена", f"{step}\nПричина сбоя: {reason[:120]}")
            self.state["ladder"] = 0
            self.state["escalation_notice"] = False
        else:
            self.state["ladder"] = ladder + 1
            pause = self.next_pause(ladder)
            log(f"после «{step}» связи нет, следующая попытка через {pause:.0f} с",
                level="error")
            if self.cfg["general"]["notify"] and ladder == 1:
                notify("Happ: VPN не поднимается", reason[:160], urgency="critical")
            self.stop.wait(pause)
        save_state(self.state)
        return recovered

    def next_pause(self, ladder: int) -> float:
        """Пока лестница не пройдена — короткие паузы из backoff. Дальше сторож
        переходит в редкий фоновый режим: сбой явно не лечится перезапуском,
        долбить каждые полминуты бессмысленно, но и бросать нельзя."""
        backoff = self.cfg["recovery"]["backoff"]
        if ladder < len(backoff):
            return float(backoff[ladder])
        return float(self.cfg["recovery"]["soft_retry_interval"])

    def verify(self) -> bool:
        deadline = time.monotonic() + float(self.cfg["general"]["verify_timeout"])
        while time.monotonic() < deadline:
            if self.stop.wait(3):
                return False             # остановка важнее: дождёмся следующего запуска
            health = run_health(self.cfg, include_logs=False)
            if health.ok:
                return True
        return False


# --------------------------------------------------------------------------
# команды CLI
# --------------------------------------------------------------------------

def cmd_check(cfg: dict, args: argparse.Namespace) -> int:
    health = run_health(cfg)
    print(c(f"\n  Проверка Happ — {time.strftime('%H:%M:%S')}\n", "bold"))
    for check in health.checks:
        print(check.line())
    try:
        geo_problems = geo_selfcheck(cfg, apply_fix=False)
    except Exception:  # noqa: BLE001
        geo_problems = []
    geo_check = Check("Geo-файлы маршрутизации", not geo_problems,
                      "; ".join(geo_problems) if geo_problems
                      else "все нужные коды на месте", critical=False)
    print(geo_check.line())
    if geo_problems:
        print("      " + c("почините: happ-fix-geo fix", "yellow"))
    if health.uplink_down:
        print("\n  " + c("НЕТ ФИЗИЧЕСКОЙ СЕТИ", "yellow") + " — VPN перезапускать бесполезно\n")
        return 3
    if health.ok:
        print("\n  Итог: " + c("ЗДОРОВ", "green") + "\n")
        return 0
    print("\n  Итог: " + c("СБОЙ", "red") + " — " + health.reason() + "\n")
    return 1


def cmd_ping(cfg: dict, args: argparse.Namespace) -> int:
    tun_up = iface_exists(cfg["happ"]["tun_interface"])
    via = "через активный туннель" if tun_up else "напрямую"
    print(c(f"\n  Пинг серверов ({via})\n", "bold"))
    results = ping_servers(cfg)
    if not results:
        print("  Серверы не найдены. Добавьте их в [servers] list в "
              f"{CONFIG_PATH}\n  (host:port или ссылки vless:// / vmess:// / trojan:// / ss://)\n")
        return 1
    alive = 0
    for r in results:
        if r.ms is not None:
            alive += 1
            mark = c("OK  ", "green")
            lat = f"{r.ms:7.0f} ms"
        else:
            mark = c("СБОЙ", "red")
            lat = f"{r.status:>10}"
        endpoint = f"{r.host}:{r.port}"
        print(f"  {mark} {lat}  {endpoint:<24} {r.name[:52]}")
    print(f"\n  Живых: {alive} из {len(results)}\n")
    return 0 if alive else 2


def cmd_restart(cfg: dict, args: argparse.Namespace) -> int:
    happ = Happ(cfg)
    log("принудительный перезапуск VPN по команде", level="info")
    happ.disconnect()
    time.sleep(3)
    happ.connect()
    deadline = time.monotonic() + float(cfg["general"]["verify_timeout"])
    while time.monotonic() < deadline:
        time.sleep(3)
        if run_health(cfg, include_logs=False).ok:
            print("  " + c("VPN поднят", "green"))
            return 0
    print("  " + c("VPN не поднялся за отведённое время", "red"))
    return 1


def cmd_pause(cfg: dict, args: argparse.Namespace) -> int:
    try:
        seconds = parse_duration(args.duration)
    except ValueError as exc:
        print(f"  {exc}")
        return 2
    until = set_pause(seconds)
    stamp = time.strftime("%H:%M:%S", time.localtime(until))
    print(f"  Сторож на паузе до {stamp} (снять: happ-watchdog resume)")
    log(f"пауза до {stamp} по команде", level="info", echo=False)
    return 0


def cmd_resume(cfg: dict, args: argparse.Namespace) -> int:
    PAUSE_PATH.unlink(missing_ok=True)
    print("  Сторож снова активен")
    log("пауза снята по команде", level="info", echo=False)
    return 0


def cmd_status(cfg: dict, args: argparse.Namespace) -> int:
    state = load_state()
    cutoff = time.time() - 3600
    recent = [t for t in state.get("restarts", []) if t > cutoff]
    hard = [t for t in state.get("escalations", []) if t > cutoff]
    last_check = state.get("last_check", 0)
    print(c("\n  happ-watchdog\n", "bold"))
    pause_end = paused_until()
    if pause_end:
        print("  " + c(f"НА ПАУЗЕ до {time.strftime('%H:%M:%S', time.localtime(pause_end))}", "yellow"))
    print(f"  Последняя проверка : {time.strftime('%H:%M:%S', time.localtime(last_check)) if last_check else '—'}")
    print(f"  Последний статус   : {state.get('last_status', '—')}")
    print(f"  Перезапусков за час: {len(recent)} (без лимита)")
    print(f"  Из них жёстких     : {len(hard)} / {cfg['recovery']['max_escalations_per_hour']}")
    print(f"  Ступень эскалации  : {state.get('ladder', 0)}")
    print(f"  Конфиг             : {CONFIG_PATH}")
    print(f"  Журнал             : {LOG_PATH}")
    unit = Path.home() / ".config/systemd/user/happ-watchdog.service"
    if unit.exists():
        active = subprocess.run(["systemctl", "--user", "is-active", "happ-watchdog"],
                                capture_output=True, text=True, check=False).stdout.strip()
        print(f"  Служба systemd     : {active}")
    print()
    return 0


def cmd_run(cfg: dict, args: argparse.Namespace) -> int:
    try:
        lock = acquire_run_lock()
    except AlreadyRunning as exc:
        service = subprocess.run(["systemctl", "--user", "is-active", "happ-watchdog"],
                                 capture_output=True, text=True, check=False).stdout.strip()
        print(c(f"  Сторож уже работает (pid {exc.pid})", "yellow"))
        if service == "active":
            print("  Это служба systemd. Смотреть: journalctl --user -u happ-watchdog -f")
            print("  Остановить:              systemctl --user stop happ-watchdog")
        print("  Второй экземпляр запускать нельзя: они будут дёргать VPN наперегонки.")
        return 1

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    happ = Happ(cfg, stop)
    state = load_state()
    state["ladder"] = 0
    recovery = Recovery(cfg, happ, state, stop)
    interval = float(cfg["general"]["interval"])
    threshold = int(cfg["general"]["failures_before_restart"])
    startup_grace = float(cfg["general"]["startup_grace"])
    ping_interval = float(cfg["servers"]["ping_interval"])
    quiet = bool(cfg["general"]["quiet_when_healthy"])

    log(f"{APP} {VERSION} запущен: интервал {interval:.0f} с, "
        f"порог {threshold} сбоя(ев), конфиг {args.config}", level="info")

    fails = 0
    last_status = None
    gui_absent = False           # видели ли мы Happ выключенным
    grace_until = 0.0            # до этого момента Happ считается поднимающимся
    next_ping = time.monotonic() + 5 if ping_interval > 0 else float("inf")
    geo_interval = float(cfg["geo"]["check_interval"]) if cfg["geo"]["autofix"] else 0
    next_geo = time.monotonic() if geo_interval > 0 else float("inf")

    while not stop.is_set():
        started = time.monotonic()

        pause_end = paused_until()
        if pause_end:
            status = "пауза"
            if last_status != status:
                log("сторож на паузе до "
                    + time.strftime("%H:%M:%S", time.localtime(pause_end)), level="info")
            last_status = status
            state["last_status"] = status
            state["last_check"] = time.time()
            save_state(state)
            stop.wait(min(interval, max(1.0, pause_end - time.time())))
            continue

        if cfg["general"]["only_when_gui_running"] and not happ.gui_running():
            fails = 0
            gui_absent = True
            status = "Happ не запущен"
            if last_status != status:
                log("Happ не запущен — считаю, что VPN выключен намеренно, не вмешиваюсь",
                    level="info")
            last_status = status
            state["last_status"] = status
            save_state(state)
            stop.wait(interval)
            continue

        if gui_absent:
            # Happ только что подняли: ядро и tun появляются секунд за двадцать,
            # и дёргать connect в этот момент — драться с его же запуском.
            gui_absent = False
            grace_until = time.monotonic() + startup_grace
            fails = 0
            log(f"Happ запущен — даю {startup_grace:.0f} с на подъём туннеля", level="info")

        health = run_health(cfg)
        state["last_check"] = time.time()

        if health.uplink_down:
            fails = 0
            status = "нет физической сети"
            if last_status != status:
                log("нет физической сети — жду восстановления аплинка, VPN не трогаю",
                    level="warn")
        elif health.ok:
            if fails:
                log("связь восстановилась сама, счётчик сбоев сброшен", level="ok")
            fails = 0
            state["ladder"] = 0
            status = "здоров"
            if not quiet:
                log("проверка пройдена: " + " | ".join(
                    f"{ch.name}={ch.ms:.0f}ms" if ch.ms else ch.name
                    for ch in health.checks if ch.ok), level="info")
        elif time.monotonic() < grace_until:
            status = "запуск Happ"
            if last_status != status:
                log(f"Happ поднимается, сбои не считаю: {health.reason()}", level="info")
        else:
            fails += 1
            status = "сбой"
            log(f"сбой {fails}/{threshold}: {health.reason()}", level="warn")
            if fails >= threshold:
                recovery.perform(health.reason())
                fails = 0

        last_status = status
        state["last_status"] = status
        save_state(state)

        if stop.is_set():
            break            # дальше идут долгие фоновые задачи — они подождут до запуска

        if time.monotonic() >= next_geo:
            next_geo = time.monotonic() + geo_interval
            try:
                geo_selfcheck(cfg)
            except Exception as exc:  # noqa: BLE001 — сторож не должен падать из-за этого
                log(f"проверка geo-файлов не удалась: {type(exc).__name__}: {exc}", level="warn")

        if stop.is_set():
            break

        if time.monotonic() >= next_ping:
            next_ping = time.monotonic() + ping_interval
            results = ping_servers(cfg)
            if results:
                alive = [r for r in results if r.ms is not None]
                log(f"пинг серверов: живых {len(alive)}/{len(results)}"
                    + (f", лучший {alive[0].host}:{alive[0].port} {alive[0].ms:.0f} ms"
                       if alive else ""), level="info")
                if (cfg["servers"]["restart_if_active_server_dead"] and results
                        and not alive and not health.uplink_down):
                    log("ни один сервер не отвечает — принудительное переподключение",
                        level="error")
                    recovery.perform("ни один сервер подписки не отвечает")

        elapsed = time.monotonic() - started
        if elapsed > interval * 1.5:
            # Раньше это было нормой: последовательные пробы складывали таймауты,
            # и между проверками проходили минуты вместо `interval`.
            log(f"цикл проверок занял {elapsed:.0f} с при интервале {interval:.0f} с",
                level="warn")
        stop.wait(max(1.0, interval - elapsed))

    log("остановлен", level="info")
    lock.close()
    return 0


SERVICE_TEMPLATE = """\
[Unit]
Description=Happ VPN watchdog — автоматический перезапуск при сбоях
After=graphical-session.target network-online.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart={python} {script} run
Restart=always
RestartSec=10
TimeoutStopSec=30
{environment}

[Install]
WantedBy=default.target
"""


def cmd_install_service(cfg: dict, args: argparse.Namespace) -> int:
    unit_dir = Path.home() / ".config/systemd/user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "happ-watchdog.service"

    # Deeplink-ам Happ нужна сессия пользователя — прокидываем её переменные.
    # XAUTHORITY сюда не входит намеренно: путь к нему меняется при каждом входе
    # в сессию, поэтому его ищет session_env() перед самым запуском Happ.
    passthrough = ["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
                   "DBUS_SESSION_BUS_ADDRESS", "QT_QPA_PLATFORM"]
    env_lines = [f'Environment="{key}={os.environ[key]}"' for key in passthrough if os.environ.get(key)]

    unit_path.write_text(SERVICE_TEMPLATE.format(
        python=sys.executable,
        script=Path(__file__).resolve(),
        environment="\n".join(env_lines),
    ), encoding="utf-8")

    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", "happ-watchdog"], check=False)
    print(f"  Служба установлена: {unit_path}")
    print("  Логи:    journalctl --user -u happ-watchdog -f")
    print(f"  Или:     tail -f {LOG_PATH}")
    return 0


def cmd_uninstall_service(cfg: dict, args: argparse.Namespace) -> int:
    subprocess.run(["systemctl", "--user", "disable", "--now", "happ-watchdog"], check=False)
    unit_path = Path.home() / ".config/systemd/user/happ-watchdog.service"
    unit_path.unlink(missing_ok=True)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print("  Служба удалена")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="happ-watchdog",
        description="Сторож Happ VPN: пингует серверы, следит за туннелем, DNS и логами, "
                    "автоматически переподключает VPN при любой ошибке.")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH, help="путь к config.toml")
    parser.add_argument("--version", action="version", version=f"{APP} {VERSION}")
    sub = parser.add_subparsers(dest="command")

    commands = {
        "run": (cmd_run, "постоянный мониторинг с автоперезапуском"),
        "check": (cmd_check, "разовая диагностика туннеля"),
        "ping": (cmd_ping, "пинг всех известных серверов"),
        "restart": (cmd_restart, "принудительно переподключить VPN"),
        "status": (cmd_status, "состояние сторожа"),
        "pause": (cmd_pause, "не вмешиваться какое-то время (например: pause 30m)"),
        "resume": (cmd_resume, "снять паузу"),
        "install-service": (cmd_install_service, "поставить автозапуск через systemd --user"),
        "uninstall-service": (cmd_uninstall_service, "снять автозапуск"),
    }
    for name, (_, help_text) in commands.items():
        parser_sub = sub.add_parser(name, help=help_text)
        if name == "pause":
            parser_sub.add_argument("duration", nargs="?", default="30m",
                                    help="длительность: 90s, 30m, 2h, 1d (по умолчанию 30m)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    cfg = load_config(args.config)
    handler = commands[args.command][0]
    try:
        return handler(cfg, args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
