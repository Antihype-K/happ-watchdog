#!/usr/bin/env python3
"""happ-fix-geo — чинит geo-файлы профиля маршрутизации Happ.

Проблема, которую решает утилита: профиль маршрутизации (например «ExtraVPN RU»)
приносит свои урезанные geoip.dat/geosite.dat — только с российскими кодами.
Xray получает XRAY_LOCATION_ASSET на папку профиля, а конфиги серверов из
подписки нередко ссылаются на стандартные коды вроде geosite:apple. Такого кода
в урезанном файле нет, и ядро вообще не стартует:

    Failed to start: ... illegal domain rule: geosite:apple
                     > failed to check code APPLE from geosite.dat > EOF

Лечение: дописать в файлы профиля недостающие записи из полных geo-файлов,
которые лежат в /opt/happ/bin/core. Коды профиля при совпадении имён побеждают,
так что российская маршрутизация остаётся ровно такой, как её задумал автор
профиля.

Формат geoip.dat/geosite.dat — protobuf: подряд идущие записи с полем 1
(length-delimited), внутри каждой первым полем строковый код страны/категории.
Слияние сводится к склейке нужных записей, перекодировать ничего не нужно.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

HOME = Path.home()
PROFILES_DIR = HOME / ".local/share/Happ/routing"
VANILLA_DIR = Path("/opt/happ/bin/core")
FILES = ("geosite.dat", "geoip.dat")


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(buf):
            raise EOFError("файл обрывается посреди varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def parse_entries(path: Path) -> tuple[list[tuple[str, bytes]], bool]:
    """[(код, сырая запись с тегом и длиной)], признак обрыва файла."""
    buf = path.read_bytes()
    entries: list[tuple[str, bytes]] = []
    pos = 0
    truncated = False
    while pos < len(buf):
        start = pos
        try:
            key, pos = read_varint(buf, pos)
            if key & 0x07 != 2:
                raise ValueError(f"неожиданный wire type {key & 0x07}")
            length, pos = read_varint(buf, pos)
            if pos + length > len(buf):
                truncated = True
                break
            record = buf[pos:pos + length]
            pos += length
            code = ""
            if record[:1] == b"\x0a":                     # поле 1: строковый код
                str_len, offset = read_varint(record, 1)
                code = record[offset:offset + str_len].decode("utf-8", "replace")
            entries.append((code.upper(), buf[start:pos]))
        except (EOFError, ValueError, IndexError):
            truncated = True
            break
    return entries, truncated


def merge_file(profile_path: Path, vanilla_path: Path, *, dry_run: bool) -> dict:
    profile_entries, profile_broken = parse_entries(profile_path)
    vanilla_entries, vanilla_broken = parse_entries(vanilla_path)

    profile_codes = {code for code, _ in profile_entries}
    added = [(code, raw) for code, raw in vanilla_entries if code not in profile_codes]

    report = {
        "file": profile_path.name,
        "profile_codes": len(profile_codes),
        "vanilla_codes": len({c for c, _ in vanilla_entries}),
        "added": len(added),
        "profile_broken": profile_broken,
        "vanilla_broken": vanilla_broken,
        "size_before": profile_path.stat().st_size,
        "size_after": 0,
        "backup": None,
    }

    if profile_broken:
        # Битый файл профиля чинить склейкой нельзя — берём полный целиком.
        print(f"  ! {profile_path.name} обрезан, заменяю полным файлом")
        payload = b"".join(raw for _, raw in vanilla_entries)
    else:
        payload = (b"".join(raw for _, raw in profile_entries)
                   + b"".join(raw for _, raw in added))

    report["size_after"] = len(payload)
    if dry_run or not added and not profile_broken:
        return report

    backup = profile_path.with_suffix(profile_path.suffix + f".bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(profile_path, backup)
    report["backup"] = backup.name
    tmp = profile_path.with_suffix(profile_path.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(profile_path)
    return report


def active_profiles(only: str | None) -> list[Path]:
    if not PROFILES_DIR.is_dir():
        return []
    dirs = sorted(p for p in PROFILES_DIR.iterdir() if p.is_dir())
    if only:
        dirs = [p for p in dirs if p.name == only]
    return dirs


def cmd_fix(args: argparse.Namespace) -> int:
    profiles = active_profiles(args.profile)
    if not profiles:
        print(f"  Профилей маршрутизации не найдено в {PROFILES_DIR}")
        return 1

    for missing in (VANILLA_DIR / name for name in FILES):
        if not missing.exists():
            print(f"  Нет эталонного файла {missing} — Happ установлен не полностью")
            return 1

    changed = False
    for profile in profiles:
        print(f"\n  Профиль «{profile.name}»")
        for name in FILES:
            target = profile / name
            if not target.exists():
                print(f"    {name}: отсутствует — копирую полный файл")
                if not args.dry_run:
                    shutil.copy2(VANILLA_DIR / name, target)
                    changed = True
                continue
            report = merge_file(target, VANILLA_DIR / name, dry_run=args.dry_run)
            state = "обрезан" if report["profile_broken"] else "цел"
            print(f"    {name}: {state}, кодов в профиле {report['profile_codes']}, "
                  f"добавлено {report['added']}, "
                  f"{report['size_before'] // 1024} КБ → {report['size_after'] // 1024} КБ")
            if report["backup"]:
                print(f"      резервная копия: {report['backup']}")
            if report["added"] or report["profile_broken"]:
                changed = True

    if args.dry_run:
        print("\n  Это был пробный прогон, файлы не тронуты.")
    elif changed:
        print("\n  Готово. Переподключите VPN: happ-watchdog restart")
    else:
        print("\n  Всё уже на месте, менять нечего.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    profiles = active_profiles(args.profile)
    if not profiles:
        print(f"  Профилей маршрутизации не найдено в {PROFILES_DIR}")
        return 1
    for profile in profiles:
        print(f"\n  Профиль «{profile.name}»")
        for name in FILES:
            target = profile / name
            if not target.exists():
                print(f"    {name}: ОТСУТСТВУЕТ")
                continue
            entries, broken = parse_entries(target)
            codes = sorted({code for code, _ in entries})
            print(f"    {name}: {target.stat().st_size // 1024} КБ, кодов {len(codes)}"
                  f"{', ФАЙЛ ОБРЕЗАН' if broken else ''}")
            print(f"      {', '.join(codes[:24])}{' …' if len(codes) > 24 else ''}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    restored = 0
    for profile in active_profiles(args.profile):
        for name in FILES:
            backups = sorted(profile.glob(f"{name}.bak-*"))
            if not backups:
                continue
            newest = backups[-1]
            shutil.copy2(newest, profile / name)
            print(f"  {profile.name}/{name} ← {newest.name}")
            restored += 1
    if not restored:
        print("  Резервных копий не найдено")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="happ-fix-geo",
        description="Дополняет урезанные geo-файлы профиля маршрутизации Happ "
                    "стандартными кодами, из-за нехватки которых не стартует ядро xray.")
    parser.add_argument("--profile", help="имя профиля (по умолчанию все)")
    sub = parser.add_subparsers(dest="command")
    fix = sub.add_parser("fix", help="дополнить geo-файлы (с резервной копией)")
    fix.add_argument("--dry-run", action="store_true", help="только показать, что будет сделано")
    sub.add_parser("show", help="показать, какие коды есть в профиле")
    sub.add_parser("restore", help="вернуть последнюю резервную копию")

    args = parser.parse_args()
    handlers = {"fix": cmd_fix, "show": cmd_show, "restore": cmd_restore}
    if not args.command:
        parser.print_help()
        return 0
    if args.command != "fix":
        args.dry_run = False
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
