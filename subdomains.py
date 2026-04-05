#!/usr/bin/env python3
"""
Subdomains v1.8 - Subdomain Finder

Reads a list of root domains, discovers their subdomains using public online
sources (certificate databases and passive DNS), and outputs the root domain
and all its subdomains.

No brute-force, no noise: only real subdomains found in public records.

USAGE:
  cat domains.lst | subdomains
  subdomains < domains.lst
  subdomains < domains.lst > subdomains.lst
"""

import sys
import re
import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

# Константы
REQUEST_TIMEOUT = 20       # Таймаут запроса к внешнему API, секунды
DELAY_BETWEEN_API = 1      # Пауза между запросами к разным источникам, секунды
DELAY_BETWEEN_DOMAINS = 2  # Пауза между обработкой корневых доменов, секунды
MAX_WORKERS = 2            # Количество параллельных потоков (ограничено для соблюдения лимитов API)

# Регулярное выражение для валидации доменных имён
VALID_DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
)

def _clean_name(name: str) -> str:
    """Удаляет wildcard-префиксы (*. и *) и приводит к нижнему регистру"""
    name = name.lower().strip()
    if name.startswith("*."):
        name = name[2:]
    elif name.startswith("*"):
        name = name[1:]
    return name.strip()

def http_get(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    """Заменитель requests.get() на urllib. Возвращает текст или пустую строку при ошибке."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 Subdomains/1.8"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except (urllib.error.HTTPError, urllib.error.URLError, Exception):
        return ""

def fetch_certspotter(root: str) -> set:
    """Получение поддоменов через CertSpotter CT API"""
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={quote(root)}&include_subdomains=true&expand=dns_names"
        text = http_get(url)
        if not text:
            return set()
        data = json.loads(text)
        subs = set()
        for item in data:
            for name in item.get("dns_names", []):
                subs.add(_clean_name(name))
        return subs
    except (json.JSONDecodeError, ValueError, TypeError):
        return set()

def fetch_hackertarget(root: str) -> set:
    """Получение поддоменов через HackerTarget Passive DNS"""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(root)}"
        text = http_get(url)
        if not text:
            return set()
        subs = set()
        for line in text.strip().splitlines():
            if "," in line:
                sub = _clean_name(line.split(",")[0])
                if sub:
                    subs.add(sub)
        return subs
    except Exception:
        return set()

def fetch_crtsh(root: str) -> set:
    """Получение поддоменов через Crt.sh CT API"""
    try:
        url = f"https://crt.sh/?q=%.{quote(root)}&output=json"
        text = http_get(url)
        if not text:
            return set()
        data = json.loads(text)
        subs = set()
        for item in data:
            # name_value может содержать несколько доменов через \n
            for name in str(item.get("name_value", "")).split("\n"):
                sub = _clean_name(name)
                if sub:
                    subs.add(sub)
        return subs
    except (json.JSONDecodeError, ValueError, TypeError):
        return set()

def is_valid_subdomain(sub: str, root: str) -> bool:
    """Проверка: является ли строка корректным поддоменом заданного корневого домена"""
    if not sub or sub.startswith("*"):
        return False
    if not VALID_DOMAIN_RE.match(sub):
        return False
    # Допускаем точное совпадение с корневым доменом или суффикс .root
    return sub == root or sub.endswith(f".{root}")

def collect_for_domain(root: str) -> list:
    """Сбор и фильтрация поддоменов. Возвращает отсортированный список."""
    raw = set()

    # Пробуем все три источника
    # 1. CertSpotter
    raw.update(fetch_certspotter(root))
    time.sleep(DELAY_BETWEEN_API)
    # 2. HackerTarget
    raw.update(fetch_hackertarget(root))
    time.sleep(DELAY_BETWEEN_API)
    # 3. Crt.sh
    raw.update(fetch_crtsh(root))

    # Фильтрация, дедупликация и сортировка
    return sorted({s for s in raw if is_valid_subdomain(s, root)})

def main():
    # Чтение корневых доменов из stdin
    # Игнорируем пустые строки и комментарии (начинающиеся с #)
    roots = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]

    # Если вход пустой — завершаемся без вывода
    if not roots:
        sys.exit(0)

    # executor.map выполняет задачи параллельно, но отдаёт результаты строго в порядке входного списка
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for root, valid_subs in zip(roots, executor.map(collect_for_domain, roots)):
            try:
                print()
                print('# ' + root)
                print(root)
                for sub in valid_subs:
                    print(sub)
                time.sleep(DELAY_BETWEEN_DOMAINS)
            except Exception:
                pass


if __name__ == '__main__':
    # Показываем справку при вызове с -h или --help, или если запущен без перенаправления ввода
    if sys.stdin.isatty() or '-h' in sys.argv or '--help' in sys.argv:
        print(__doc__, file=sys.stderr)
        sys.exit(0)

    # Обрабатываем прерывание без вывода ошибки
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
