#!/usr/bin/env python3
"""
Subdomains v1.11 - Subdomain Finder

Reads a list of root domains, discovers their subdomains using public online
sources (certificate databases and passive DNS), and outputs the root domain
and all its subdomains.

No brute-force, no noise: only real subdomains found in public records.

USAGE:
  cat infile.lst | subdomains [OPTIONS]
  subdomains [OPTIONS] < infile.lst > outfile.lst

OPTIONS:
  -r, --resolved-only        Output only successfully resolved entries
  -w, --resolved-wan-only    Output only public (WAN) resolved entries
  -l, --resolved-lan-only    Output only private (LAN) resolved entries
  -d, --dns=SERVERS          Custom DNS servers (comma-separated, e.g. 8.8.8.8,1.1.1.1)
"""

import sys
import re
import json
import time
import socket
import struct
import random
import ipaddress
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

# Константы
REQUEST_TIMEOUT = 20       # Таймаут запроса к внешнему API, секунды
RESOLVE_TIMEOUT = 5        # Таймаут одного DNS-запроса, секунды
DELAY_BETWEEN_API = 1      # Пауза между запросами к разным источникам, секунды
DELAY_BETWEEN_DOMAINS = 2  # Пауза между обработкой корневых доменов, секунды
MAX_WORKERS = 2            # Количество параллельных потоков (ограничено для соблюдения лимитов API)

# Регулярное выражение для валидации доменных имён
VALID_DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
)

# Минимальный DNS-клиент (чистый Python, без зависимостей)
def _dns_query(qname, qtype, nameservers, timeout=RESOLVE_TIMEOUT):
    """
    Отправить DNS-запрос к указанным серверам.
    qtype: 1 = A, 12 = PTR
    Возвращает список ответов (строки) или None при ошибке.
    """
    # Формируем заголовок
    txn_id = random.randint(0, 65535)
    flags = 0x0100  # стандартный рекурсивный запрос
    header = struct.pack('>HHHHHH', txn_id, flags, 1, 0, 0, 0)

    # Формируем вопрос
    question = b''
    for label in qname.rstrip('.').split('.'):
        question += bytes([len(label)]) + label.encode('ascii')
    question += b'\x00' + struct.pack('>HH', qtype, 1)  # тип, класс=IN

    packet = header + question

    # Пробуем сервера по очереди
    for ns in nameservers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (ns, 53))
            data, _ = sock.recvfrom(512)  # UDP-ответ обычно <=512 байт
            sock.close()

            # Парсим ответ (минимально: только ответы на наш вопрос)
            # Пропускаем заголовок и вопрос
            offset = 12  # заголовок
            # Пропускаем вопрос
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 5  # null-байт + 2 байта тип + 2 байта класс

            # Читаем ответы
            answers = []
            ancount = struct.unpack('>H', data[6:8])[0]
            for _ in range(ancount):
                # Пропускаем имя (может быть сжатие)
                while offset < len(data):
                    if offset >= len(data):
                        break
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    elif (length & 0xC0) == 0xC0:  # сжатие
                        offset += 2
                        break
                    else:
                        offset += length + 1

                if offset + 10 > len(data):
                    break
                atype, aclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset+10])
                offset += 10

                if atype == 1 and qtype == 1:  # A-запись
                    if rdlen == 4:
                        ip = '.'.join(str(b) for b in data[offset:offset+4])
                        answers.append(ip)
                elif atype == 12 and qtype == 12:  # PTR-запись
                    # Парсим доменное имя в ответе
                    rdata_offset = offset
                    name_parts = []
                    while rdata_offset < len(data):
                        length = data[rdata_offset]
                        if length == 0:
                            break
                        elif (length & 0xC0) == 0xC0:
                            # Для простоты игнорируем сжатие в ответах PTR
                            break
                        else:
                            rdata_offset += 1
                            name_parts.append(data[rdata_offset:rdata_offset+length].decode('ascii', errors='ignore'))
                            rdata_offset += length
                    if name_parts:
                        answers.append('.'.join(name_parts).rstrip('.').lower())

                offset += rdlen

            if answers:
                return answers
        except:
            continue
    return None

def _rdns_custom(ip, nameservers, short=False):
    """Обратный DNS через кастомные сервера (PTR-запрос)"""
    # Формируем reverse-имя: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
    rev_name = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
    results = _dns_query(rev_name, 12, nameservers)  # 12 = PTR
    if results:
        h = results[0]
        return h.split('.')[0] if short else h
    return None

def _fwd_custom(host, nameservers):
    """Прямой DNS через кастомные сервера (A-запрос)"""
    results = _dns_query(host, 1, nameservers)  # 1 = A
    if results:
        return sorted(set(results), key=lambda x: tuple(map(int, x.split('.'))))
    return []

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
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 Subdomains/1.11"})
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

def is_private_ip(ip_str: str) -> bool:
    """Проверяет, является ли IP-адрес приватным (LAN)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False

def resolve_domain(domain: str, dns_servers: list = None) -> list:
    """
    Резолвит домен.
    Если указаны dns_servers - использует встроенный минимальный DNS-клиент (_fwd_custom).
    Иначе - системный socket.getaddrinfo().
    Возвращает список найденных IPv4-адресов или пустой список при ошибке.
    """
    if dns_servers:
        # Используем кастомный DNS-клиент
        return _fwd_custom(domain, dns_servers)
    else:
        # Используем системный резолвер
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(RESOLVE_TIMEOUT)
            results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            # Фильтруем только IPv4 (AF_INET)
            ips = list(set(r[4][0] for r in results if r[0] == socket.AF_INET and len(r[4]) >= 1))
            socket.setdefaulttimeout(old_timeout)
            return ips
        except (socket.gaierror, socket.timeout, OSError, Exception):
            return []

def filter_by_resolution(subs: list, dns_servers: list, resolved_only: bool, wan_only: bool, lan_only: bool) -> list:
    """
    Фильтрует список поддоменов по результату резолва.
    - resolved_only: оставить только те, что успешно резолвятся
    - wan_only: оставить только с публичными (WAN) IP
    - lan_only: оставить только с приватными (LAN) IP
    """
    if not (resolved_only or wan_only or lan_only):
        return subs

    result = []
    for sub in subs:
        ips = resolve_domain(sub, dns_servers)

        if resolved_only and not ips:
            continue
        if wan_only and not any(not is_private_ip(ip) for ip in ips):
            continue
        if lan_only and not any(is_private_ip(ip) for ip in ips):
            continue

        # Если прошли все фильтры - добавляем
        if (resolved_only or wan_only or lan_only):
            # Дополнительная проверка: если указан wan_only/lan_only, но резолв пустой - пропускаем
            if (wan_only or lan_only) and not ips:
                continue
            result.append(sub)

    return result

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
    # Парсим аргументы командной строки
    custom_dns = None            # список кастомных DNS-серверов
    resolved_only = False        # флаг: выводить только отрезолвленные записи
    resolved_lan_only = False    # флаг: выводить только отрезолвленные записи с адресами из LAN
    resolved_wan_only = False    # флаг: выводить только отрезолвленные записи с адресами из WAN

    args = sys.argv[1:]

    # Используем while-цикл для поддержки аргументов вида "-d 8.8.8.8" (через пробел)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '-d':
            # Формат через пробел: -d 8.8.8.8,1.1.1.1
            if i + 1 < len(args):
                i += 1
                servers = args[i]
                custom_dns = [s.strip() for s in servers.split(',') if s.strip()]
            else:
                print("Error: Option -d requires a value", file=sys.stderr)
                sys.exit(1)
        elif arg.startswith('--dns='):
            # Формат через знак равно: --dns=8.8.8.8,1.1.1.1
            servers = arg.split('=', 1)[1]
            if servers:
                custom_dns = [s.strip() for s in servers.split(',') if s.strip()]
            else:
                print("Error: Option --dns requires a value", file=sys.stderr)
                sys.exit(1)
        elif arg in ('-r', '--resolved-only'):
            resolved_only = True
        elif arg in ('-l', '--resolved-lan-only'):
            resolved_lan_only = True
        elif arg in ('-w', '--resolved-wan-only'):
            resolved_wan_only = True
        elif arg in ('-h', '--help'):
            print(__doc__, file=sys.stderr)
            sys.exit(0)
        else:
            print(f"Error: Invalid option: {arg}", file=sys.stderr)
            sys.exit(1)
        i += 1

    # Чтение корневых доменов из stdin
    # Игнорируем пустые строки и комментарии (начинающиеся с #)
    roots = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]

    # Если вход пустой - завершаемся без вывода
    if not roots:
        sys.exit(0)

    # executor.map выполняет задачи параллельно, но отдаёт результаты строго в порядке входного списка
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for root, valid_subs in zip(roots, executor.map(collect_for_domain, roots)):
            try:
                # Применяем фильтрацию по резолву, если заданы соответствующие флаги
                if resolved_only or resolved_wan_only or resolved_lan_only:
                    valid_subs = filter_by_resolution(valid_subs, custom_dns, resolved_only, resolved_wan_only, resolved_lan_only)

                    # При фильтрации: если корневой домен резолвится — добавляем его в список
                    if resolve_domain(root, custom_dns) and root not in valid_subs:
                        valid_subs.append(root)

                    # При фильтрации выводим только если есть результаты
                    if valid_subs:
                        print()
                        print('# ' + root)
                        # Корневой домен первым, затем отсортированные поддомены (без корня)
                        subs_without_root = sorted(s for s in valid_subs if s != root)
                        print(root)
                        for sub in subs_without_root:
                            print(sub)
                else:
                    # Без флагов фильтрации:
                    # 1. Всегда выводим заголовок домена
                    # 2. Если корневой домен резолвится и его нет в списке — добавляем его
                    output_subs = set(valid_subs)
                    if root not in output_subs:
                        # Проверяем, резолвится ли корневой домен
                        if resolve_domain(root, custom_dns):
                            output_subs.add(root)

                    print()
                    print('# ' + root)
                    # Корневой домен первым, затем отсортированные поддомены (без корня)
                    subs_without_root = sorted(s for s in output_subs if s != root)
                    print(root)
                    for sub in subs_without_root:
                        print(sub)
                time.sleep(DELAY_BETWEEN_DOMAINS)
            except Exception:
                pass


# Точка входа
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
