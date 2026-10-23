"""Read-only diagnostics; never change the chosen egress or use a fallback."""
import socket
import ssl
import struct
import http.client
from urllib.parse import urlsplit


def read_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError('Прокси закрыл соединение.')
        data += chunk
    return data


def connect_socks(route, hostname, port, timeout=10):
    sock = socket.create_connection((route['host'], route['port']), timeout=timeout)
    try:
        auth = bool(route['username'])
        sock.sendall(bytes((5, 1, 2 if auth else 0)))
        if read_exact(sock, 2) != bytes((5, 2 if auth else 0)):
            raise RuntimeError('SOCKS5 отклонил выбранный способ авторизации.')
        if auth:
            user, password = route['username'].encode(), route['password'].encode()
            sock.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
            if read_exact(sock, 2) != b'\x01\x00':
                raise RuntimeError('SOCKS5 отклонил авторизацию.')
        host = hostname.encode('idna')
        if not 0 < len(host) <= 255:
            raise ValueError('Слишком длинное имя назначения.')
        sock.sendall(b'\x05\x01\x00\x03' + bytes((len(host),)) + host + struct.pack('!H', port))
        reply = read_exact(sock, 4)
        if reply[:3] != b'\x05\x00\x00':
            raise RuntimeError('SOCKS5 не смог открыть соединение с назначением.')
        lengths = {1: 4, 4: 16}
        size = read_exact(sock, 1)[0] if reply[3] == 3 else lengths.get(reply[3])
        if size is None:
            raise RuntimeError('Некорректный ответ SOCKS5.')
        read_exact(sock, size + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def probe(route, url='https://www.gstatic.com/generate_204'):
    target = urlsplit(url)
    if target.scheme not in ('http', 'https') or not target.hostname or target.username:
        raise ValueError('Нужен HTTP(S)-адрес без учётных данных.')
    port = target.port or (443 if target.scheme == 'https' else 80)
    if route['mode'] == 'socks5':
        sock = connect_socks(route, target.hostname, port)
    elif route['mode'] == 'direct':
        sock = socket.create_connection((target.hostname, port), timeout=10)
    else:
        raise ValueError('Неизвестный маршрут.')
    with sock:
        if target.scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target.hostname)
        with sock:
            path = target.path or '/'
            if target.query:
                path += '?' + target.query
            sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {target.hostname}\r\nConnection: close\r\n\r\n'.encode('ascii'))
            response = http.client.HTTPResponse(sock)
            response.begin()
            if not 200 <= response.status < 400:
                raise RuntimeError(f'Проверочный сервер ответил HTTP {response.status}.')
            return response.status
