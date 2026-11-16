from unittest.mock import Mock

import pytest

from networking import Deadline, DeadlineExceeded, DestinationBlocked, public_address, request_headers, resolve_public


@pytest.mark.parametrize('address', ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '192.0.2.1', '::1', '::', 'fc00::1', 'fe80::1', 'ff02::1', '::ffff:8.8.8.8', '64:ff9b::808:808', '2002:0808:0808::1'])
def test_non_public_and_transition_addresses_are_denied(address):
    assert not public_address(address)
    with pytest.raises(DestinationBlocked):
        resolve_public(address, Deadline(1), 1)


def test_mixed_dns_answer_is_denied(monkeypatch):
    monkeypatch.setattr('networking.socket.getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('8.8.8.8', 0)), (2, 1, 6, '', ('127.0.0.1', 0))])
    with pytest.raises(DestinationBlocked):
        resolve_public('mixed.example', Deadline(1), 1)


@pytest.mark.parametrize('host', ['2130706433', '127.1', '0177.0.0.1', '0x7f000001'])
def test_alternative_ip_notation_resolves_before_policy(host, monkeypatch):
    monkeypatch.setattr('networking.socket.getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('127.0.0.1', 0))])
    with pytest.raises(DestinationBlocked):
        resolve_public(host, Deadline(1), 1)


def test_expired_budget_stops_resolution():
    deadline = Deadline(1)
    deadline.expires_at = 0
    with pytest.raises(DeadlineExceeded):
        resolve_public('example.com', deadline, 1)


class FakeSocket:
    def __init__(self):
        self.data = bytearray(b'HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 6\r\n\r\nSECRET')
        self.target = None
        self.closed = False
    def settimeout(self, timeout):
        assert timeout > 0
    def connect(self, target):
        self.target = target
    def sendall(self, data):
        self.sent = data
    def recv(self, count):
        value = bytes(self.data[:count])
        del self.data[:count]
        return value
    def close(self):
        self.closed = True


def test_tls_connection_uses_validated_ip_and_original_hostname(monkeypatch):
    sock = FakeSocket()
    context = Mock()
    context.wrap_socket.return_value = sock
    monkeypatch.setattr('networking.socket.socket', lambda *args: sock)
    monkeypatch.setattr('networking.ssl.create_default_context', lambda **kwargs: context)
    monkeypatch.setattr('networking.socket.getaddrinfo', lambda *a, **kw: pytest.fail('Connection must not resolve the hostname again'))
    response = request_headers('https://example.com/entry?x=1', '93.184.216.34', Deadline(2), 1)
    assert sock.target == ('93.184.216.34', 443)
    context.wrap_socket.assert_called_once_with(sock, server_hostname='example.com')
    assert b'Host: example.com\r\n' in sock.sent
    assert response.location == '/next'
    assert sock.data == b'SECRET'  # No response body was consumed.
    assert sock.closed


def test_unusual_port_is_blocked_before_socket_creation(monkeypatch):
    monkeypatch.setattr('networking.socket.socket', lambda *a: pytest.fail('Must not connect'))
    with pytest.raises(DestinationBlocked):
        request_headers('https://example.com:8080', '8.8.8.8', Deadline(1), 1)


def test_header_trickle_exhausts_shared_deadline(monkeypatch):
    sock = FakeSocket()
    clock = iter([0, 0.1, 0.2, 0.3, 1.1])
    monkeypatch.setattr('networking.monotonic', lambda: next(clock))
    monkeypatch.setattr('networking.socket.socket', lambda *a: sock)
    with pytest.raises(DeadlineExceeded):
        request_headers('http://example.com', '8.8.8.8', Deadline(1), 1)
    assert sock.closed
