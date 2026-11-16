import sys
import socket
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def no_live_connections(monkeypatch):
    """Regression tests may never contact an investigation target."""
    def deny(*args, **kwargs):
        pytest.fail("Unexpected live network operation in deterministic tests")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
