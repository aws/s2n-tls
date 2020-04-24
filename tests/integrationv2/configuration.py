import threading
from contextlib import contextmanager
from common import Ciphersuites, Curves


# List of ciphersuites that will be tested.
CIPHERSUITES = [
    Ciphersuites.TLS_CHACHA20_POLY1305_SHA256,
    Ciphersuites.TLS_AES_128_GCM_256,
    Ciphersuites.TLS_AES_256_GCM_384
]


# List of curves that will be tested.
CURVES = [
    Curves.P256,
    Curves.P384
]


class AvailablePorts():
    """
    NOTE: This is not where this belongs, refactor needed.
    An iterator that atomically returns the next available port.
    """

    def __init__(self):
        self.ports = iter(range(8000, 9000))
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.ports)


available_ports = AvailablePorts()
