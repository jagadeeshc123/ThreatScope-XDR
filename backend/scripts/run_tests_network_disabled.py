"""Run the backend suite while denying uncontrolled external networking and app subprocesses."""

from __future__ import annotations

import asyncio  # Load platform subprocess subclasses before the Popen guard is installed.
import inspect
import ipaddress
import os
import socket
import subprocess
import unittest
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


BACKEND = Path(__file__).resolve().parents[1]
APPLICATION = (BACKEND / "app").resolve()
_create_connection = socket.create_connection
_getaddrinfo = socket.getaddrinfo
_urlopen = urllib.request.urlopen
_popen = subprocess.Popen
_os_system = os.system
_os_popen = os.popen


def _loopback(host: str) -> bool:
    if host.casefold() in {"localhost", "testserver"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def guarded_create_connection(address, *args, **kwargs):
    if not _loopback(str(address[0])):
        raise AssertionError("Uncontrolled external network connection denied")
    return _create_connection(address, *args, **kwargs)


def guarded_getaddrinfo(host, *args, **kwargs):
    if host is not None and not _loopback(str(host)):
        raise AssertionError("Uncontrolled external DNS lookup denied")
    return _getaddrinfo(host, *args, **kwargs)


def guarded_urlopen(url, *args, **kwargs):
    value = getattr(url, "full_url", url)
    host = urlsplit(str(value)).hostname or ""
    if not _loopback(host):
        raise AssertionError("Uncontrolled external URL request denied")
    return _urlopen(url, *args, **kwargs)


def _called_from_application() -> bool:
    for frame in inspect.stack()[2:16]:
        try:
            if APPLICATION in Path(frame.filename).resolve().parents:
                return True
        except OSError:
            continue
    return False


def guarded_popen(*args, **kwargs):
    if _called_from_application():
        raise AssertionError("Application subprocess execution denied")
    return _popen(*args, **kwargs)


def guarded_system(command):
    if _called_from_application():
        raise AssertionError("Application shell execution denied")
    return _os_system(command)


def guarded_os_popen(command, *args, **kwargs):
    if _called_from_application():
        raise AssertionError("Application shell execution denied")
    return _os_popen(command, *args, **kwargs)


def main() -> int:
    socket.create_connection = guarded_create_connection
    socket.getaddrinfo = guarded_getaddrinfo
    urllib.request.urlopen = guarded_urlopen
    subprocess.Popen = guarded_popen
    os.system = guarded_system
    os.popen = guarded_os_popen
    try:
        import httpx
        original = httpx.HTTPTransport.handle_request
        original_async = httpx.AsyncHTTPTransport.handle_async_request

        def guarded_http(self, request):
            if not _loopback(request.url.host):
                raise AssertionError("Uncontrolled external HTTP transport denied")
            return original(self, request)

        httpx.HTTPTransport.handle_request = guarded_http

        async def guarded_async_http(self, request):
            if not _loopback(request.url.host):
                raise AssertionError("Uncontrolled external async HTTP transport denied")
            return await original_async(self, request)

        httpx.AsyncHTTPTransport.handle_async_request = guarded_async_http
    except (ImportError, AttributeError):
        pass
    suite = unittest.defaultTestLoader.discover(str(BACKEND / "tests"), pattern="test*.py", top_level_dir=str(BACKEND))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
