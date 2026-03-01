"""
ipecho-client: Minimal SOCKS5 proxy IP detection (27 bytes total)

Usage:
    from ipecho_client import get_proxy_ip, get_proxy_ip_async

    # Sync
    ip = get_proxy_ip("YOUR_SERVER", 9999, proxy_port=9090)

    # Async
    ip = await get_proxy_ip_async("YOUR_SERVER", 9999, proxy_port=9090)
"""

import socket
import struct
import asyncio
from typing import Optional

__version__ = "1.0.0"
__all__ = ["get_proxy_ip", "get_proxy_ip_async"]


def _resolve_host(host: str) -> str:
    """Resolve hostname to IP locally."""
    try:
        socket.inet_aton(host)
        return host  # Already an IP
    except socket.error:
        return socket.gethostbyname(host)  # Local DNS resolution


def get_proxy_ip(
    target: str,
    target_port: int = 9999,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 1080,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> str:
    """
    Get proxy exit IP by connecting through SOCKS5 to an ipecho server.

    Args:
        target: IP or hostname of ipecho server (DNS resolved locally)
        target_port: Port of ipecho server (default: 9999)
        proxy_host: SOCKS5 proxy host (default: 127.0.0.1)
        proxy_port: SOCKS5 proxy port (default: 1080)
        username: SOCKS5 username (optional)
        password: SOCKS5 password (optional)
        timeout: Connection timeout in seconds (default: 30)

    Returns:
        Proxy exit IP as string (e.g., "1.2.3.4")
    """
    target_ip = _resolve_host(target)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((proxy_host, proxy_port))

        # SOCKS5 auth negotiation
        if username:
            s.send(b'\x05\x01\x02')
            s.recv(2)

            auth = bytes([0x01, len(username)]) + username.encode()
            auth += bytes([len(password or "")]) + (password or "").encode()
            s.send(auth)

            if s.recv(2)[1] != 0x00:
                raise ConnectionError("SOCKS5 authentication failed")
        else:
            s.send(b'\x05\x01\x00')
            s.recv(2)

        # CONNECT request (address type 0x01 = IPv4)
        ip_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack('!H', target_port)
        s.send(b'\x05\x01\x00\x01' + ip_bytes + port_bytes)

        resp = s.recv(32)
        if resp[1] != 0x00:
            raise ConnectionError(f"SOCKS5 connect failed: code {resp[1]}")

        # Read 4-byte IP response
        ip_bytes = s.recv(4)
        if len(ip_bytes) != 4:
            raise ConnectionError(f"Invalid response: expected 4 bytes, got {len(ip_bytes)}")

        return socket.inet_ntoa(ip_bytes)

    finally:
        s.close()


async def get_proxy_ip_async(
    target: str,
    target_port: int = 9999,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 1080,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> str:
    """
    Async version: Get proxy exit IP through SOCKS5.

    Args:
        target: IP or hostname of ipecho server (DNS resolved locally)
        target_port: Port of ipecho server (default: 9999)
        proxy_host: SOCKS5 proxy host (default: 127.0.0.1)
        proxy_port: SOCKS5 proxy port (default: 1080)
        username: SOCKS5 username (optional)
        password: SOCKS5 password (optional)
        timeout: Connection timeout in seconds (default: 30)

    Returns:
        Proxy exit IP as string (e.g., "1.2.3.4")
    """
    # Resolve DNS locally (in executor to not block)
    loop = asyncio.get_event_loop()
    target_ip = await loop.run_in_executor(None, _resolve_host, target)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        raise ConnectionError("Connection timeout")

    try:
        # SOCKS5 auth negotiation
        if username:
            writer.write(b'\x05\x01\x02')
            await writer.drain()
            await reader.read(2)

            auth = bytes([0x01, len(username)]) + username.encode()
            auth += bytes([len(password or "")]) + (password or "").encode()
            writer.write(auth)
            await writer.drain()

            resp = await reader.read(2)
            if resp[1] != 0x00:
                raise ConnectionError("SOCKS5 authentication failed")
        else:
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            await reader.read(2)

        # CONNECT request
        ip_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack('!H', target_port)
        writer.write(b'\x05\x01\x00\x01' + ip_bytes + port_bytes)
        await writer.drain()

        resp = await reader.read(32)
        if resp[1] != 0x00:
            raise ConnectionError(f"SOCKS5 connect failed: code {resp[1]}")

        # Read 4-byte IP response
        ip_bytes = await asyncio.wait_for(reader.read(4), timeout=timeout)
        if len(ip_bytes) != 4:
            raise ConnectionError(f"Invalid response: expected 4 bytes, got {len(ip_bytes)}")

        return socket.inet_ntoa(ip_bytes)

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass


def _cli() -> None:
    """CLI entry point."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Get SOCKS5 proxy exit IP")
    parser.add_argument("target", help="IP or hostname of ipecho server")
    parser.add_argument("-p", "--port", type=int, default=9999, help="Server port (default: 9999)")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="SOCKS5 host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=1080, help="SOCKS5 port (default: 1080)")
    parser.add_argument("-u", "--username", help="SOCKS5 username")
    parser.add_argument("--password", help="SOCKS5 password")
    parser.add_argument("-t", "--timeout", type=float, default=30, help="Timeout (default: 30)")

    args = parser.parse_args()

    try:
        ip = get_proxy_ip(
            target=args.target,
            target_port=args.port,
            proxy_host=args.proxy_host,
            proxy_port=args.proxy_port,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
        )
        print(ip)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
