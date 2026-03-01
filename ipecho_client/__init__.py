"""
ipecho-client: Minimal SOCKS5 proxy IP detection (27 bytes total)

Usage:
    from ipecho_client import get_proxy_ip, get_proxy_ip_async

    # Sync
    ip = get_proxy_ip("YOUR_SERVER", 9999, "proxy.example.com", 1080)

    # Async
    ip = await get_proxy_ip_async("YOUR_SERVER", 9999, "proxy.example.com", 1080)
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
    ipecho_server: str,
    ipecho_port: int,
    proxy_host: str,
    proxy_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> Optional[str]:
    """
    Get proxy exit IP by connecting through SOCKS5 to an ipecho server.

    Args:
        ipecho_server: IP or hostname of ipecho server (DNS resolved locally)
        ipecho_port: Port of ipecho server
        proxy_host: SOCKS5 proxy host (required, non-empty)
        proxy_port: SOCKS5 proxy port (required)
        username: SOCKS5 username (optional)
        password: SOCKS5 password (optional)
        timeout: Connection timeout in seconds (default: 30)

    Returns:
        Proxy exit IP as string (e.g., "1.2.3.4"), or None on failure

    Raises:
        ValueError: If proxy_host or proxy_port is empty/invalid
    """
    if not proxy_host or not proxy_host.strip():
        raise ValueError("proxy_host is required and cannot be empty")
    if not proxy_port:
        raise ValueError("proxy_port is required and cannot be empty")

    s = None
    try:
        target_ip = _resolve_host(ipecho_server)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        s.connect((proxy_host, proxy_port))

        # SOCKS5 auth negotiation
        if username:
            s.send(b'\x05\x01\x02')
            resp = s.recv(2)
            if len(resp) < 2:
                return None

            auth = bytes([0x01, len(username)]) + username.encode()
            auth += bytes([len(password or "")]) + (password or "").encode()
            s.send(auth)

            resp = s.recv(2)
            if len(resp) < 2 or resp[1] != 0x00:
                return None
        else:
            s.send(b'\x05\x01\x00')
            resp = s.recv(2)
            if len(resp) < 2:
                return None

        # CONNECT request (address type 0x01 = IPv4)
        ip_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack('!H', ipecho_port)
        s.send(b'\x05\x01\x00\x01' + ip_bytes + port_bytes)

        # SOCKS5 response: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2) = 10 bytes
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            return None

        # Read 4-byte IP response from ipecho server
        ip_bytes = s.recv(4)
        if len(ip_bytes) != 4:
            return None

        return socket.inet_ntoa(ip_bytes)

    except Exception:
        return None
    finally:
        if s:
            s.close()


async def get_proxy_ip_async(
    ipecho_server: str,
    ipecho_port: int,
    proxy_host: str,
    proxy_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> Optional[str]:
    """
    Async version: Get proxy exit IP through SOCKS5.

    Args:
        ipecho_server: IP or hostname of ipecho server (DNS resolved locally)
        ipecho_port: Port of ipecho server
        proxy_host: SOCKS5 proxy host (required, non-empty)
        proxy_port: SOCKS5 proxy port (required)
        username: SOCKS5 username (optional)
        password: SOCKS5 password (optional)
        timeout: Connection timeout in seconds (default: 30)

    Returns:
        Proxy exit IP as string (e.g., "1.2.3.4"), or None on failure

    Raises:
        ValueError: If proxy_host or proxy_port is empty/invalid
    """
    if not proxy_host or not proxy_host.strip():
        raise ValueError("proxy_host is required and cannot be empty")
    if not proxy_port:
        raise ValueError("proxy_port is required and cannot be empty")

    writer = None
    try:
        # Resolve DNS locally (in executor to not block)
        loop = asyncio.get_event_loop()
        target_ip = await loop.run_in_executor(None, _resolve_host, ipecho_server)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=timeout
        )

        # SOCKS5 auth negotiation
        if username:
            writer.write(b'\x05\x01\x02')
            await writer.drain()
            resp = await reader.read(2)
            if len(resp) < 2:
                return None

            auth = bytes([0x01, len(username)]) + username.encode()
            auth += bytes([len(password or "")]) + (password or "").encode()
            writer.write(auth)
            await writer.drain()

            resp = await reader.read(2)
            if len(resp) < 2 or resp[1] != 0x00:
                return None
        else:
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            resp = await reader.read(2)
            if len(resp) < 2:
                return None

        # CONNECT request
        ip_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack('!H', ipecho_port)
        writer.write(b'\x05\x01\x00\x01' + ip_bytes + port_bytes)
        await writer.drain()

        # SOCKS5 response: 10 bytes for IPv4
        resp = await asyncio.wait_for(reader.read(10), timeout=timeout)
        if len(resp) < 2 or resp[1] != 0x00:
            return None

        # Read 4-byte IP response from ipecho server
        ip_bytes = await asyncio.wait_for(reader.read(4), timeout=timeout)
        if len(ip_bytes) != 4:
            return None

        return socket.inet_ntoa(ip_bytes)

    except Exception:
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _cli() -> None:
    """CLI entry point."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Get SOCKS5 proxy exit IP")
    parser.add_argument("ipecho_server", help="IP or hostname of ipecho server")
    parser.add_argument("ipecho_port", type=int, help="Port of ipecho server")
    parser.add_argument("--proxy-host", required=True, help="SOCKS5 host (required)")
    parser.add_argument("--proxy-port", type=int, required=True, help="SOCKS5 port (required)")
    parser.add_argument("-u", "--username", help="SOCKS5 username")
    parser.add_argument("--password", help="SOCKS5 password")
    parser.add_argument("-t", "--timeout", type=float, default=30, help="Timeout (default: 30)")

    args = parser.parse_args()

    try:
        ip = get_proxy_ip(
            ipecho_server=args.ipecho_server,
            ipecho_port=args.ipecho_port,
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
