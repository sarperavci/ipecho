# ipecho

Detect your SOCKS5 proxy's exit IP using only **27 bytes** of traffic.

Most IP checkers (like icanhazip.com) use ~500 bytes due to HTTP overhead. This uses raw TCP - just 4 bytes for the IP response.

## How it works

1. You run a tiny server that responds with the client's IP (4 raw bytes)
2. You connect through your SOCKS5 proxy to that server
3. Server sees the proxy's exit IP and sends it back

That's it.

## Server

```bash
# Docker
docker run --restart=unless-stopped -p 9999:9999 ghcr.io/sarperavci/ipecho

# Or build yourself
cd ipecho/server && go build -o ipecho-server && ./ipecho-server 9999
```

## Client

```bash
pip install git+https://github.com/sarperavci/ipecho.git
```

```python
from ipecho_client import get_proxy_ip

ip = get_proxy_ip(
    target="YOUR_SERVER_IP",
    target_port=9999,
    proxy_port=9090
)
print(ip)  # 1.2.3.4
```

Async version available too:

```python
ip = await get_proxy_ip_async("YOUR_SERVER_IP", 9999, proxy_port=9090)
```

## Why?

Why not?