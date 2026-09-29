"""Decide, from /proc/net/tcp and tcp6, whether a container listens off loopback.

The engine's control API moved to a Unix socket so that joining an operator's
network would not put a listener on it. The way to show that is not to probe a
port and see it refused -- a refused port says nothing about the others -- but to
read the kernel's own table of listening sockets inside the container, every one
of them, and require each to be bound to loopback.

Input is the two files concatenated, as `cat /proc/net/tcp /proc/net/tcp6` prints
them (tcp6 may be absent if IPv6 is off). Addresses are hex, in the kernel's byte
order, which is what this decodes.

    exit 0  every LISTEN socket is on 127.0.0.0/8 or ::1 (the lines say which)
    exit 1  at least one listens elsewhere -- 0.0.0.0, ::, or a real address
    exit 2  the input is not what those files contain: UNVERIFIED, never a pass
"""

from __future__ import annotations

import ipaddress
import sys

LISTEN = "0A"


class Unreadable(Exception):
    pass


def _decode(hex_addr: str) -> ipaddress._BaseAddress:
    raw = bytes.fromhex(hex_addr)
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw[::-1])
    if len(raw) == 16:
        # Four 32-bit words, each in host (little-endian) order.
        return ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    raise Unreadable(f"an address of {len(raw)} bytes")


def listeners(text: str) -> list:
    """[(address, port)] for every socket in the LISTEN state."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].split()[:2] == ["sl", "local_address"]:
        raise Unreadable("the input does not start with the /proc/net/tcp header")
    found = []
    headers = 0
    for line in lines:
        fields = line.split()
        if fields[:2] == ["sl", "local_address"]:
            headers += 1
            continue
        if len(fields) < 4 or not fields[0].endswith(":"):
            raise Unreadable("a row does not have the /proc/net/tcp shape")
        local, state = fields[1], fields[3]
        if ":" not in local:
            raise Unreadable("a local address has no port")
        address, port = local.rsplit(":", 1)
        try:
            decoded = _decode(address)
            number = int(port, 16)
        except ValueError as exc:
            raise Unreadable(f"an address could not be decoded ({exc})") from None
        if state == LISTEN:
            found.append((decoded, number))
    if headers > 2:
        raise Unreadable("more than two tables in the input")
    return found


def judge(text: str) -> tuple:
    try:
        found = listeners(text)
    except Unreadable as exc:
        return 2, [f"UNVERIFIED: {exc}"]
    lines, worst = [], 0
    for address, port in found:
        if address.is_loopback:
            lines.append(f"loopback only: {address}:{port}")
        else:
            worst = 1
            lines.append(f"LISTENS OFF LOOPBACK: {address}:{port}")
    if not found:
        lines.append("no listening TCP socket at all")
    return worst, lines


def main() -> int:
    code, lines = judge(sys.stdin.read())
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
