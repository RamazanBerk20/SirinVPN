#!/usr/bin/env python3
"""One bounded HTTP response on QEMU guestfwd stdin/stdout; no host networking."""

import json
import signal
import sys
import uuid


def main():
    signal.alarm(15)
    label, identity = sys.argv[1:]
    if label not in ["direct", "vps"] or str(uuid.UUID(identity)) != identity:
        raise ValueError("Invalid test endpoint identity")
    request = sys.stdin.buffer.readline(8193)
    if request not in [b"GET / HTTP/1.1\r\n", b"GET / HTTP/1.0\r\n"]:
        raise ValueError("Unexpected test endpoint request")
    for _ in range(64):
        header = sys.stdin.buffer.readline(8193)
        if header == b"\r\n":
            break
        if not header or len(header) > 8192:
            raise ValueError("Invalid test endpoint header")
    else:
        raise ValueError("Too many test endpoint headers")
    body = json.dumps({"exit": label, "fixture": identity}).encode()
    sys.stdout.buffer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + f"Content-Length: {len(body)}\r\n".encode()
                            + b"Connection: close\r\n\r\n" + body)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
