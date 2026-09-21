#!/usr/bin/env python3

import http.server
import pathlib
import ssl
import sys


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: release_https_server.py ROOT CERT KEY PORT_FILE")
    root, certificate, key, port_file = map(pathlib.Path, sys.argv[1:])
    handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
        *args, directory=str(root), **kwargs
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port_file.write_text(f"{server.server_port}\n", encoding="ascii")
    server.serve_forever()


if __name__ == "__main__":
    main()
