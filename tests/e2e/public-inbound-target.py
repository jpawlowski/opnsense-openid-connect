#!/usr/bin/env python3

"""Silent disposable HTTPS target for the external Quick Tunnel routing canary."""

import argparse
import http.server
import re
import ssl


APPLICATION = re.compile(r"^e2e-[a-f0-9]{8}$")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OIDCE2E"

    def log_message(self, format, *arguments):
        return

    def do_POST(self):
        allowed = {
            f"/api/openidconnect/auth/backchannel/{self.server.application_code}": 204,
            f"/api/openidconnect/ssf/push/{self.server.application_code}": 202,
        }
        length = int(self.headers.get("Content-Length", "0"))
        if self.path not in allowed or length > 128 * 1024:
            self.send_error(404)
            return
        self.rfile.read(length)
        self.send_response(allowed[self.path])
        self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--application-code", required=True)
    arguments = parser.parse_args()
    if not APPLICATION.fullmatch(arguments.application_code) or not 1024 <= arguments.port <= 65535:
        parser.error("unsafe target port or application code")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", arguments.port), Handler)
    server.application_code = arguments.application_code
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(arguments.certificate, arguments.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
