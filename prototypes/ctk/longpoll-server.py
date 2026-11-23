#!/usr/bin/env python3
"""Throwaway TLS server for the prototype's long-poll check: holds a request open, then answers.

  ./make-longpoll-cert.sh <address>      # once: certificate for this Mac's LAN address
  ./longpoll-server.py <address>         # listens on that address only, port 8444

GET /hold?secs=N answers after N seconds (at most 300). Nothing else is served, read or stored.
"""
import http.server
import os
import ssl
import sys
import time
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 330

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            secs = min(max(int(urllib.parse.parse_qs(u.query)["secs"][0]), 0), 300)
        except (KeyError, ValueError):
            secs = None
        if u.path != "/hold" or secs is None:
            self.send_error(404)
            return
        self.log_message("holding %d s", secs)
        t0 = time.time()
        time.sleep(secs)
        body = b"held %d\n" % secs
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            self.log_message("answered after %.1f s", time.time() - t0)
        except OSError as e:
            self.log_message("client gone after %.1f s: %s", time.time() - t0, e)
        self.close_connection = True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def finish_request(self, request, client_address):
        # Handshake in the request's own thread, so a slow client can't block the listener.
        request.settimeout(20)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError) as e:
            print(f"{client_address[0]} TLS handshake failed: {e}", flush=True)
            return
        tls.settimeout(330)
        super().finish_request(tls, client_address)


if __name__ == "__main__":
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".longpoll")
    addr = (sys.argv[1], 8444)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(here, "server.pem"), os.path.join(here, "server.key"))
    s = Server(addr, Handler)
    s.ctx = ctx
    print(f"listening on {addr[0]}:{addr[1]}", flush=True)
    s.serve_forever()
