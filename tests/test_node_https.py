"""Verify the native HTTPS paths on local sockets, with a real TLS handshake."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest


SRC = Path(__file__).resolve().parents[1] / "src"


@unittest.skipIf(os.environ.get("V2RAYA_TEST_SYSROOT"), "requires native libcurl")
class NodeHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name)
        cls.driver = str(root / "driver")
        cls.cert = str(root / "cert.pem")
        key = str(root / "key.pem")
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-x509", "-days", "1",
                        "-nodes", "-subj", "/CN=node.invalid", "-addext", "subjectAltName=DNS:node.invalid,IP:127.0.0.1",
                        "-keyout", key, "-out", cls.cert], check=True, stderr=subprocess.DEVNULL)
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(cls.cert, key)
        harness = root / "driver.c"
        harness.write_text(r'''
#include "node_https.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 5 || curl_global_init(CURL_GLOBAL_DEFAULT)) return 1;
    int handle = atoi(argv[2]);
    long expected = atol(argv[4]);
    struct node_https_proxy proxy = {.scheme = argv[1], .address = "127.0.0.1", .port = handle};
    struct node_https_result result;
    int ok = !strcmp(argv[1], "fd") ? node_https_fd(handle, argv[3], 3000, expected, &result) :
            node_https_proxy(&proxy, argv[3], 3000, 0, expected, &result);
    printf("%d %s %ld %ld\n", ok, result.detail, result.http_code, result.ms);
    curl_global_cleanup();
    return 0;
}
''')
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-std=gnu11", "-I", str(SRC),
                        str(harness), str(SRC / "node_https.c"), "-lcurl",
                        "-o", cls.driver], check=True)

    def origin(self, conn, host, trusted, status, observations):
        # SSLObject operates over any byte stream, including the HTTP proxy's
        # outer TLS connection. Both certificates are verified by the client.
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        secure = self.tls.wrap_bio(incoming, outgoing, server_side=True)

        def exchange(operation, *args):
            while True:
                try:
                    result = operation(*args)
                except ssl.SSLWantReadError:
                    conn.sendall(outgoing.read())
                    data = conn.recv(16384)
                    if not data:
                        raise EOFError
                    incoming.write(data)
                else:
                    conn.sendall(outgoing.read())
                    return result

        try:
            exchange(secure.do_handshake)
            request = b""
            while b"\r\n\r\n" not in request:
                block = exchange(secure.read, 16384)
                if not block:
                    raise EOFError
                request += block
        except (ssl.SSLError, EOFError, ConnectionResetError, BrokenPipeError):
            if trusted and host == "node.invalid":
                raise
            return
        observations.append(request.split(b"\r\n", 1)[0])
        exchange(secure.write, f"HTTP/1.1 {status} fixture\r\nContent-Length: 0\r\n"
                 "Location: https://should-not-follow.invalid/\r\n\r\n".encode())

    def check(self, scheme, status, host="node.invalid", trusted=True, expected=204):
        observations = []
        errors = []
        client = listener = None
        if scheme == "fd":
            client, server = socket.socketpair()
            handle = client.fileno()
        else:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)
            handle = listener.getsockname()[1]

        def serve():
            try:
                conn = server if listener is None else listener.accept()[0]
                if scheme == "https":
                    try:
                        conn = self.tls.wrap_socket(conn, server_side=True)
                    except ssl.SSLError:
                        if trusted:
                            raise
                        return
                with conn:
                    conn.settimeout(3)
                    if scheme == "socks5h":
                        with conn.makefile("rb") as stream:
                            self.assertEqual(stream.read(1), b"\x05")
                            stream.read(stream.read(1)[0])
                            conn.sendall(b"\x05\x00")
                            self.assertEqual(stream.read(4), b"\x05\x01\x00\x03")
                            self.assertEqual(stream.read(stream.read(1)[0]).decode(), host)
                            self.assertEqual(int.from_bytes(stream.read(2), "big"), 443)
                            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                    elif scheme in {"http", "https"}:
                        with conn.makefile("rb") as stream:
                            self.assertEqual(stream.readline().split()[:2], [b"CONNECT", f"{host}:443".encode()])
                            while stream.readline() not in (b"\r\n", b""):
                                pass
                        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    self.origin(conn, host, trusted, status, observations)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            env = {**os.environ, "NO_PROXY": "*", "https_proxy": "http://127.0.0.1:1"}
            if trusted:
                env["SSL_CERT_FILE"] = self.cert
            else:
                env.pop("SSL_CERT_FILE", None)
            result = subprocess.check_output(
                [self.driver, scheme, str(handle), f"https://{host}/check", str(expected)],
                pass_fds=(() if client is None else (handle,)), timeout=5, text=True, env=env).split()
        finally:
            if client:
                client.close()
            thread.join(4)
            if listener:
                listener.close()
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]
        if trusted and host == "node.invalid":
            self.assertEqual(observations, [b"GET /check HTTP/1.1"])
        self.assertGreaterEqual(int(result[3]), 0)
        return result[:3]

    def test_socketpair_tls_and_origin_status(self):
        self.assertEqual(self.check("fd", 204), ["1", "https_response", "204"])
        self.assertEqual(self.check("fd", 301), ["0", "https_http_error", "301"])
        self.assertEqual(self.check("fd", 200, expected=200), ["1", "https_response", "200"])
        self.assertEqual(self.check("fd", 204, trusted=False), ["0", "https_tls_error", "0"])
        self.assertEqual(self.check("fd", 204, host="wrong.invalid"), ["0", "https_tls_error", "0"])

    def test_proxy_performs_remote_dns_and_verified_get(self):
        self.assertEqual(self.check("socks5h", 204), ["1", "https_response", "204"])
        self.assertEqual(self.check("http", 204), ["1", "https_response", "204"])
        self.assertEqual(self.check("socks5h", 503), ["0", "https_http_error", "503"])
        self.assertEqual(self.check("http", 204, trusted=False), ["0", "https_tls_error", "0"])

    def test_tls_to_proxy_and_origin(self):
        self.assertEqual(self.check("https", 204), ["1", "https_response", "204"])
        self.assertEqual(self.check("https", 204, trusted=False), ["0", "https_tls_error", "0"])
        self.assertEqual(self.check("https", 204, host="wrong.invalid"), ["0", "https_tls_error", "0"])


if __name__ == "__main__":
    unittest.main()
