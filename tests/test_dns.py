"""Resolver regression for builds with synchronous OpenWrt libcurl."""
import test_monitor as fixtures


class DNSTest(fixtures.MonitorHarness):
    def test_tcp_hostname(self):
        port = self.sockets[0].getsockname()[1]
        self.api.servers = [fixtures.profile(1, "TCP only", f"localhost:{port}", "socks5")]
        self.api.connected = [fixtures.assignment("proxy", 1)]
        self.start()
        snapshot = self.wait_for(lambda s: fixtures.server_state(s, "proxy") == "ok")
        self.assertEqual(fixtures.rows(snapshot)["proxy"]["members"][0]["server"]["detail"], "local_tcp")
        self.sockets[0].settimeout(1)
        self.sockets[0].accept()[0].close()
