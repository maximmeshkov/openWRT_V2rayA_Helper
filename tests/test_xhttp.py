"""Use synthetic Xray configuration and loopback-only endpoint fixtures."""
import json
from pathlib import Path
import socket

import test_monitor as fixtures


class XHTTPTest(fixtures.MonitorHarness):
    def setUp(self):
        super().setUp()
        self.config = Path(self.tmp.name, "config.json")

    def core(self, tag, *, security="tls", alpn=None, endpoint=None):
        host, port = (endpoint or self.open_port).split(":")
        return {"tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": int(port),
                                        "users": [{"id": "private-fixture-id"}]}]},
                "streamSettings": {"network": "xhttp", "security": security,
                                   "tlsSettings": {} if alpn is None else {"alpn": alpn}}}

    def write(self, outbounds, routing=None):
        staged = self.config.with_suffix(".new")
        staged.write_text(json.dumps({"outbounds": outbounds, "routing": routing or {}}))
        staged.replace(self.config)

    def test_xhttp_switch_in_flight_and_h3_only(self):
        self.api.servers = [fixtures.profile(1, "XHTTP", self.open_port, "vless(xhttp+tls)")]
        self.api.connected = [fixtures.assignment("proxy", 1)]
        self.write([self.core("proxy", alpn=["h2", "h3"])])
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(udp.close)
        udp.bind(self.sockets[0].getsockname())
        udp.settimeout(5)

        def change_on_recheck(number):
            if number == 2:
                self.write([self.core("proxy", alpn=["h3"])])

        self.api.on_touch = change_on_recheck
        self.start("--xray-config", str(self.config))
        row = self.wait_for(lambda d: fixtures.rows(d).get("proxy", {}).get("members", []) and
                            fixtures.rows(d)["proxy"]["members"][0]["transport"] == "quic")
        self.assertEqual(fixtures.server_state(row, "proxy"), "pending")
        self.sockets[0].settimeout(2)
        conn, _ = self.sockets[0].accept()
        conn.close()
        query, sender = udp.recvfrom(2048)
        self.assertEqual((len(query), query[5], query[14]), (1200, 8, 8))
        udp.sendto(b"\x80\0\0\0\0\x08" + query[15:23] + b"\x08" + query[6:14] + b"\0\0\0\x01", sender)
        row = self.wait_for(lambda d: fixtures.server_state(d, "proxy") == "ok")
        self.assertEqual(fixtures.rows(row)["proxy"]["members"][0]["server"]["detail"], "local_quic")
        self.config.write_text('{"outbounds": [')
        self.wait_for(lambda d: fixtures.server_state(d, "proxy") == "unsupported")
        self.write([self.core("proxy", alpn=["h2"])])
        row = self.wait_for(lambda d: fixtures.server_state(d, "proxy") == "ok")
        self.assertEqual(fixtures.rows(row)["proxy"]["members"][0]["server"]["detail"], "local_tcp")
        self.assertNotIn("private-fixture-id", self.output.read_text())

    def test_xhttp_tag_endpoint_transport_and_group_matching(self):
        names = ["proxy", "duplicate", "wrongPort", "wrongProto", "wrongNet", "wrongSecurity", "badALPN",
                 "reality", "noTLS", "group"]
        self.api.names = names
        labels = {"reality": "vless(xhttp+reality)", "noTLS": "vless(xhttp)"}
        for n, name in enumerate(names, 1):
            self.api.servers.append(fixtures.profile(n, name, self.open_port, labels.get(name, "vless(xhttp+tls)")))
            self.api.connected = (self.api.connected or []) + [fixtures.assignment(name, n)]
        self.api.servers.append(fixtures.profile(11, "unusedSelector", self.open_port, "vless(xhttp+tls)"))
        self.api.connected.append(fixtures.assignment("group", 11))
        wrong_proto, wrong_net = self.core("wrongProto"), self.core("wrongNet")
        wrong_proto["protocol"] = "vmess"
        wrong_net["streamSettings"]["network"] = "ws"
        self.write([self.core("proxy", alpn=["h2", "h3"]), self.core("duplicate"), self.core("duplicate"),
                    self.core("wrongPort", endpoint=self.closed_port), wrong_proto, wrong_net,
                    self.core("wrongSecurity", security="reality"), self.core("badALPN", alpn="h3"),
                    self.core("reality", security="reality", alpn=["h3"]), self.core("noTLS", security="none"),
                    self.core("『group』"), self.core("『unusedSelector』")],
                   {"balancers": [{"tag": "group", "selector": ["『group』"]}]})
        self.start("--xray-config", str(self.config))
        expected = dict.fromkeys(names, "unsupported")
        expected.update(dict.fromkeys(["proxy", "group", "reality", "noTLS"], "ok"))
        row = self.wait_for(lambda d: all(fixtures.server_state(d, k) == v for k, v in expected.items()))
        self.assertEqual(fixtures.rows(row)["group"]["members"][1]["server"]["state"], "unsupported")
