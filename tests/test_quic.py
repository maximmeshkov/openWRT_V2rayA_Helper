"""Exercise the native daemon with a UDP-only QUIC Version Negotiation fixture."""
import select
import socket
import test_monitor as fixtures


class QuicTest(fixtures.MonitorHarness):
    def probe(self, net, reply, *, family=socket.AF_INET, host=None):
        udp = socket.socket(family, socket.SOCK_DGRAM)
        self.addCleanup(udp.close)
        udp.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        port = udp.getsockname()[1]
        listeners = [udp]
        if host == "localhost":
            v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.addCleanup(v4.close)
            v4.bind(("127.0.0.1", port))
            listeners.append(v4)
        address = f"{host or '127.0.0.1'}:{port}"
        self.api.servers = [fixtures.profile(1, "QUIC only", address, net)]
        self.api.connected = [fixtures.assignment("proxy", 1)]
        self.start()
        ready, _, _ = select.select(listeners, [], [], 4)
        self.assertTrue(ready, "monitor did not send a QUIC probe")
        received_on = ready[0]
        query, sender = received_on.recvfrom(65535)
        self.assertEqual(len(query), 1200)
        self.assertTrue(query[0] & 0x80)
        self.assertEqual(query[1:5], bytes.fromhex("1a2a3a4a"))
        dlen = query[5]
        slen = query[6 + dlen]
        self.assertEqual((dlen, slen), (8, 8))
        dcid = query[6:6 + dlen]
        scid = query[7 + dlen:7 + dlen + slen]
        if reply is not None:
            packet = b"\x80\0\0\0\0" + bytes([slen]) + scid + bytes([dlen]) + dcid
            received_on.sendto(reply(packet, query), sender)
        snapshot = self.wait_for(lambda s: fixtures.server_state(s, "proxy")
                                 in ("ok", "error", "timeout"))
        row = fixtures.rows(snapshot)["proxy"]
        self.assertEqual(row["route"]["state"], "unknown")
        return row["members"][0]["server"]

    def test_quic_round_trip(self):
        result = self.probe("tuic", lambda header, _: header + (1).to_bytes(4, "big"))
        self.assertEqual((result["state"], result["detail"]), ("ok", "local_quic"))
        self.assertGreaterEqual(result["ms"], 0)

    def test_quic_resolver_with_localhost(self):
        if not socket.has_dualstack_ipv6():
            self.skipTest("needs a dual-stack loopback responder")
        result = self.probe("juicity", lambda header, _: header + (1).to_bytes(4, "big"),
                            family=socket.AF_INET6, host="localhost")
        self.assertEqual(result["detail"], "local_quic")

    def test_quic_rejects_wrong_connection_id(self):
        def reply(header, _):
            changed = bytearray(header)
            changed[6] ^= 0xff
            return changed + (1).to_bytes(4, "big")
        result = self.probe("hysteria2", reply)
        self.assertEqual(result["detail"], "quic_invalid_reply")
        self.assertNotIn("ms", result)

    def test_quic_rejects_negotiation_for_its_own_version(self):
        result = self.probe("tuic", lambda header, query: header + query[1:5])
        self.assertEqual(result["detail"], "quic_invalid_reply")

    def test_quic_response_is_required(self):
        result = self.probe("tuic", None)
        self.assertEqual((result["state"], result["detail"]), ("timeout", "quic_no_reply"))
        self.assertNotIn("ms", result)
