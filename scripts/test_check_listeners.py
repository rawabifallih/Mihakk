"""Tests for check_listeners.py, against rows the kernel actually prints."""

from __future__ import annotations

import unittest

from check_listeners import judge

HEADER4 = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
           "retrnsmt   uid  timeout inode")
HEADER6 = ("  sl  local_address                         remote_address                "
           "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")


def row4(local, state="0A"):
    return (f"   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 "
            "00000000 10003        0 7060 1 0000000001c779be 100 0 0 10 0")


def row6(local, state="0A"):
    return (f"   0: {local} 00000000000000000000000000000000:0000 {state} "
            "00000000:00000000 00:00000000 00000000 0 0 7 1 0 100 0 0 10 0")


# Taken from the engine container: the liveness endpoint on 127.0.0.1:8901 and
# Docker's embedded DNS resolver on 127.0.0.11.
ENGINE = "\n".join([HEADER4, row4("0100007F:22C5"), row4("0B00007F:AB55"),
                    row4("0100007F:22C5", state="06"), HEADER6])


class TestListeners(unittest.TestCase):
    def test_the_engine_as_observed_is_loopback_only(self):
        code, lines = judge(ENGINE)
        self.assertEqual(code, 0, lines)
        self.assertIn("loopback only: 127.0.0.1:8901", lines)

    def test_every_interface_is_caught(self):
        code, lines = judge("\n".join([HEADER4, row4("00000000:22C4")]))
        self.assertEqual(code, 1)
        self.assertIn("LISTENS OFF LOOPBACK: 0.0.0.0:8900", lines)

    def test_a_real_address_is_caught(self):
        # 172.18.0.2 in kernel byte order.
        code, lines = judge("\n".join([HEADER4, row4("020012AC:22C4")]))
        self.assertEqual(code, 1, lines)
        self.assertIn("LISTENS OFF LOOPBACK: 172.18.0.2:8900", lines)

    def test_ipv6_any_and_loopback(self):
        any6 = row6("00000000000000000000000000000000:22C4")
        lo6 = row6("00000000000000000000000001000000:22C5")
        self.assertEqual(judge("\n".join([HEADER4, HEADER6, lo6]))[0], 0)
        self.assertEqual(judge("\n".join([HEADER4, HEADER6, any6]))[0], 1)

    def test_a_connection_that_is_not_listening_is_ignored(self):
        code, _ = judge("\n".join([HEADER4, row4("020012AC:22C4", state="01")]))
        self.assertEqual(code, 0)

    def test_unreadable_input_is_unverified(self):
        for text in ("", "garbage", "\n".join([row4("0100007F:22C5")]),
                     "\n".join([HEADER4, "   0: nothex:22C5 x 0A"]),
                     "\n".join([HEADER4, "not a row"]),
                     "\n".join([HEADER4, HEADER6, HEADER4])):
            self.assertEqual(judge(text)[0], 2, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
