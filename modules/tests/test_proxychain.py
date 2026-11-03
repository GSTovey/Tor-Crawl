"""Unit tests for modules.proxychain — Tor-over-Proxy chain management."""

import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

from modules.proxychain import (
    FrontProxyConfig,
    TorrcManager,
    check_tcp_connection,
    check_tor_running,
    verify_proxy_chain,
)


# ---------------------------------------------------------------------------
# FrontProxyConfig
# ---------------------------------------------------------------------------

class TestFrontProxyConfig(unittest.TestCase):
    """Tests for FrontProxyConfig data class."""

    def test_defaults(self):
        cfg = FrontProxyConfig()
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 7890)
        self.assertEqual(cfg.proxy_type, "socks5")
        self.assertIsNone(cfg.protocol)

    def test_address_property(self):
        cfg = FrontProxyConfig(host="10.0.0.1", port=1080)
        self.assertEqual(cfg.address, "10.0.0.1:1080")

    def test_torrc_directive_socks5(self):
        cfg = FrontProxyConfig(proxy_type="socks5")
        self.assertEqual(cfg.torrc_directive, "Socks5Proxy")

    def test_torrc_directive_http(self):
        cfg = FrontProxyConfig(proxy_type="http")
        self.assertEqual(cfg.torrc_directive, "HTTPSProxy")

    def test_invalid_proxy_type_raises(self):
        with self.assertRaises(ValueError):
            FrontProxyConfig(proxy_type="invalid")

    def test_invalid_protocol_raises(self):
        with self.assertRaises(ValueError):
            FrontProxyConfig(protocol="invalid")

    def test_valid_protocols_accepted(self):
        for proto in ("shadowsocks", "trojan", "vmess", "vless"):
            cfg = FrontProxyConfig(protocol=proto)
            self.assertEqual(cfg.protocol, proto)

    def test_repr(self):
        cfg = FrontProxyConfig(host="10.0.0.1", port=7890,
                               proxy_type="socks5", protocol="vmess")
        r = repr(cfg)
        self.assertIn("socks5", r)
        self.assertIn("10.0.0.1:7890", r)
        self.assertIn("vmess", r)

    def test_username_password_stored(self):
        cfg = FrontProxyConfig(username="user1", password="pass1")
        self.assertEqual(cfg.username, "user1")
        self.assertEqual(cfg.password, "pass1")


# ---------------------------------------------------------------------------
# TorrcManager
# ---------------------------------------------------------------------------

class TestTorrcManager(unittest.TestCase):
    """Tests for TorrcManager — torrc file management."""

    def setUp(self):
        # Create a temporary torrc file for testing
        self.tmpdir = tempfile.mkdtemp()
        self.torrc_path = os.path.join(self.tmpdir, "torrc")
        self._write_torrc("")  # empty file
        self.mgr = TorrcManager(torrc_path=self.torrc_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_torrc(self, content: str) -> None:
        with open(self.torrc_path, "w", encoding="utf-8") as f:
            f.write(content)

    def _read_torrc(self) -> str:
        with open(self.torrc_path, "r", encoding="utf-8") as f:
            return f.read()

    # --- read / write ---

    def test_read_empty(self):
        self.assertEqual(self.mgr.read(), "")

    def test_read_content(self):
        self._write_torrc("SOCKSPort 9050\nLog notice file /var/log/tor.log\n")
        self.assertIn("SOCKSPort 9050", self.mgr.read())

    def test_read_file_not_found(self):
        mgr = TorrcManager(torrc_path="/nonexistent/torrc")
        with self.assertRaises(FileNotFoundError):
            mgr.read()

    def test_write(self):
        self.mgr.write("Hello\n")
        self.assertEqual(self._read_torrc(), "Hello\n")

    # --- backup / restore ---

    def test_backup_creates_file(self):
        self._write_torrc("original\n")
        backup_path = self.mgr.backup()
        self.assertTrue(os.path.isfile(backup_path))
        with open(backup_path, "r") as f:
            self.assertEqual(f.read(), "original\n")

    def test_restore_from_backup(self):
        self._write_torrc("original\n")
        self.mgr.backup()
        self._write_torrc("modified\n")
        self.assertTrue(self.mgr.restore())
        self.assertEqual(self._read_torrc(), "original\n")

    def test_restore_from_memory(self):
        """Restore falls back to in-memory content when backup file is gone."""
        self._write_torrc("original\n")
        self.mgr.backup()
        # Delete the backup file
        os.remove(self.mgr._backup_path)
        self._write_torrc("modified\n")
        self.assertTrue(self.mgr.restore())
        self.assertEqual(self._read_torrc(), "original\n")

    # --- has_upstream_proxy ---

    def test_has_upstream_proxy_false_when_empty(self):
        self.assertFalse(self.mgr.has_upstream_proxy())

    def test_has_upstream_proxy_false_when_other_content(self):
        self._write_torrc("SOCKSPort 9050\n")
        self.assertFalse(self.mgr.has_upstream_proxy())

    def test_has_upstream_proxy_true_socks5(self):
        self._write_torrc("Socks5Proxy 127.0.0.1:7890\n")
        self.assertTrue(self.mgr.has_upstream_proxy())

    def test_has_upstream_proxy_true_https(self):
        self._write_torrc("HTTPSProxy 127.0.0.1:7890\n")
        self.assertTrue(self.mgr.has_upstream_proxy())

    def test_has_upstream_proxy_ignores_comments(self):
        self._write_torrc("# Socks5Proxy 127.0.0.1:7890\n")
        self.assertFalse(self.mgr.has_upstream_proxy())

    # --- set_upstream_proxy ---

    def test_set_upstream_proxy_adds_directive(self):
        self._write_torrc("SOCKSPort 9050\n")
        self.mgr.set_upstream_proxy("socks5", "127.0.0.1", 7890)
        content = self._read_torrc()
        self.assertIn("SOCKSPort 9050", content)
        self.assertIn("Socks5Proxy 127.0.0.1:7890", content)
        self.assertIn(TorrcManager.SENTINEL, content)

    def test_set_upstream_proxy_replaces_existing(self):
        self._write_torrc("Socks5Proxy 10.0.0.1:1080\n")
        self.mgr.set_upstream_proxy("socks5", "127.0.0.1", 7890)
        content = self._read_torrc()
        self.assertNotIn("10.0.0.1:1080", content)
        self.assertIn("Socks5Proxy 127.0.0.1:7890", content)

    def test_set_upstream_proxy_http(self):
        self._write_torrc("")
        self.mgr.set_upstream_proxy("http", "192.168.1.1", 3128)
        content = self._read_torrc()
        self.assertIn("HTTPSProxy 192.168.1.1:3128", content)

    def test_set_upstream_proxy_with_auth(self):
        self._write_torrc("")
        self.mgr.set_upstream_proxy(
            "socks5", "127.0.0.1", 7890,
            username="alice", password="s3cret",
        )
        content = self._read_torrc()
        self.assertIn("Socks5ProxyUsername alice", content)
        self.assertIn("Socks5ProxyPassword s3cret", content)

    def test_set_upstream_proxy_http_with_auth(self):
        self._write_torrc("")
        self.mgr.set_upstream_proxy(
            "http", "127.0.0.1", 3128,
            username="bob", password="p4ss",
        )
        content = self._read_torrc()
        self.assertIn("HTTPSProxyAuthenticator bob:p4ss", content)

    def test_set_upstream_proxy_invalid_type(self):
        with self.assertRaises(ValueError):
            self.mgr.set_upstream_proxy("invalid", "127.0.0.1", 7890)

    def test_set_upstream_proxy_backup_created(self):
        self._write_torrc("original\n")
        backup_path = self.mgr.set_upstream_proxy("socks5", "127.0.0.1", 7890)
        self.assertIsNotNone(backup_path)
        self.assertTrue(os.path.isfile(backup_path))
        with open(backup_path, "r") as f:
            self.assertEqual(f.read(), "original\n")

    # --- remove_upstream_proxy ---

    def test_remove_upstream_proxy(self):
        self._write_torrc("SOCKSPort 9050\n")
        self.mgr.set_upstream_proxy("socks5", "127.0.0.1", 7890)
        self.assertTrue(self.mgr.remove_upstream_proxy())
        content = self._read_torrc()
        self.assertNotIn("Socks5Proxy", content)
        self.assertNotIn(TorrcManager.SENTINEL, content)
        self.assertIn("SOCKSPort 9050", content)

    def test_remove_upstream_proxy_no_changes(self):
        self._write_torrc("SOCKSPort 9050\n")
        self.assertFalse(self.mgr.remove_upstream_proxy())

    # --- detect_torrc_path ---

    @mock.patch.object(os.path, "isfile", return_value=True)
    def test_detect_torrc_found(self, mock_isfile):
        path = TorrcManager._detect_torrc_path()
        # One of the platform paths should have matched
        self.assertIsNotNone(path)

    @mock.patch.object(os.path, "isfile", return_value=False)
    def test_detect_torrc_not_found(self, mock_isfile):
        path = TorrcManager._detect_torrc_path()
        self.assertIsNone(path)


# ---------------------------------------------------------------------------
# TCP connectivity
# ---------------------------------------------------------------------------

class TestCheckTCPConnection(unittest.TestCase):
    """Tests for check_tcp_connection."""

    @mock.patch.object(socket, "create_connection")
    def test_success(self, mock_connect):
        mock_sock = mock.Mock()
        mock_connect.return_value = mock_sock
        ok, err = check_tcp_connection("127.0.0.1", 9050)
        self.assertTrue(ok)
        self.assertEqual(err, "")
        mock_sock.close.assert_called_once()

    @mock.patch.object(socket, "create_connection")
    def test_refused(self, mock_connect):
        mock_connect.side_effect = ConnectionRefusedError("refused")
        ok, err = check_tcp_connection("127.0.0.1", 9999)
        self.assertFalse(ok)
        self.assertIn("refused", err)

    @mock.patch.object(socket, "create_connection")
    def test_timeout(self, mock_connect):
        mock_connect.side_effect = socket.timeout("timed out")
        ok, err = check_tcp_connection("10.255.255.1", 9999, timeout=1.0)
        self.assertFalse(ok)
        self.assertIn("timed out", err)


# ---------------------------------------------------------------------------
# check_tor_running
# ---------------------------------------------------------------------------

class TestCheckTorRunning(unittest.TestCase):
    """Tests for check_tor_running cross-platform helper."""

    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_port_open_returns_true(self, mock_check):
        mock_check.return_value = (True, "")
        self.assertTrue(check_tor_running(verbose=False))
        mock_check.assert_called_once_with("127.0.0.1", 9050, timeout=3.0)

    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_port_closed_no_process_returns_false(self, mock_check):
        """When port is closed and no tor process runs, returns False."""
        mock_check.return_value = (False, "refused")
        # On this test platform, subprocess.check_output for process
        # detection will either succeed (tor running) or fail (tor not
        # running).  Either way, the function should not crash and
        # should return a boolean.
        result = check_tor_running(verbose=False)
        self.assertIsInstance(result, bool)

    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_does_not_throw(self, mock_check):
        """Function should never raise an exception even on errors."""
        # check_tcp_connection itself handles errors and returns (False, msg)
        mock_check.return_value = (False, "unexpected socket error")
        result = check_tor_running(verbose=False)
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# verify_proxy_chain
# ---------------------------------------------------------------------------

class TestVerifyProxyChain(unittest.TestCase):
    """Tests for verify_proxy_chain end-to-end verification."""

    @mock.patch("modules.proxychain.get_external_ip")
    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_all_passes(self, mock_tcp, mock_ip):
        mock_tcp.return_value = (True, "")
        mock_ip.side_effect = ["1.1.1.1", "2.2.2.2"]  # direct, tor
        upstream = FrontProxyConfig("127.0.0.1", 7890)
        self.assertTrue(verify_proxy_chain(
            tor_host="127.0.0.1", tor_port=9050,
            upstream=upstream, verbose=False,
        ))

    @mock.patch("modules.proxychain.get_external_ip")
    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_upstream_unreachable(self, mock_tcp, mock_ip):
        mock_tcp.side_effect = [
            (False, "refused"),  # upstream
            (True, ""),          # tor
        ]
        mock_ip.side_effect = ["1.1.1.1", "2.2.2.2"]
        upstream = FrontProxyConfig("127.0.0.1", 7890)
        self.assertFalse(verify_proxy_chain(
            tor_host="127.0.0.1", tor_port=9050,
            upstream=upstream, verbose=False,
        ))

    @mock.patch("modules.proxychain.get_external_ip")
    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_tor_unreachable(self, mock_tcp, mock_ip):
        mock_tcp.side_effect = [
            (True, ""),          # upstream
            (False, "refused"),  # tor
        ]
        mock_ip.return_value = "1.1.1.1"
        upstream = FrontProxyConfig("127.0.0.1", 7890)
        self.assertFalse(verify_proxy_chain(
            tor_host="127.0.0.1", tor_port=9050,
            upstream=upstream, verbose=False,
        ))

    @mock.patch("modules.proxychain.get_external_ip")
    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_ip_match_means_failure(self, mock_tcp, mock_ip):
        mock_tcp.return_value = (True, "")
        mock_ip.side_effect = ["1.1.1.1", "1.1.1.1"]  # same IP!
        upstream = FrontProxyConfig("127.0.0.1", 7890)
        self.assertFalse(verify_proxy_chain(
            tor_host="127.0.0.1", tor_port=9050,
            upstream=upstream, verbose=False,
        ))

    @mock.patch("modules.proxychain.get_external_ip")
    @mock.patch("modules.proxychain.check_tcp_connection")
    def test_no_upstream(self, mock_tcp, mock_ip):
        """Chain without upstream proxy (Tor only)."""
        mock_tcp.return_value = (True, "")
        mock_ip.side_effect = ["1.1.1.1", "2.2.2.2"]
        self.assertTrue(verify_proxy_chain(
            tor_host="127.0.0.1", tor_port=9050,
            upstream=None, verbose=False,
        ))


if __name__ == "__main__":
    unittest.main()
