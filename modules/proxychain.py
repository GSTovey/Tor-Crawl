#!/usr/bin/python
"""
Tor-over-Proxy chain management for TorCrawl.py.

Handles:
- Torrc configuration file management (read, write, backup, restore)
- Front proxy configuration and validation
- Multi-hop proxy chain verification
- Cross-platform Tor service detection and reload

Supports Clash/V2Ray as front proxy with protocols:
Shadowsocks, Trojan, VMess, VLESS
"""

import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from json import load as json_load
from typing import Optional, Tuple
from urllib.error import HTTPError
from urllib.request import urlopen


# ---------------------------------------------------------------------------
# Platform-specific torrc path detection
# ---------------------------------------------------------------------------

_TORRC_PATHS = {
    "win32": [
        # Tor Browser default
        os.path.expandvars(r"%APPDATA%\Tor\torrc"),
        # Expert Bundle
        os.path.expandvars(r"%PROGRAMFILES%\Tor\torrc"),
        # Manual installs
        r"C:\Tor\torrc",
        r"C:\tor-win64\torrc",
    ],
    "darwin": [
        "/usr/local/etc/tor/torrc",
        "/opt/homebrew/etc/tor/torrc",
        os.path.expanduser(
            "~/Library/Application Support/TorBrowser-Data/Tor/torrc"
        ),
    ],
    "linux": [
        "/etc/tor/torrc",
        os.path.expanduser("~/.tor/torrc"),
    ],
}

# Mapping of user-facing proxy type names to torrc directive names
_UPSTREAM_PROXY_DIRECTIVES = {
    "socks5": "Socks5Proxy",
    "http": "HTTPSProxy",
}


# ---------------------------------------------------------------------------
# FrontProxyConfig
# ---------------------------------------------------------------------------

class FrontProxyConfig:
    """Configuration for a front proxy (Clash/V2Ray) that sits before Tor.

    Attributes:
        host: Proxy hostname or IP (default: 127.0.0.1).
        port: Proxy port (default: 7890, common Clash default).
        proxy_type: Local interface type - 'socks5' or 'http'.
        protocol: Remote protocol - 'shadowsocks', 'trojan', 'vmess', 'vless'.
                  Informational only; does not change app behaviour.
        username: Optional proxy authentication username.
        password: Optional proxy authentication password.
    """

    VALID_PROXY_TYPES = ("socks5", "http")
    VALID_PROTOCOLS = ("shadowsocks", "trojan", "vmess", "vless")

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 7890,
        proxy_type: str = "socks5",
        protocol: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        if proxy_type not in self.VALID_PROXY_TYPES:
            raise ValueError(
                f"Invalid proxy_type '{proxy_type}'. "
                f"Use one of: {', '.join(self.VALID_PROXY_TYPES)}"
            )
        if protocol is not None and protocol not in self.VALID_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol '{protocol}'. "
                f"Use one of: {', '.join(self.VALID_PROTOCOLS)}"
            )

        self.host = host
        self.port = int(port)
        self.proxy_type = proxy_type
        self.protocol = protocol
        self.username = username
        self.password = password

    @property
    def address(self) -> str:
        """Return 'host:port' string."""
        return f"{self.host}:{self.port}"

    @property
    def torrc_directive(self) -> str:
        """Return the torrc directive name (Socks5Proxy or HTTPSProxy)."""
        return _UPSTREAM_PROXY_DIRECTIVES[self.proxy_type]

    def __repr__(self) -> str:
        protocol_info = f" ({self.protocol})" if self.protocol else ""
        return (f"FrontProxyConfig({self.proxy_type}://{self.address}"
                f"{protocol_info})")


# ---------------------------------------------------------------------------
# TorrcManager
# ---------------------------------------------------------------------------

class TorrcManager:
    """Manage Tor configuration file (torrc).

    Handles detection, reading, backing up, updating, and restoring
    the torrc file across Linux, macOS, and Windows.

    Usage:
        mgr = TorrcManager()
        mgr.backup()
        mgr.set_upstream_proxy("socks5", "127.0.0.1", 7890)
        mgr.reload_tor()
        # ... crawl ...
        mgr.restore()
    """

    # Sentinel comment added to torrc so we can identify and clean up our
    # own modifications.
    SENTINEL = "# Added by TorCrawl.py"

    def __init__(self, torrc_path: Optional[str] = None):
        """Initialise the manager.

        Args:
            torrc_path: Path to torrc. Auto-detected if None.
        """
        self.torrc_path = torrc_path or self._detect_torrc_path()
        self._backup_path: Optional[str] = None
        self._original_content: Optional[str] = None

    # --- Static helpers ---------------------------------------------------

    @staticmethod
    def _detect_torrc_path() -> Optional[str]:
        """Auto-detect torrc path for the current platform.

        Returns:
            Path to torrc if found, None otherwise.
        """
        platform = sys.platform
        paths = _TORRC_PATHS.get(platform, _TORRC_PATHS["linux"])
        for path in paths:
            if os.path.isfile(path):
                return path
        return None

    # --- Read / Write ----------------------------------------------------

    def read(self) -> str:
        """Read the full contents of the torrc file.

        Returns:
            String contents of torrc.

        Raises:
            FileNotFoundError: If torrc does not exist.
            PermissionError: If torrc is not readable.
        """
        if not self.torrc_path:
            raise FileNotFoundError("torrc path is not set and could not be "
                                    "auto-detected.")
        with open(self.torrc_path, 'r', encoding='utf-8') as f:
            return f.read()

    def write(self, content: str) -> None:
        """Write content to the torrc file.

        Args:
            content: Full new content for torrc.
        """
        if not self.torrc_path:
            raise FileNotFoundError("torrc path is not set.")
        with open(self.torrc_path, 'w', encoding='utf-8') as f:
            f.write(content)

    # --- Backup / Restore ------------------------------------------------

    def backup(self) -> str:
        """Create a timestamped backup of torrc.

        Reads the current content into memory and writes a backup file to
        the same directory as torrc.

        Returns:
            Path to the backup file.

        Raises:
            FileNotFoundError: If torrc does not exist.
        """
        if not self.torrc_path:
            raise FileNotFoundError("torrc path is not set.")

        # Save original content in memory
        self._original_content = self.read()

        # Write backup file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"torrc.backup.{timestamp}"
        backup_dir = os.path.dirname(self.torrc_path)
        self._backup_path = os.path.join(backup_dir, backup_name)

        shutil.copy2(self.torrc_path, self._backup_path)
        return self._backup_path

    def restore(self) -> bool:
        """Restore torrc from the most recent backup.

        Tries to restore from the on-disk backup first, then falls back
        to the in-memory original content.

        Returns:
            True if restoration succeeded, False otherwise.
        """
        if not self.torrc_path:
            return False

        # Try on-disk backup first
        if self._backup_path and os.path.isfile(self._backup_path):
            shutil.copy2(self._backup_path, self.torrc_path)
            return True

        # Fall back to in-memory content
        if self._original_content is not None:
            self.write(self._original_content)
            return True

        return False

    # --- Upstream proxy management ---------------------------------------

    def has_upstream_proxy(self) -> bool:
        """Check whether torrc already has an upstream proxy directive.

        Returns:
            True if an uncommented Socks5Proxy or HTTPSProxy line exists.
        """
        try:
            content = self.read()
        except FileNotFoundError:
            return False

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if (stripped.startswith('Socks5Proxy ') or
                    stripped.startswith('HTTPSProxy ')):
                return True
        return False

    def set_upstream_proxy(
        self,
        proxy_type: str,
        host: str,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verbose: bool = False,
    ) -> Optional[str]:
        """Add or replace an upstream proxy directive in torrc.

        Existing upstream proxy directives (Socks5Proxy, HTTPSProxy, and
        their authentication variants) are removed before the new one is
        appended.  A backup is created automatically before modification.

        Args:
            proxy_type: 'socks5' or 'http'.
            host: Upstream proxy hostname/IP.
            port: Upstream proxy port.
            username: Optional proxy username.
            password: Optional proxy password.
            verbose: Print progress messages.

        Returns:
            Path to the backup file, or None if the operation failed.

        Raises:
            ValueError: If proxy_type is invalid.
        """
        if proxy_type not in _UPSTREAM_PROXY_DIRECTIVES:
            raise ValueError(
                f"Unsupported proxy type: {proxy_type}. "
                f"Use 'socks5' or 'http'."
            )

        if not self.torrc_path:
            print("## ERROR: torrc path is not set.")
            return None

        directive = _UPSTREAM_PROXY_DIRECTIVES[proxy_type]

        # Backup before touching anything
        backup_path = self.backup()
        if verbose:
            print(f"## torrc backed up to: {backup_path}")

        try:
            content = self.read()
        except FileNotFoundError:
            print(f"## ERROR: torrc not found at {self.torrc_path}")
            return None

        lines = content.splitlines()

        # Build the new directive
        proxy_line = f"{directive} {host}:{port}"

        # Remove existing upstream proxy directives and our own sentinel
        directives_to_remove = {
            'Socks5Proxy', 'HTTPSProxy',
            'Socks5ProxyUsername', 'Socks5ProxyPassword',
            'HTTPSProxyAuthenticator',
        }
        new_lines = []
        skip_next_sentinel = False
        for line in lines:
            stripped = line.strip()
            # Skip our own sentinel comment
            if stripped == self.SENTINEL:
                skip_next_sentinel = True
                continue
            # If the previous line was our sentinel, this is our directive
            if skip_next_sentinel:
                skip_next_sentinel = False
                continue
            # Skip existing upstream proxy directives
            if any(stripped.startswith(d + ' ') or stripped == d
                   for d in directives_to_remove):
                continue
            new_lines.append(line)

        # Append new configuration block
        new_lines.append("")
        new_lines.append(self.SENTINEL)
        new_lines.append(proxy_line)

        # Append auth lines if provided
        if username and password and proxy_type == "socks5":
            new_lines.append(f"Socks5ProxyUsername {username}")
            new_lines.append(f"Socks5ProxyPassword {password}")
        elif username and password and proxy_type == "http":
            new_lines.append(f"HTTPSProxyAuthenticator {username}:{password}")

        new_content = "\n".join(new_lines) + "\n"
        self.write(new_content)

        if verbose:
            print(f"## torrc updated: '{proxy_line}'")

        return backup_path

    def remove_upstream_proxy(self, verbose: bool = False) -> bool:
        """Remove upstream proxy directives added by TorCrawl.py.

        Returns:
            True if changes were made, False otherwise.
        """
        if not self.torrc_path:
            return False

        try:
            content = self.read()
        except FileNotFoundError:
            return False

        directives_to_remove = {
            'Socks5Proxy', 'HTTPSProxy',
            'Socks5ProxyUsername', 'Socks5ProxyPassword',
            'HTTPSProxyAuthenticator',
        }

        new_lines = []
        changed = False
        skip_next = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == self.SENTINEL:
                skip_next = True
                changed = True
                continue

            if skip_next:
                skip_next = False
                changed = True
                continue

            if any(stripped.startswith(d + ' ') or stripped == d
                   for d in directives_to_remove):
                changed = True
                continue

            new_lines.append(line)

        if changed:
            self.write("\n".join(new_lines) + "\n")
            if verbose:
                print(f"## Removed upstream proxy configuration from torrc")

        return changed

    # --- Tor reload ------------------------------------------------------

    @staticmethod
    def reload_tor(verbose: bool = False) -> bool:
        """Reload Tor configuration.

        On POSIX, sends SIGHUP to the tor process.
        On Windows, attempts to restart the Tor service via sc.exe.

        Returns:
            True if reload was initiated, False otherwise.
        """
        platform = sys.platform

        if platform in ("linux", "darwin"):
            # Try pkill first (most portable)
            try:
                subprocess.run(
                    ["pkill", "-HUP", "tor"],
                    check=False, timeout=5,
                )
                if verbose:
                    print("## Sent SIGHUP to Tor via pkill")
                return True
            except Exception:
                pass

            # Fallback: pgrep + kill
            try:
                result = subprocess.run(
                    ["pgrep", "-x", "tor"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    pid = int(result.stdout.strip().split('\n')[0])
                    os.kill(pid, 16)  # SIGTERM fallback if no signal module
                    if verbose:
                        print(f"## Sent signal to Tor (PID {pid})")
                    return True
            except Exception:
                pass

            print("## Warning: Could not reload Tor automatically.")
            print("## Please run: sudo systemctl reload tor  (or equivalent)")
            return False

        elif platform == "win32":
            # Try sc.exe to restart Tor service
            try:
                subprocess.run(
                    ["sc", "stop", "tor"],
                    check=False, timeout=10,
                    capture_output=True,
                )
                subprocess.run(
                    ["sc", "start", "tor"],
                    check=False, timeout=10,
                    capture_output=True,
                )
                if verbose:
                    print("## Restarted Tor service via sc.exe")
                return True
            except Exception as e:
                print(f"## Warning: Could not restart Tor service: {e}")
                print("## Please restart Tor manually via Services or "
                      "Task Manager")
                return False

        return False


# ---------------------------------------------------------------------------
# Connectivity checks
# ---------------------------------------------------------------------------

def check_tcp_connection(
    host: str, port: int, timeout: float = 5.0
) -> Tuple[bool, str]:
    """Test whether a TCP connection can be established to host:port.

    Args:
        host: Hostname or IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        Tuple of (success, error_message).
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True, ""
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return False, str(e)


def get_external_ip(
    proxy_host: Optional[str] = None,
    proxy_port: Optional[int] = None,
    timeout: float = 10.0,
) -> Optional[str]:
    """Get the externally visible IP address.

    When proxy_host/proxy_port are provided, the request is routed through
    that SOCKS5 proxy by temporarily monkey-patching the socket.  The
    original socket state is restored afterwards.

    Args:
        proxy_host: Optional SOCKS5 proxy host.
        proxy_port: Optional SOCKS5 proxy port.
        timeout: Request timeout in seconds.

    Returns:
        IP address string, or None on failure.
    """
    api_url = 'https://api.ipify.org/?format=json'

    if proxy_host and proxy_port:
        original_socket = socket.socket
        original_getaddrinfo = socket.getaddrinfo
        try:
            import socks
            socks.setdefaultproxy(
                socks.PROXY_TYPE_SOCKS5, proxy_host, proxy_port
            )
            socket.socket = socks.socksocket
            socket.getaddrinfo = lambda *args: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '',
                 (args[0], args[1]))
            ]
            response = urlopen(api_url, timeout=timeout)
            return json_load(response)['ip']
        except Exception:
            return None
        finally:
            socket.socket = original_socket
            socket.getaddrinfo = original_getaddrinfo
    else:
        try:
            response = urlopen(api_url, timeout=timeout)
            return json_load(response)['ip']
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def verify_proxy_chain(
    tor_host: str = "127.0.0.1",
    tor_port: int = 9050,
    upstream: Optional[FrontProxyConfig] = None,
    verbose: bool = False,
) -> bool:
    """Verify the full proxy chain end-to-end.

    Checks:
    1. TCP connectivity to the upstream (front) proxy (if configured).
    2. TCP connectivity to the local Tor SOCKS5 port.
    3. External IP through Tor is different from direct IP.

    Args:
        tor_host: Local Tor SOCKS5 host.
        tor_port: Local Tor SOCKS5 port.
        upstream: FrontProxyConfig for the upstream proxy, or None.
        verbose: Print detailed progress.

    Returns:
        True if all checks pass.
    """
    all_ok = True

    # Step 1: Upstream proxy connectivity
    if upstream is not None:
        if verbose:
            print(f"## [1/3] Checking upstream proxy "
                  f"({upstream.proxy_type}://{upstream.address})...")
        ok, err = check_tcp_connection(upstream.host, upstream.port)
        if not ok:
            print(f"## FAIL: Cannot reach upstream proxy at "
                  f"{upstream.address}: {err}")
            print("## Is Clash/V2Ray running?")
            all_ok = False
        elif verbose:
            print(f"##   OK: Upstream proxy reachable")

    # Step 2: Local Tor connectivity
    if verbose:
        print(f"## [2/3] Checking local Tor SOCKS5 "
              f"({tor_host}:{tor_port})...")
    ok, err = check_tcp_connection(tor_host, tor_port)
    if not ok:
        print(f"## FAIL: Cannot reach Tor at {tor_host}:{tor_port}: {err}")
        print("## Is Tor running?")
        all_ok = False
    elif verbose:
        print(f"##   OK: Tor SOCKS5 port reachable")

    if not all_ok:
        return False

    # Step 3: IP comparison
    if verbose:
        print(f"## [3/3] Verifying Tor is routing traffic...")

    direct_ip = get_external_ip()
    tor_ip = get_external_ip(proxy_host=tor_host, proxy_port=tor_port)

    if direct_ip and verbose:
        print(f"##   Direct IP: {direct_ip}")
    if tor_ip and verbose:
        print(f"##   Tor exit IP: {tor_ip}")

    if direct_ip and tor_ip:
        if tor_ip == direct_ip:
            print(f"## FAIL: Tor exit IP matches direct IP. "
                  f"Traffic is NOT going through Tor!")
            all_ok = False
        elif verbose:
            print(f"##   OK: IPs differ — Tor is working")
    elif not tor_ip:
        print(f"## FAIL: Cannot determine Tor exit IP. "
              f"Check Tor and upstream proxy configuration.")
        all_ok = False

    if all_ok and verbose:
        chain_desc = (
            f"You → Tor ({tor_host}:{tor_port})"
            + (f" → {upstream.proxy_type} ({upstream.address})"
               if upstream else "")
            + f" → Tor Network → Target"
        )
        print(f"## Chain verified: {chain_desc}")

    return all_ok


# ---------------------------------------------------------------------------
# Convenience: check if Tor service is running (cross-platform)
# ---------------------------------------------------------------------------

def check_tor_running(verbose: bool = False) -> bool:
    """Check if the Tor process is running (cross-platform).

    Uses TCP port check as primary method (most reliable).  Falls back to
    process-name detection for informational messages.

    Args:
        verbose: Print status messages.

    Returns:
        True if Tor appears to be running.
    """
    # Primary: TCP port check on the default SOCKS5 port
    ok, _ = check_tcp_connection("127.0.0.1", 9050, timeout=3.0)
    if ok:
        if verbose:
            print("## TOR is ready! (SOCKS5 port 9050 reachable)")
        return True

    # Secondary: process-name detection (platform-specific)
    platform = sys.platform
    tor_process = False

    if platform == "win32":
        try:
            output = subprocess.check_output(
                ['tasklist'], text=True, timeout=5
            )
            tor_process = 'tor.exe' in output.lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    else:
        try:
            output = subprocess.check_output(
                ['ps', '-e'], text=True, timeout=5
            )
            import re
            tor_process = bool(
                re.compile(r'\b(tor)\b', re.IGNORECASE).search(output)
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    if tor_process:
        if verbose:
            print("## TOR process found, but SOCKS5 port 9050 is not "
                  "responding.")
        return False

    return False
