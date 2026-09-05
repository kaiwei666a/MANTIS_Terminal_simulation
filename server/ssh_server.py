from __future__ import annotations

import os
import signal
import socket
import threading
import time
import uuid
import warnings
from typing import Iterable, Optional

try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import paramiko
from paramiko import SFTPServer

from runtime.shell_runtime import handle_exec_command_once, run_agent_shell
from storage.session_store import append_auth_log, log_attack
from transfer.file_transfer import (
    RootedSFTP,
    _parse_scp_exec,
    scp_serve_download,
    scp_serve_upload,
)
from terminal_config import (
    ECDSA_KEY_PATH,
    ED25519_KEY_PATH,
    HOST,
    HOSTNAME,
    PORT,
    RSA_KEY_PATH,
    ensure_runtime_directories,
)


def _generate_ed25519_host_keyfile(path: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as file:
        file.write(pem)


def _restrict_private_key_permissions(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def load_or_create_host_keys() -> list[paramiko.PKey]:
    keys: list[paramiko.PKey] = []

    try:
        if not os.path.exists(RSA_KEY_PATH):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(RSA_KEY_PATH)
            _restrict_private_key_permissions(RSA_KEY_PATH)
        keys.append(paramiko.RSAKey.from_private_key_file(RSA_KEY_PATH))
    except Exception as exc:
        log_attack(f"[!] Failed to initialize RSA host key: {exc}", "warn")

    try:
        if not os.path.exists(ED25519_KEY_PATH):
            _generate_ed25519_host_keyfile(ED25519_KEY_PATH)
            _restrict_private_key_permissions(ED25519_KEY_PATH)
        keys.append(paramiko.Ed25519Key.from_private_key_file(ED25519_KEY_PATH))
    except Exception as exc:
        log_attack(f"[!] Failed to initialize Ed25519 host key: {exc}", "warn")

    try:
        if not os.path.exists(ECDSA_KEY_PATH):
            key = paramiko.ECDSAKey.generate()
            key.write_private_key_file(ECDSA_KEY_PATH)
            _restrict_private_key_permissions(ECDSA_KEY_PATH)
        keys.append(paramiko.ECDSAKey.from_private_key_file(ECDSA_KEY_PATH))
    except Exception as exc:
        log_attack(f"[!] Failed to initialize ECDSA host key: {exc}", "warn")

    if not keys:
        raise RuntimeError("No SSH host key could be loaded or generated")
    return keys


class HoneypotServer(paramiko.ServerInterface):

    def __init__(self, session_id: str, remote_addr: str, local_port: int):
        super().__init__()
        self._session_id = session_id
        self._remote_addr = remote_addr
        self._local_port = local_port
        self.event = threading.Event()
        self.exec_command: Optional[str] = None
        self.shell_requested = False
        self.auth_username = ""
        self.pty_width = 80
        self.pty_height = 24

    def get_allowed_auths(self, username):
        return "none,password"

    def check_auth_password(self, username, password):
        self.auth_username = str(username)
        append_auth_log(
            event="ssh_auth_attempt",
            session_id=self._session_id,
            username=username,
            hostname=HOSTNAME,
            remote_addr=self._remote_addr,
            success=True,
            note="password auth accepted (ignored)",
            method="password",
            password=str(password),
            proto="ssh",
            local_port=self._local_port,
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        self.pty_width = max(20, int(width or 80))
        self.pty_height = max(5, int(height or 24))
        return True

    def check_channel_window_change_request(
        self, channel, width, height, pixelwidth, pixelheight
    ):
        self.pty_width = max(20, int(width or self.pty_width))
        self.pty_height = max(5, int(height or self.pty_height))
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        try:
            if isinstance(command, (bytes, bytearray)):
                self.exec_command = command.decode("utf-8", errors="ignore")
            else:
                self.exec_command = str(command)
        except Exception:
            self.exec_command = str(command)
        self.event.set()
        return True


class SSHServer:

    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        host_keys: Optional[Iterable[paramiko.PKey]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.host_keys = list(host_keys) if host_keys is not None else []
        self.stop_event = threading.Event()
        self.server_socket: Optional[socket.socket] = None

    def serve_forever(self) -> None:
        ensure_runtime_directories()
        if not self.host_keys:
            self.host_keys = load_or_create_host_keys()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)
        server_socket.settimeout(1.0)
        self.server_socket = server_socket
        log_attack(f"[*] Fake SSH server listening on {self.host}:{self.port}")

        try:
            while not self.stop_event.is_set():
                try:
                    client_socket, address = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise

                remote_addr = f"{address[0]}:{address[1]}"
                append_auth_log(
                    event="tcp_connect",
                    session_id="",
                    username="",
                    hostname=HOSTNAME,
                    remote_addr=remote_addr,
                    success=True,
                    note=f"SSH({self.port})",
                    proto="ssh",
                    local_port=self.port,
                )
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, address),
                    daemon=True,
                )
                thread.start()
        finally:
            self.close()
            log_attack("[*] SSH server stopped")

    def stop(self) -> None:
        self.stop_event.set()
        self.close()

    def close(self) -> None:
        server_socket = self.server_socket
        self.server_socket = None
        if server_socket is not None:
            try:
                server_socket.close()
            except Exception:
                pass

    def _handle_connection(self, client_socket, address) -> None:
        session_id = str(uuid.uuid4())
        remote_addr = f"{address[0]}:{address[1]}"
        login_username = ""
        append_auth_log(
            event="connect",
            session_id=session_id,
            username="",
            hostname=HOSTNAME,
            remote_addr=remote_addr,
            success=True,
            note="session opened",
            proto="ssh",
            local_port=self.port,
        )
        log_attack(f"[*] New connection from {remote_addr}, session={session_id}")

        transport = None
        channel = None
        try:
            client_socket.settimeout(15.0)
            transport = paramiko.Transport(client_socket)
            for host_key in self.host_keys:
                transport.add_server_key(host_key)

            server = HoneypotServer(
                session_id=session_id,
                remote_addr=remote_addr,
                local_port=self.port,
            )
            transport.set_subsystem_handler("sftp", SFTPServer, RootedSFTP)
            transport.start_server(server=server)

            channel = transport.accept(20)
            if channel is None:
                log_attack(f"[{session_id}] No channel, closing")
                return

            login_username = str(server.auth_username or transport.get_username() or "")
            if not login_username:
                raise paramiko.SSHException("authenticated username unavailable")
            append_auth_log(
                event="ssh_session_open",
                session_id=session_id,
                username=login_username,
                hostname=HOSTNAME,
                remote_addr=remote_addr,
                success=True,
                note="ssh session opened",
                proto="ssh",
                local_port=self.port,
            )

            for _ in range(40):
                if server.exec_command is not None or server.shell_requested:
                    break
                time.sleep(0.05)

            exec_command = server.exec_command
            if exec_command:
                mode, raw_path = _parse_scp_exec(exec_command)
                if mode == "download":
                    log_attack(f"[{session_id}] Handling SCP -f {raw_path}")
                    scp_serve_download(
                        channel, raw_path, session_id, remote_addr, login_username
                    )
                elif mode == "upload":
                    log_attack(f"[{session_id}] Handling SCP -t {raw_path}")
                    scp_serve_upload(
                        channel, raw_path, session_id, remote_addr, login_username
                    )
                else:
                    handle_exec_command_once(
                        channel,
                        session_id,
                        remote_addr,
                        exec_command,
                        login_username,
                    )
                return

            if server.shell_requested:
                run_agent_shell(
                    channel,
                    session_id,
                    remote_addr,
                    login_username,
                    terminal_state=server,
                )
                try:
                    channel.shutdown_write()
                except Exception:
                    pass
                time.sleep(0.15)
                return

            while transport.is_active() and not channel.closed:
                time.sleep(0.1)

        except Exception as exc:
            message = str(exc)
            if (
                isinstance(exc, (paramiko.SSHException, EOFError, socket.timeout))
                and "Error reading SSH protocol banner" in message
            ):
                log_attack(
                    f"[{session_id}] pre-auth disconnect/banner read failed "
                    f"from {remote_addr}: {message}",
                    "warn",
                )
            else:
                log_attack(f"[{session_id}] connection error: {exc}", "error")
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_socket.close()
            except Exception:
                pass
            append_auth_log(
                event="disconnect",
                session_id=session_id,
                username=login_username,
                hostname=HOSTNAME,
                remote_addr=remote_addr,
                success=True,
                note="session closed",
                proto="ssh",
                local_port=self.port,
            )
            log_attack(f"[*] Connection handler finished for session {session_id}")


def install_signal_handlers(server: SSHServer) -> None:
    def handle_shutdown(signum, frame) -> None:
        log_attack("[*] Shutdown signal received, stopping server.", "warn")
        server.stop()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)


__all__ = [
    "HoneypotServer",
    "SSHServer",
    "install_signal_handlers",
    "load_or_create_host_keys",
]
