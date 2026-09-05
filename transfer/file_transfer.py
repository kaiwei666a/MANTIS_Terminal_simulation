from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from paramiko import (
    SFTPAttributes,
    SFTP_FAILURE,
    SFTPHandle,
    SFTP_NO_SUCH_FILE,
    SFTP_OK,
    SFTP_PERMISSION_DENIED,
    SFTPServerInterface,
)

from server.ssh_io import _safe_send
from storage.session_store import append_auth_log, log_attack
from terminal_config import HOSTNAME, SCP_ROOT
from transfer.transfer_backend import _copy_to_docker_and_delete, _normalize_under_root


class RootedSFTPHandle(SFTPHandle):
    def __init__(
        self,
        flags,
        filename=None,
        session_id: str = "",
        remote_addr: str = "",
        login_username: str = "",
    ):
        super().__init__(flags)
        self.filename = filename
        self.session_id = session_id
        self.remote_addr = remote_addr
        self.login_username = login_username
        self.readfile = None
        self.writefile = None

    def read(self, offset, length):
        if not self.readfile:
            return SFTP_FAILURE
        try:
            self.readfile.seek(offset)
            return self.readfile.read(length)
        except Exception:
            return SFTP_FAILURE

    def write(self, offset, data):
        if not self.writefile:
            return SFTP_FAILURE
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

    def close(self):
        try:
            file_path = self.filename
            wrote = self.writefile is not None

            if self.readfile:
                self.readfile.close()
            if self.writefile:
                self.writefile.close()

            if wrote and file_path:
                _copy_to_docker_and_delete(
                    file_path,
                    source_proto="sftp",
                    session_id=self.session_id,
                    remote_addr=self.remote_addr,
                    login_username=self.login_username,
                )

            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

class RootedSFTP(SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server)
        self.root = os.path.abspath(SCP_ROOT)
        self.session_id = getattr(server, "_session_id", "")
        self.remote_addr = getattr(server, "_remote_addr", "")
        self.login_username = getattr(server, "auth_username", "")
        try:
            os.makedirs(self.root, exist_ok=True)
        except Exception:
            pass

    def _to_local(self, path: str) -> str:
        if not path:
            path = "/"
        if path.startswith("/"):
            path = path[1:]
        parts = []
        for p in path.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        local = os.path.abspath(os.path.join(self.root, *parts)) if parts else self.root
        normalized_root = self.root.lower() if os.name == "nt" else self.root
        normalized_local = local.lower() if os.name == "nt" else local
        if normalized_local == normalized_root or normalized_local.startswith(normalized_root + os.sep):
            return local
        return self.root

    def list_folder(self, path):
        try:
            local = self._to_local(path)
            if not os.path.isdir(local):
                return SFTP_NO_SUCH_FILE
            out = []
            for name in os.listdir(local):
                full = os.path.join(local, name)
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                attr = SFTPAttributes.from_stat(st)
                attr.filename = name
                out.append(attr)
            return out
        except Exception:
            return SFTP_FAILURE

    def stat(self, path):
        try:
            local = self._to_local(path)
            st = os.stat(local)
            return SFTPAttributes.from_stat(st)
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    lstat = stat

    def open(self, path, flags, attr):
        try:
            local = self._to_local(path)
            os_flags = _convert_sftp_pflags_to_os(flags)
            write_requested = bool(os_flags & (os.O_WRONLY | os.O_RDWR))
            read_requested = bool(os_flags & os.O_RDWR) or not bool(os_flags & os.O_WRONLY)
            wants_create = bool(os_flags & os.O_CREAT)
            wants_append = bool(os_flags & os.O_APPEND)
            wants_trunc = bool(os_flags & os.O_TRUNC)

            if write_requested:
                parent = os.path.dirname(local)
                if parent and not os.path.exists(parent):
                    os.makedirs(parent, exist_ok=True)


            if write_requested and read_requested:
                if wants_append:
                    py_mode = "a+b"
                elif wants_trunc:
                    py_mode = "w+b"
                else:
                    py_mode = "r+b"
                    if wants_create and not os.path.exists(local):
                        py_mode = "w+b"
            elif write_requested:
                py_mode = "ab" if wants_append else "wb"
            else:
                py_mode = "rb"

            fobj = open(local, py_mode)

            if attr and attr.st_mode is not None and write_requested:
                try:
                    os.chmod(local, attr.st_mode & 0o777)
                except Exception:
                    pass

            h = RootedSFTPHandle(
                flags,
                filename=local,
                session_id=self.session_id,
                remote_addr=self.remote_addr,
                login_username=self.login_username,
            )
            if "r" in py_mode:
                h.readfile = fobj
            if "w" in py_mode or "+" in py_mode or "a" in py_mode:
                h.writefile = fobj
            return h
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception as e:
            log_attack(f"[sftp] open failed path={path!r} local={locals().get('local', '')!r}: {e}", "warn")
            return SFTP_FAILURE

    def remove(self, path):
        try:
            local = self._to_local(path)
            os.remove(local)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    def mkdir(self, path, attr):
        try:
            local = self._to_local(path)
            os.makedirs(local, exist_ok=True)
            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

    def rmdir(self, path):
        try:
            local = self._to_local(path)
            os.rmdir(local)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    def rename(self, oldpath, newpath):
        try:
            src = self._to_local(oldpath)
            dst = self._to_local(newpath)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

def _scp_read_ack(chan) -> int:
    try:
        b = chan.recv(1)
        if not b:
            return -1
        return b[0]
    except Exception:
        return -1

def _scp_send_ack(chan):
    _safe_send(chan, b"\x00")

def _scp_send_error(chan, msg: str, fatal: bool = False):
    try:
        b = (msg + "\n").encode("utf-8", errors="ignore")
        _safe_send(chan, b"\x01" + b)
    except Exception:
        pass
    if fatal:
        try:
            chan.close()
        except Exception:
            pass

def _scp_read_line(chan) -> bytes:
    buf = b""
    while True:
        b = chan.recv(1)
        if not b:
            return b""
        buf += b
        if b == b"\n":
            return buf

def _scp_read_exact(chan, size: int) -> bytes:
    out = b""
    remaining = size
    while remaining > 0:
        chunk = chan.recv(min(32768, remaining))
        if not chunk:
            break
        out += chunk
        remaining -= len(chunk)
    return out

def _ensure_parent(path: str):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

def _convert_sftp_pflags_to_os(pflags: int) -> int:
    if int(pflags) & ~0x3F:
        return int(pflags)

    P_READ = 0x01
    P_WRITE = 0x02
    P_APPEND = 0x04
    P_CREAT = 0x08
    P_TRUNC = 0x10
    P_EXCL = 0x20

    read_requested = bool(pflags & P_READ)
    write_requested = bool(pflags & P_WRITE)

    if read_requested and write_requested:
        os_flags = os.O_RDWR
    elif write_requested:
        os_flags = os.O_WRONLY
    else:
        os_flags = os.O_RDONLY

    if pflags & P_APPEND:
        os_flags |= os.O_APPEND
    if pflags & P_CREAT:
        os_flags |= os.O_CREAT
    if pflags & P_TRUNC:
        os_flags |= os.O_TRUNC
    if pflags & P_EXCL:
        os_flags |= os.O_EXCL

    return os_flags

_SCPEXEC_RE = re.compile(r"scp(\.exe)?$", re.IGNORECASE)

def _parse_scp_exec(exec_cmd: str) -> Tuple[Optional[str], Optional[str]]:
    if not exec_cmd:
        return None, None
    args = exec_cmd.strip().split()
    if not args:
        return None, None

    cmd0 = os.path.basename(args[0])
    if not _SCPEXEC_RE.fullmatch(cmd0):
        i = 0
        while i < len(args) and not _SCPEXEC_RE.fullmatch(os.path.basename(args[i])):
            i += 1
        if i >= len(args):
            return None, None
        args = args[i:]

    args = args[1:]
    if not args:
        return None, None

    opts, rest = [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            rest.extend(args[i + 1:])
            break
        elif a.startswith("-"):
            opts.append(a)
        else:
            rest.append(a)
        i += 1

    optstr = " ".join(opts).lower()
    mode = None
    if re.search(r'(^|\s)-t(\s|$)', optstr):
        mode = "upload"
    elif re.search(r'(^|\s)-f(\s|$)', optstr):
        mode = "download"
    else:
        return None, None

    target = rest[0] if rest else "/"
    return mode, target

def scp_serve_download(
    chan,
    remote_path: str,
    session_id: str,
    remote_addr: str,
    login_username: str,
):
    req_path = remote_path.strip()
    local_path = _normalize_under_root(req_path)
    base = os.path.basename(local_path)

    append_auth_log(event="scp_download", session_id=session_id, username=login_username,
                    hostname=HOSTNAME, remote_addr=remote_addr, success=False,
                    note=f"request_path={req_path}, local_path={local_path}")

    if not (os.path.exists(local_path) and os.path.isfile(local_path)):
        _scp_send_error(chan, f"not found: {req_path}")
        try:
            chan.send_exit_status(1)
        except Exception:
            pass
        log_attack(f"[{session_id}] SCP file not found: {local_path}", "warn")
        return

    try:
        size = os.path.getsize(local_path)
        mode = 0o644

        ack = _scp_read_ack(chan)
        if ack != 0:
            _scp_send_error(chan, "Client not ready")
            return

        header = f"C{mode:04o} {size} {base}\n".encode("utf-8")
        _safe_send(chan, header)
        _scp_read_ack(chan)

        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(32768)
                if not chunk:
                    break
                _safe_send(chan, chunk)

        _scp_send_ack(chan)
        _scp_read_ack(chan)

        try:
            chan.send_exit_status(0)
        except Exception:
            pass

        append_auth_log(event="scp_download", session_id=session_id, username=login_username,
                        hostname=HOSTNAME, remote_addr=remote_addr, success=True,
                        note=f"ok {base} ({size} bytes)")
        log_attack(f"[{session_id}] SCP sent: {base} ({size} bytes)")
    except Exception as e:
        _scp_send_error(chan, f"error: {e}", fatal=True)
        try:
            chan.send_exit_status(2)
        except Exception:
            pass

def scp_serve_upload(
    chan,
    target_path: str,
    session_id: str,
    remote_addr: str,
    login_username: str,
):
    base_target = _normalize_under_root(target_path.strip())
    root_dir = (
        base_target if os.path.isdir(base_target) or target_path.endswith("/")
        else os.path.dirname(base_target)
    )
    if not os.path.isdir(root_dir):
        os.makedirs(root_dir, exist_ok=True)

    dir_stack: List[str] = [root_dir]

    def _cwd() -> str:
        return dir_stack[-1]

    def _enter_dir(name: str):
        d = os.path.join(_cwd(), name)
        d = _normalize_under_root(d)
        os.makedirs(d, exist_ok=True)
        dir_stack.append(d)

    def _leave_dir():
        if len(dir_stack) > 1:
            dir_stack.pop()

    def _write_file(mode: int, size: int, name: str):
        dst = os.path.join(_cwd(), name)
        dst = _normalize_under_root(dst)
        _ensure_parent(dst)

        data = _scp_read_exact(chan, size)
        with open(dst, "wb") as f:
            f.write(data)

        _ = _scp_read_ack(chan)
        _scp_send_ack(chan)

        try:
            os.chmod(dst, mode & 0o777)
        except Exception:
            pass

        _copy_to_docker_and_delete(
            dst,
            source_proto="scp",
            session_id=session_id,
            remote_addr=remote_addr,
            login_username=login_username,
        )

        append_auth_log(
            event="scp_upload",
            session_id=session_id,
            username=login_username,
            hostname=HOSTNAME,
            remote_addr=remote_addr,
            success=True,
            note=f"upload to docker from {dst} ({size} bytes)"
        )
        log_attack(f"[{session_id}] SCP received to docker: {dst} ({size} bytes)")

    try:
        _scp_send_ack(chan)
        log_attack(f"[{session_id}] SCP upload ready, target: {target_path}")

        while True:
            line = _scp_read_line(chan)
            if line == b"":
                break
            s = line.rstrip(b"\r\n")
            if not s:
                _scp_send_ack(chan)
                continue

            tag = s[:1]
            rest = s[1:].decode("utf-8", "ignore").strip()

            if tag == b"C":
                mode_str, size_str, name = rest.split(" ", 2)
                mode = int(mode_str, 8)
                size = int(size_str)
                _scp_send_ack(chan)
                _write_file(mode, size, name)

            elif tag == b"D":
                mode_str, _zero, name = rest.split(" ", 2)
                _enter_dir(name)
                try:
                    os.chmod(_cwd(), int(mode_str, 8) & 0o777)
                except Exception:
                    pass
                _scp_send_ack(chan)

            elif tag == b"E":
                _leave_dir()
                _scp_send_ack(chan)

            elif tag == b"T":
                _scp_send_ack(chan)

            elif tag in (b"\x00",):
                _scp_send_ack(chan)

            else:
                _scp_send_error(chan, f"unsupported header: {line!r}", fatal=True)
                return
    except Exception as e:
        _scp_send_error(chan, f"upload error: {e}", fatal=True)
        log_attack(f"[{session_id}] SCP upload error: {e}", "error")
    else:
        try:
            chan.send_exit_status(0)
        except Exception:
            pass
