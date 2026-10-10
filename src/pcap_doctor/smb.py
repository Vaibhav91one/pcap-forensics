"""SMB / SMB2 / SMB3 operations read from the ``smb`` tshark pass: shares, files, users and NTLM identities (#204)."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from .tshark import Row, to_bool01, to_int

SMB2_COMMANDS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT", 5: "CREATE",
                 6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
                 14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK"}
SMB1_COMMANDS = {0x72: "NEGOTIATE", 0x73: "SESSION_SETUP_ANDX", 0x75: "TREE_CONNECT_ANDX", 0xA2: "NT_CREATE_ANDX",
                 0x25: "TRANSACTION", 0x2F: "WRITE_ANDX", 0x2E: "READ_ANDX", 0x04: "CLOSE"}
EXECUTABLE = re.compile(r"\.(exe|dll|sys|bat|cmd|ps1|vbs|js|scr|msi|com)$", re.I)
ADMIN_SHARE = re.compile(r"\\([A-Za-z]\$|ADMIN\$)$", re.I)
#: named pipes that remote service/task execution tools (PsExec, smbexec, atexec, wmiexec) talk to
EXEC_PIPES = ("svcctl", "atsvc", "psexesvc", "winreg", "remcom")


def unescape(value: str) -> str:
    """tshark's field output doubles every backslash: a doubled pair is one real backslash."""
    return value.replace("\\\\", "\\")


class SmbOp(BaseModel):
    key: str
    frame: int
    ts: float | None = None
    version: str  # SMB1 | SMB2
    command: str
    response: bool | None = None
    status: str | None = None
    tree: str | None = None
    filename: str | None = None
    user: str | None = None
    domain: str | None = None
    host: str | None = None
    dialects: list[str] = Field(default_factory=list)
    sign_required: bool | None = None  # NEGOTIATE responses only
    sign_enabled: bool | None = None

    @property
    def anonymous(self) -> bool:
        return self.command == "SESSION_SETUP" and self.user is not None and self.user.upper() in ("", "NULL", "ANONYMOUS LOGON")

    @property
    def share(self) -> str | None:
        return self.tree.rsplit("\\", 1)[-1] if self.tree else None


def parse_smb(rows: list[Row], key_of: object) -> list[SmbOp]:  # key_of: Callable[[Row], str | None]
    from .index import first, many

    ops: list[SmbOp] = []
    for row in rows:
        key = key_of(row)  # type: ignore[operator]
        if not key:
            continue
        frame = to_int(first(row, "frame.number")) or 0
        ts = float(first(row, "frame.time_epoch")) if first(row, "frame.time_epoch") else None
        smb2 = many(row, "smb2.cmd")
        responses = many(row, "smb2.flags.response")
        if smb2:
            commands = [SMB2_COMMANDS.get(n, f"CMD_{c}") if (n := to_int(c)) is not None else f"CMD_{c}" for c in smb2]
            version = "SMB2"
        else:
            codes = [to_int(c, 16) if c.lower().startswith("0x") else to_int(c) for c in many(row, "smb.cmd")]
            commands = [SMB1_COMMANDS.get(n, f"CMD_{n:#x}") for n in codes if n is not None]
            version = "SMB1"
            responses = []
        for i, command in enumerate(commands):
            op = SmbOp(
                key=key, frame=frame, ts=ts, version=version, command=command,
                response=to_bool01(responses[i] if i < len(responses) else (responses[0] if responses else "")),
                status=first(row, "smb2.nt_status") or first(row, "smb.nt_status") or None,
                tree=unescape(first(row, "smb2.tree") or first(row, "smb.path")) or None,
                filename=unescape(first(row, "smb2.filename") or first(row, "smb.file")) or None,
                user=first(row, "ntlmssp.auth.username") or None,
                domain=first(row, "ntlmssp.auth.domain") or None,
                host=first(row, "ntlmssp.auth.hostname") or None,
            )
            if command == "NEGOTIATE":
                op.dialects = many(row, "smb.dialect.name")
                if op.response:
                    op.sign_required = to_bool01(first(row, "smb2.sec_mode.sign_required") or first(row, "smb.sm.sig_required"))
                    op.sign_enabled = to_bool01(first(row, "smb2.sec_mode.sign_enabled"))
            ops.append(op)
    return ops
