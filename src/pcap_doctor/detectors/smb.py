"""D10 -- SMB / SMB2 / SMB3: legacy dialect, signing, admin shares, service pipes, executables, null sessions (#204)."""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from ..smb import ADMIN_SHARE, EXEC_PIPES, EXECUTABLE
from .base import Detector, ev

ATTACK_ADMIN = "MITRE ATT&CK T1021.002 (SMB/Windows Admin Shares)"


class SmbDetector(Detector):
    name: ClassVar[str] = "d10.smb"
    title: ClassVar[str] = "SMB exposure and lateral-movement shapes"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "smb"
    description: ClassVar[str] = (
        "SMBv1 dialects, unsigned SMB2/3 sessions, administrative share access, service-control pipes, "
        "executables written to shares and anonymous (null) sessions."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()

        def once(code: str, key: str, detail: str) -> bool:
            token = (code, key, detail)
            if token in seen:
                return False
            seen.add(token)
            return True

        for op in index.smb:
            flow = index.flows.get(op.key)
            subjects = [flow.endpoint_a, flow.endpoint_b] if flow else []
            if op.version == "SMB1" and once("SMB1_IN_USE", op.key, ""):
                out.append(self.finding(
                    code="SMB1_IN_USE", title=f"SMBv1 used on {op.key}", severity="high", confidence="high",
                    summary="SMB1 traffic was observed. SMBv1 is deprecated, unsigned by default, and the protocol "
                    "the EternalBlue family of exploits targets.",
                    scope=op.key, flow_key=op.key, subjects=subjects,
                    evidence=[ev(op.frame, "smb.cmd", op.command)],
                    remediation="Disable SMBv1 on clients and servers (Windows: Disable-WindowsOptionalFeature SMB1Protocol; "
                    "Samba: server min protocol = SMB2).",
                    references=["CVE-2017-0144", "MS17-010"], tags=["smb", "legacy"]))
            if op.version == "SMB2" and op.command == "NEGOTIATE" and op.response and op.sign_required is False \
                    and once("SMB_SIGNING_NOT_REQUIRED", op.key, ""):
                out.append(self.finding(
                    code="SMB_SIGNING_NOT_REQUIRED", title=f"SMB signing not required by the server on {op.key}",
                    severity="medium", confidence="high",
                    summary="The server's NEGOTIATE response does not require message signing, so an on-path "
                    "attacker can relay or tamper with SMB sessions.",
                    scope=op.key, flow_key=op.key, subjects=subjects,
                    evidence=[ev(op.frame, "smb2.sec_mode.sign_required", "0")],
                    remediation="Require SMB signing (Windows: 'Microsoft network server: Digitally sign communications (always)'; "
                    "Samba: server signing = mandatory).",
                    references=["MITRE ATT&CK T1557.001"], tags=["smb", "relay"]))
            if op.anonymous and not op.response and once("SMB_NULL_SESSION", op.key, ""):
                out.append(self.finding(
                    code="SMB_NULL_SESSION", title=f"Anonymous SMB session on {op.key}", severity="medium",
                    confidence="high",
                    summary="An SMB session was set up with an empty (null) NTLM identity. Null sessions are used to "
                    "enumerate users, shares and policies without credentials.",
                    scope=op.key, flow_key=op.key, subjects=subjects,
                    evidence=[ev(op.frame, "ntlmssp.auth.username", op.user or "")],
                    remediation="Restrict anonymous access (RestrictAnonymous=2, 'Network access: Allow anonymous SID/Name "
                    "translation' disabled) and disable guest/anonymous shares.",
                    references=["CWE-287"], tags=["smb", "anonymous"]))
            if op.command in ("TREE_CONNECT", "TREE_CONNECT_ANDX") and op.tree and ADMIN_SHARE.search(op.tree) \
                    and once("SMB_ADMIN_SHARE_ACCESS", op.key, op.tree.lower()):
                out.append(self.finding(
                    code="SMB_ADMIN_SHARE_ACCESS", title=f"Administrative share {op.share} accessed on {op.key}",
                    severity="medium", confidence="high",
                    summary=f"A client connected to the administrative share {op.tree}. Remote administration tools and "
                    "lateral-movement tooling use these shares to stage files and run services.",
                    scope=f"{op.key}:{op.tree.lower()}", flow_key=op.key, subjects=subjects,
                    evidence=[ev(op.frame, "smb2.tree", op.tree)],
                    remediation="Confirm the access is expected administration; restrict admin shares to jump hosts and "
                    "disable AutoShareWks/AutoShareServer where they are not needed.",
                    references=[ATTACK_ADMIN], tags=["smb", "lateral-movement"]))
            if op.filename and op.command in ("CREATE", "NT_CREATE_ANDX"):
                leaf = op.filename.replace("/", "\\").rsplit("\\", 1)[-1]
                if (leaf.lower() in EXEC_PIPES or leaf.lower().removesuffix(".exe") in EXEC_PIPES) \
                        and once("SMB_REMOTE_EXEC_PIPE", op.key, leaf.lower()):
                    out.append(self.finding(
                            code="SMB_REMOTE_EXEC_PIPE", title=f"Remote execution pipe {leaf} opened on {op.key}",
                            severity="high", confidence="medium",
                            summary=f"The named pipe or service {leaf} was opened over SMB. PsExec, smbexec and atexec "
                            "use svcctl/atsvc/PSEXESVC to create and start services or tasks on a remote host.",
                            scope=f"{op.key}:{leaf.lower()}", flow_key=op.key, subjects=subjects,
                            evidence=[ev(op.frame, "smb2.filename", op.filename)],
                            remediation="Investigate the source host and account; block remote service creation from "
                            "workstations (firewall 445 between clients, restrict SeNetworkLogonRight).",
                            references=["MITRE ATT&CK T1569.002 (Service Execution)", ATTACK_ADMIN],
                            tags=["smb", "lateral-movement"]))
                if EXECUTABLE.search(leaf) and once("SMB_EXECUTABLE_ON_SHARE", op.key, op.filename.lower()):
                    on_admin = bool(op.tree and ADMIN_SHARE.search(op.tree))
                    out.append(self.finding(
                        code="SMB_EXECUTABLE_ON_SHARE", title=f"Executable {leaf} opened over SMB on {op.key}",
                        severity="high" if on_admin else "medium", confidence="medium",
                        summary=f"{op.filename} was opened on {op.tree or 'a share'}. Executables written to a remote "
                        "share are the staging step of remote execution and malware spread.",
                        scope=f"{op.key}:{op.filename.lower()}", flow_key=op.key, subjects=subjects,
                        evidence=[ev(op.frame, "smb2.filename", op.filename)],
                        remediation="Verify the file and the writing account; restrict write access to shares and "
                        "enable application allow-listing on the target.",
                        references=[ATTACK_ADMIN, "MITRE ATT&CK T1105"], tags=["smb", "executable"]))
        return out
