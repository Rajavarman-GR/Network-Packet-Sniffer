"""Passive recognition of common FTP control-channel commands/replies."""

import re

from .base import ProtocolDecoder, make_finding

_COMMANDS = {"USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT"}
_REPLY = re.compile(rb"^([1-5][0-9]{2})([ -])([^\r\n]*)")


def _line(payload):
    return payload[:2048].split(b"\r\n", 1)[0].strip()


def _parse_ftp(payload):
    line = _line(payload)
    reply = _REPLY.match(line)
    if reply:
        return {"protocol": "FTP", "kind": "response", "code": int(reply.group(1)), "continuation": reply.group(2) == b"-", "message": reply.group(3).decode("iso-8859-1", "replace")}
    match = re.match(rb"^([A-Za-z]{3,4})(?:[ \t]+(.*))?$", line)
    if not match or match.group(1).decode("ascii").upper() not in _COMMANDS:
        return None
    command = match.group(1).decode("ascii").upper()
    argument = (match.group(2) or b"").decode("iso-8859-1", "replace")
    return {"protocol": "FTP", "kind": "command", "command": command, "argument": argument}


class FTPDecoder(ProtocolDecoder):
    name = "FTP"
    priority = 70

    def applies(self, packet, payload):
        return _parse_ftp(payload) is not None

    def decode(self, packet, payload):
        return _parse_ftp(payload)

    def findings(self, packet, payload):
        decoded = _parse_ftp(payload)
        if not decoded or decoded.get("kind") != "command":
            return []
        command = decoded["command"]
        if command not in {"USER", "PASS"}:
            return []
        message = (
            "Cleartext FTP USER command detected." if command == "USER"
            else "Cleartext FTP PASS (password) command detected."
        )
        return [make_finding("cleartext_credentials", message, decoded["argument"], "FTP {} command".format(command))]
