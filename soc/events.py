"""Format d'événement normalisé : tous les parseurs produisent des Event."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    ts: datetime
    source: str                 # ssh | firewall | web | file
    type: str                   # ssh_failed, ssh_success, sudo_command, fw_block, fw_allow,
                                # http_request, file_created, file_modified, file_renamed
    host: str = "srv-01"
    src_ip: str | None = None
    user: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def brief(self) -> str:
        who = f" user={self.user}" if self.user else ""
        ip = f" ip={self.src_ip}" if self.src_ip else ""
        return f"{self.ts:%H:%M:%S} [{self.source}/{self.type}]{ip}{who}"


def utcnow() -> datetime:
    """Heure UTC courante, sans fuseau (format utilisé partout dans le projet)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
