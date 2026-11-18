# Open Glucose Stream reference — https://github.com/mauriciabad/open-glucose-stream
# SPDX-FileCopyrightText: 2026 Maurici Abad
# SPDX-License-Identifier: CC0-1.0
"""C§9.5: a member's leave outbox. The signed wrap (never `M`) and the membership's relays, kept until two relays keep
it (N§3.4) or it expires. Transport-independent: feed it each relay's answer with `answered`."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..nostr import RelayOk, relay_key

NEEDED = 2  # relays that must keep a leave before the member stops sending it (one may drop it)


@dataclass
class PendingLeave:
    wrap: dict
    relays: list[str]
    expiry: int
    accepted: set[str] = field(default_factory=set)  # relay_key of the relays that keep it
    nearby: bool = False  # a publisher device took it over Bluetooth

    @property
    def told(self) -> bool:
        """The administrator can learn it now: a relay keeps it, or a publisher device took it over Bluetooth."""
        return bool(self.accepted) or self.nearby

    def done(self, now: int) -> bool:
        """Nothing more to send: two of its relays keep it (every one when fewer are listed), or it expired."""
        if now >= self.expiry:
            return True
        keys = {relay_key(u) for u in self.relays}
        return bool(keys) and len(self.accepted & keys) >= min(NEEDED, len(keys))

    def waiting_on(self) -> list[str]:
        """Its relays that don't keep it yet: where the next attempt sends it."""
        return [u for u in self.relays if relay_key(u) not in self.accepted]

    def answered(self, url: str, ok: RelayOk) -> None:
        """The relay whose connection was opened to `url` answered `ok`. It counts when the answer names this wrap,
        says the relay keeps it (N§3.4) and the relay is one of the leave's; anything else changes nothing."""
        key = relay_key(url)
        if ok.event_id == self.wrap["id"] and ok.kept and key in {relay_key(u) for u in self.relays}:
            self.accepted.add(key)
