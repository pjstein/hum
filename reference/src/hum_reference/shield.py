"""The shield: a person's yearly privacy budget, kept on the phone (docs/specs/shield.md).

``seam:`` shield accounting, DP budget accounting, what leaves the phone.

Everything here is exact rational arithmetic until display. ``now`` is always an input; the
module never reads a clock. The ledger never leaves the phone, so nothing here encodes it
for transport.

Window (ADR 0102): an entry counts from its reservation until 365 days after its anchor,
the latest of ``chargedAt``, ``settledAt`` (the later of the phone's clock when it verified
the final release version and that version's ``issued``, capped at the deck's ``expires``)
and, while no final version has been seen, the latest verified ``expires``. Before an
unsettled entry leaves the window the phone looks up the deck lineage's latest version
(``Ledger.spent(now, lookup=...)``); it keeps the entry if ``expires`` moved or the lookup
failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from .release import DELTA, rho_to_eps

__all__ = [
    "COUNTING_STATES",
    "SETTLED_STATES",
    "SHIELD_RHO",
    "SHIELD_WINDOW",
    "SHIELD_YEAR_EPS",
    "Entry",
    "Ledger",
    "ShieldRule",
    "anchor",
    "check_s1",
    "display_eps",
    "fits",
    "headline_fraction",
    "in_window",
    "restore_estimate",
    "settled_at",
]

SHIELD_YEAR_EPS = 20
SHIELD_RHO = Fraction(2201, 500)
SHIELD_WINDOW = 31_536_000

RESERVED, PENDING, CHARGED, RELEASED, ESTIMATED, DROPPED = (
    "reserved",
    "pending",
    "charged",
    "released",
    "estimated",
    "dropped",
)
COUNTING_STATES = {RESERVED, PENDING, CHARGED, RELEASED, ESTIMATED}
SETTLED_STATES = {CHARGED, RELEASED, ESTIMATED}


class ShieldRule(Exception):
    """An operation the shield rules forbid. ``rule`` is the spec's id (S4, S5, S6, S7, S9)."""

    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(f"{rule}: {reason}")
        self.rule = rule
        self.reason = reason


def check_s1() -> dict[str, Any]:
    """S1: ``rho_to_eps(2201/500) ≤ 20 < rho_to_eps(4403/1000)``."""
    lo = rho_to_eps(float(SHIELD_RHO), DELTA)
    hi = rho_to_eps(float(Fraction(4403, 1000)), DELTA)
    return {"eps_at_shield_rho": lo, "eps_above": hi, "holds": lo <= 20 < hi}


@dataclass
class Entry:
    deck: bytes
    context: bytes
    rho: Fraction
    charged_at: int
    state: str
    cards: list[bytes] = field(default_factory=list)
    receipts: list[dict] = field(default_factory=list)
    sent: bool = False  # any round-0 bytes were handed to the network
    settled_at: int | None = None  # final release version verified, capped at expires
    expires: int | None = None  # envelope expires of the latest verified deck version

    def view(self) -> dict[str, Any]:
        return {
            "deck": self.deck.hex(),
            "context": self.context.hex(),
            "rho": [self.rho.numerator, self.rho.denominator],
            "chargedAt": self.charged_at,
            "settledAt": self.settled_at,
            "expires": self.expires,
            "anchor": anchor(self),
            "state": self.state,
            "cards": [c.hex() for c in self.cards],
            "receipts": len(self.receipts),
        }


def anchor(entry: Entry) -> int:
    """The latest of ``chargedAt``, ``settledAt``, and ``expires`` while unsettled."""
    a = entry.charged_at
    if entry.settled_at is not None:
        return max(a, entry.settled_at)
    if entry.expires is not None:
        return max(a, entry.expires)
    return a


def in_window(entry: Entry, now: int) -> bool:
    """S8: an entry counts while ``now < anchor + 365 days``; a clock set back frees nothing."""
    return now < anchor(entry) + SHIELD_WINDOW


def settled_at(seen_at: int, issued: int | None, expires: int | None) -> int:
    """``settledAt``: max(phone clock at verification, the final version's ``issued``), capped
    at ``expires``. A clock set back at that moment never records an early ``settledAt``."""
    t = seen_at if issued is None else max(seen_at, issued)
    return t if expires is None else min(t, expires)


def display_eps(rho: Fraction) -> float:
    """Displayed spend: binary64 ``rho_to_eps``, rounded half to even to one decimal."""
    return round(rho_to_eps(float(rho), DELTA), 1)


def headline_fraction(rho: Fraction) -> float:
    """``1 − rho_to_eps(Σρ) / 20`` as the board shows it (not used for enforcement)."""
    return 1 - rho_to_eps(float(rho), DELTA) / SHIELD_YEAR_EPS


def fits(plan_rho: Fraction, remaining: Fraction) -> bool:
    return plan_rho <= remaining


class Ledger:
    """The phone's ledger and its state machine (shield.md, "Reserving and charging")."""

    def __init__(self, entries: list[Entry] | None = None) -> None:
        self.entries: list[Entry] = list(entries or [])

    # -- sums
    def counts(self, e: Entry, now: int, lookup=None) -> bool:
        """Whether ``e`` is in the sum at ``now``.

        ``lookup(deck) -> int | None`` returns the ``expires`` of the deck lineage's latest
        version in the log, or raises when the log is unreachable. Before an unsettled entry
        is allowed to leave the window it is looked up: if ``expires`` moved the entry is
        updated and kept, and if the lookup fails (or is not offered) the entry is kept and
        tried again later. A settled entry needs no lookup (shield.md, "Window").
        """
        if e.state not in COUNTING_STATES:
            return False
        if in_window(e, now) or e.settled_at is not None:
            return in_window(e, now)
        if lookup is None:
            return False  # the arithmetic rule alone (the caller holds the lookup)
        try:
            latest = lookup(e.deck)
        except Exception:  # noqa: BLE001 - any failure keeps the entry
            return True
        if latest is None:
            return True
        if e.expires is None or latest > e.expires:
            e.expires = latest
        return in_window(e, now)

    def spent(self, now: int, lookup=None) -> Fraction:
        return sum((e.rho for e in self.entries if self.counts(e, now, lookup)), Fraction(0))

    def settled(self, now: int) -> Fraction:
        return sum(
            (e.rho for e in self.entries if e.state in SETTLED_STATES and in_window(e, now)),
            Fraction(0),
        )

    def remaining(self, now: int) -> Fraction:
        return max(SHIELD_RHO - self.spent(now), Fraction(0))

    def find(self, deck: bytes) -> Entry | None:
        for e in self.entries:
            if e.deck == deck and e.state != DROPPED:
                return e
        return None

    # -- transitions
    def reserve(
        self,
        deck: bytes,
        context: bytes,
        rho: Fraction,
        now: int,
        cards: list[bytes],
        expires: int | None = None,
    ) -> bool:
        """Append a ``reserved`` entry when the plan fits (S4); an ``estimated`` entry is reused
        (S9) and never duplicated (S5). Returns whether the deck may be played."""
        existing = self.find(deck)
        if existing is not None:
            if expires is not None:
                existing.expires = max(existing.expires or 0, expires)
            return existing.state in COUNTING_STATES
        if not fits(rho, self.remaining(now)):
            return False
        self.entries.append(Entry(deck, context, rho, now, RESERVED, list(cards), expires=expires))
        return True

    def send(self, deck: bytes) -> None:
        """First round-0 bytes handed to the network: ``reserved``/``estimated`` → ``pending``."""
        e = self.find(deck)
        if e is None:
            raise ShieldRule("S3", "no entry for this deck")
        if e.state in (RESERVED, ESTIMATED):
            e.state = PENDING
        e.sent = True

    def receipt(self, deck: bytes, receipt: dict) -> None:
        e = self.find(deck)
        if e is None or not e.sent:
            raise ShieldRule("S3", "receipt without a sent ballot")
        if e.state == PENDING:
            e.state = CHARGED
        e.receipts.append(receipt)

    def final(self, deck: bytes, seen_at: int, issued: int | None = None) -> None:
        """A final release version with ``issued`` verified at ``seen_at`` (the phone's clock):
        ``settledAt`` = max(``seen_at``, ``issued``) capped at ``expires`` (a version first seen
        after ``expires`` counts as seen at ``expires``)."""
        e = self.find(deck)
        if e is None:
            return
        if issued is not None and e.expires is not None and issued > e.expires:
            # release.md R13: a phone refuses to act on a version issued after expires
            raise ShieldRule("S8", "final version issued after the deck's expires; refused")
        e.settled_at = settled_at(seen_at, issued, e.expires)
        if e.state == CHARGED:
            e.state = RELEASED

    def extend(self, deck: bytes, expires: int) -> None:
        """A later deck version moved ``expires``; the anchor of an unsettled entry moves."""
        e = self.find(deck)
        if e is not None and (e.expires is None or expires > e.expires):
            e.expires = expires

    def drop(self, deck: bytes) -> bool:
        """Only a ``reserved`` entry with no bytes ever sent can be dropped (S7)."""
        e = self.find(deck)
        if e is None or e.sent or e.state != RESERVED:
            return False
        e.state = DROPPED
        return True

    def apply(self, event: dict[str, Any], now: int) -> dict[str, Any]:
        """One event; returns the outcome or raises ``ShieldRule``.

        Events: ``open``, ``cast``, ``send``, ``receipt``, ``rejected``, ``lost``, ``closed``,
        ``final`` (``seenAt``, ``issued``), ``abandoned``, ``leave``, ``deck_closed``,
        ``estimate``, ``extend``, ``replace``, ``round``, and the forbidden ``drop``,
        ``refund`` and ``remove``.
        """
        kind = event["event"]
        deck = event["deck"]
        if kind == "open":
            ok = self.reserve(
                deck, event["context"], event["rho"], now, event.get("cards", []),
                event.get("expires"),
            )  # fmt: skip
            return {"reserved": ok}
        if kind == "cast":
            e = self.find(deck)
            return {"cast": True, "state": e.state if e else None}
        if kind == "send":
            self.send(deck)
            return {"state": self.find(deck).state}
        if kind == "receipt":
            self.receipt(deck, event.get("receipt", {"round": 0}))
            return {"state": self.find(deck).state}
        if kind in ("rejected", "lost", "closed", "abandoned"):
            # No refund after sending: the entry stays whatever the server said (S6).
            e = self.find(deck)
            return {"state": e.state if e else None, "refund": False}
        if kind == "final":
            self.final(deck, event.get("seenAt", now), event.get("issued"))
            e = self.find(deck)
            return {"state": e.state, "settledAt": e.settled_at, "anchor": anchor(e)}
        if kind == "extend":
            self.extend(deck, event["expires"])
            e = self.find(deck)
            return {"expires": e.expires, "anchor": anchor(e)}
        if kind in ("replace", "round"):
            # Rounds 1 to 3 and replacements add no entry and change no rho (S5).
            e = self.find(deck)
            if e is None or not e.sent:
                raise ShieldRule("S5", f"{kind} for a deck without a sent round-0 ballot")
            return {"state": e.state, "entries": len(self.entries), "added": False}
        if kind == "leave":
            e = self.find(deck)
            cast = event.get("cast", False)
            dropped = False if cast else self.drop(deck)
            return {"dropped": dropped, "state": e.state if e else None}
        if kind == "deck_closed":
            dropped = self.drop(deck)
            e = self.find(deck)
            return {"dropped": dropped, "state": e.state if e else None}
        if kind == "estimate":
            if self.find(deck) is not None:
                raise ShieldRule("S5", "a second entry for one deck")
            self.entries.append(
                Entry(
                    deck,
                    event["context"],
                    event["rho"],
                    event["chargedAt"],
                    ESTIMATED,
                    expires=event.get("expires"),
                )
            )
            return {"state": ESTIMATED}
        if kind == "drop":
            e = self.find(deck)
            if e is None:
                raise ShieldRule("S7", "no entry to drop")
            if e.sent:
                raise ShieldRule("S7", "bytes were handed to the network; never dropped")
            if e.state != RESERVED:
                raise ShieldRule("S7", f"a {e.state} entry is never dropped")
            e.state = DROPPED
            return {"dropped": True}
        if kind == "refund":
            e = self.find(deck)
            if e is None or not e.sent:
                raise ShieldRule("S7", "nothing to refund")
            raise ShieldRule("S6", "an entry whose bytes were sent is never removed or reduced")
        if kind == "remove":
            e = self.find(deck)
            if e is None:
                raise ShieldRule("S9", "no entry")
            if e.state == ESTIMATED:
                raise ShieldRule("S9", "an estimated entry cannot be removed in draft 0.1")
            raise ShieldRule("S6", "entries are never removed")
        raise ValueError(f"unknown event {kind!r}")

    def board(self, now: int) -> dict[str, Any]:
        spent = self.spent(now)
        settled = self.settled(now)
        return {
            "spent_rho": [spent.numerator, spent.denominator],
            "settled_rho": [settled.numerator, settled.denominator],
            "remaining_rho": [self.remaining(now).numerator, self.remaining(now).denominator],
            "over_budget": spent > SHIELD_RHO,
            "displayed_eps": display_eps(spent),
            "settled_eps": display_eps(settled),
            "pending_eps": round(display_eps(spent) - display_eps(settled), 1),
            "headline_settled": headline_fraction(settled),
            "headline_including_pending": headline_fraction(spent),
        }


def restore_estimate(
    contexts: list[dict[str, Any]], decks: list[dict[str, Any]], now: int
) -> list[Entry]:
    """``estimated`` entries after a restore (shield.md, "Restore", S9).

    ``contexts``: ``{"lineage": bytes, "left": time or None}``, every context the backup
    lists (the backup itself keeps a left context until 365 days after the latest ``expires``
    of its decks, so no further filter applies here). ``decks``: ``{"deck", "context",
    "closes", "expires", "rho"}`` for every deck of those contexts whose latest ``expires``
    is within the last 365 days or in the future, whatever its release state. Each entry has
    ``chargedAt = closes``, the latest ``expires`` and no ``settledAt``, so its anchor is
    ``expires``.
    """
    listed = {c["lineage"] for c in contexts}
    out = []
    for d in decks:
        if d["context"] not in listed:
            continue
        if now - d["expires"] >= SHIELD_WINDOW:
            continue
        out.append(
            Entry(d["deck"], d["context"], d["rho"], d["closes"], ESTIMATED, expires=d["expires"])
        )
    return out
