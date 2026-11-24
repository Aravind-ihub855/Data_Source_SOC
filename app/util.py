"""Shared clock, ids and hashing for all generators.

The clock is a context variable so a backfill task can run on simulated time while the
live stream keeps using real time. Ids come from the seeded `random` module, so a run
started with the same SEED (and no concurrent live stream) produces the same events.
"""
import contextlib
import datetime
import hashlib
import random
import uuid
from contextvars import ContextVar
from typing import Optional

_sim_time: ContextVar[Optional[datetime.datetime]] = ContextVar("sim_time", default=None)


def now() -> datetime.datetime:
    return _sim_time.get() or datetime.datetime.now(datetime.timezone.utc)


def iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_now() -> str:
    return iso(now())


def parse_iso(s: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


@contextlib.contextmanager
def sim_clock(at: datetime.datetime):
    token = _sim_time.set(at)
    try:
        yield
    finally:
        _sim_time.reset(token)


def new_uuid() -> str:
    return str(uuid.UUID(int=random.getrandbits(128), version=4))


def stable_hex(text: str, length: int = 40) -> str:
    """Deterministic hex id (same input, same id in every source and every run)."""
    return hashlib.sha256(text.encode()).hexdigest()[:length]


def stable_uuid(text: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aetheris:{text}"))
