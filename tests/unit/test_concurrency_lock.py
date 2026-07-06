"""Unit tests for the global Ghidra serialization lock.

These do NOT touch Ghidra or a real server. They exercise the lock helper in
``pyghidra_mcp._locking`` directly against a fake "GhidraTools-like" class whose
methods sleep, and assert that concurrent callers serialize (max observed
concurrency == 1) instead of overlapping — which is exactly the property that
keeps concurrent MCP clients from racing the single JVM into a deadlock.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pyghidra_mcp._locking import (
    GHIDRA_GLOBAL_LOCK,
    serialize_ghidra,
    serialize_ghidra_methods,
)


class _ConcurrencyProbe:
    """Tracks the maximum number of threads inside guarded sections at once."""

    def __init__(self):
        self._n = 0
        self.max_seen = 0
        self._m = threading.Lock()

    def enter(self):
        with self._m:
            self._n += 1
            self.max_seen = max(self.max_seen, self._n)

    def leave(self):
        with self._m:
            self._n -= 1


@serialize_ghidra_methods
class _FakeTools:
    """Stand-in for GhidraTools: public methods are auto-serialized."""

    def __init__(self, probe: _ConcurrencyProbe):
        self.probe = probe

    def decompile(self, _target):
        self.probe.enter()
        try:
            time.sleep(0.02)  # simulate a slow Ghidra call
            return "code"
        finally:
            self.probe.leave()

    def rename(self, _target):
        self.probe.enter()
        try:
            time.sleep(0.02)
            return "renamed"
        finally:
            self.probe.leave()

    def outer_calls_inner(self, target):
        # Public method that calls another public (serialized) method on self.
        # Must not self-deadlock because the lock is reentrant.
        self.probe.enter()
        try:
            return self.decompile(target)
        finally:
            self.probe.leave()

    def _private_helper(self):
        # Underscore methods are intentionally left unwrapped.
        return "helper"


def test_public_methods_are_wrapped_and_private_are_not():
    # Wrapped methods carry the serialize wrapper (functools.wraps keeps __name__).
    assert getattr(_FakeTools.decompile, "__wrapped__", None) is not None
    assert getattr(_FakeTools.rename, "__wrapped__", None) is not None
    # Private helper is untouched.
    assert getattr(_FakeTools._private_helper, "__wrapped__", None) is None


def test_concurrent_calls_serialize():
    probe = _ConcurrencyProbe()
    tools = _FakeTools(probe)

    def worker(i):
        # Mix of read and write ops from many "clients" at once.
        if i % 2 == 0:
            return tools.decompile(f"t{i}")
        return tools.rename(f"t{i}")

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, range(16)))

    assert len(results) == 16
    # The whole point: never more than one caller inside a guarded section.
    assert probe.max_seen == 1


def test_distinct_instances_still_serialize():
    # The lock is process-wide, so two *different* GhidraTools instances (e.g.
    # two binaries / two clients) still serialize against each other.
    probe = _ConcurrencyProbe()
    a = _FakeTools(probe)
    b = _FakeTools(probe)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit((a if i % 2 else b).decompile, f"t{i}") for i in range(12)]
        for f in futs:
            f.result()

    assert probe.max_seen == 1


def test_reentrancy_no_self_deadlock():
    # A serialized public method calling another serialized public method on the
    # same thread must not deadlock (RLock reentrancy).
    probe = _ConcurrencyProbe()
    tools = _FakeTools(probe)
    assert tools.outer_calls_inner("x") == "code"


def test_serialize_ghidra_decorator_holds_lock_during_call():
    seen_locked = []

    @serialize_ghidra
    def fn():
        # RLock has no public "is held by me" API; acquire(blocking=False) from
        # the SAME thread succeeds for an RLock we already hold, so this proves
        # we are inside the guarded region.
        got = GHIDRA_GLOBAL_LOCK.acquire(blocking=False)
        try:
            seen_locked.append(got)
        finally:
            if got:
                GHIDRA_GLOBAL_LOCK.release()

    fn()
    assert seen_locked == [True]
    # Lock fully released after the call returns.
    got = GHIDRA_GLOBAL_LOCK.acquire(blocking=False)
    assert got
    GHIDRA_GLOBAL_LOCK.release()
