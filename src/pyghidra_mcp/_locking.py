"""Global Ghidra serialization lock.

Ghidra/JPype is a *single* JVM: one program database, one small decompiler
pool, and program-DB transactions that are not safe for concurrent access. The
MCP tool set mixes ``async def`` handlers (which dispatch Ghidra work via
``asyncio.to_thread`` onto a multi-worker threadpool) with plain ``def``
handlers (which the MCP/anyio framework may run on its own worker threads). So
two tool calls can be in flight on two different threads at the same time, race
inside the JVM, and deadlock it (the observed CLOSE-WAIT pileup).

The fix is one process-wide chokepoint: every Ghidra-touching operation acquires
``GHIDRA_GLOBAL_LOCK`` before doing work. Concurrent clients then QUEUE and
succeed (serialized, therefore slower) instead of hanging.

Why a ``threading.RLock`` and not an ``asyncio.Lock``:

* Sync tool handlers execute off the event loop on framework worker threads, so
  an ``asyncio.Lock`` (which only serializes coroutines on one loop) would not
  cover them. A ``threading`` primitive serializes across every thread.
* It must be *reentrant* because a single logical operation nests several
  Ghidra calls on the same thread — e.g.
  ``decompile_function_by_name_or_addr`` -> ``find_function`` ->
  ``decompile_function``. Each of those is individually serialized (see
  ``serialize_ghidra_methods``), so a plain ``Lock`` would self-deadlock.

Granularity / fairness tradeoff: the lock is taken *per GhidraTools operation*,
not per MCP tool call. A batch ``decompile_function`` (a list of targets) does
NOT hold the lock across the whole batch — each target's Ghidra calls acquire
and release it, so a batch from one client interleaves fairly with calls from
another client instead of starving them.
"""

import functools
import inspect
import threading

# One reentrant lock for the whole process. Shared by GhidraTools (via
# serialize_ghidra_methods) and by the handful of context-level Ghidra writes
# in mcp_tools (project.save after struct/function edits).
GHIDRA_GLOBAL_LOCK = threading.RLock()


def serialize_ghidra(func):
    """Wrap a callable so it holds ``GHIDRA_GLOBAL_LOCK`` while it runs."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with GHIDRA_GLOBAL_LOCK:
            return func(*args, **kwargs)

    return wrapper


def serialize_ghidra_methods(cls):
    """Class decorator: serialize every public method through the global lock.

    Wraps each plain-function attribute whose name does not start with ``_``.
    Private helpers are intentionally left unwrapped: they are only ever called
    from an already-serialized public method on the same thread, and the lock is
    reentrant, so wrapping them too would only add redundant acquisitions.
    ``staticmethod``/``classmethod`` descriptors are skipped (``inspect.isfunction``
    is False for them), which is fine — the public API here is all instance
    methods.
    """

    for name, attr in list(vars(cls).items()):
        if name.startswith("_"):
            continue
        if inspect.isfunction(attr):
            setattr(cls, name, serialize_ghidra(attr))
    return cls
