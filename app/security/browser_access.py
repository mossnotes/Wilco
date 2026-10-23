"""Coordinate vault account deletion with live browsers and profile persistence."""

import asyncio
import uuid

_locks: dict[uuid.UUID, asyncio.Lock] = {}
_revisions: dict[uuid.UUID, int] = {}
_browsers: dict[uuid.UUID, set[asyncio.Task]] = {}


def profile_lock(owner: uuid.UUID) -> asyncio.Lock:
    return _locks.setdefault(owner, asyncio.Lock())


def profile_revision(owner: uuid.UUID) -> int:
    return _revisions.get(owner, 0)


def register_browser(owner: uuid.UUID) -> None:
    _browsers.setdefault(owner, set()).add(asyncio.current_task())


def unregister_browser(owner: uuid.UUID) -> None:
    if running := _browsers.get(owner):
        running.discard(asyncio.current_task())
        if not running:
            _browsers.pop(owner, None)


def revoke_browsers(owner: uuid.UUID) -> set[asyncio.Task]:
    # Caller holds profile_lock across deletion and commit. A browser which loaded
    # the previous revision must never write that state back during cancellation.
    _revisions[owner] = profile_revision(owner) + 1
    running = set(_browsers.get(owner, ())) - {asyncio.current_task()}
    for task in running:
        if not task.done() and not task.cancelling():
            task.cancel()
    return running
