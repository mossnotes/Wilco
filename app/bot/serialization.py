"""Fair, cancellable locks with no retained entries for idle conversations."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Hashable


@dataclass
class _Entry:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


class LockPool:
    def __init__(self) -> None:
        self.entries: dict[Hashable, _Entry] = {}

    @asynccontextmanager
    async def hold(self, key: Hashable):
        entry = self.entries.setdefault(key, _Entry())
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0:
                self.entries.pop(key, None)


incoming_messages = LockPool()
