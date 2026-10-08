"""Remembers how suspicious a person's *recent* messages were, so a scam split over several messages
("Легкая работа" ... "За час 500 тысяч тг") is judged as a whole.

Only messages that scored at least `min_score` are remembered, so ordinary chat never builds up.
Memory only (nothing is written to disk) and bounded in size.
"""
from __future__ import annotations

import time
from collections import OrderedDict, deque


class ScoreHistory:
    def __init__(self, window_seconds: float, min_score: int = 2, max_users: int = 5000):
        self.window = window_seconds
        self.min_score = min_score
        self.max_users = max_users
        self._data: OrderedDict[tuple[int, int], deque[tuple[float, int]]] = OrderedDict()

    def total(self, chat_id: int, user_id: int, score: int, now: float | None = None) -> int:
        """Return this message's score plus the user's earlier qualifying scores in the window,
        and remember this message if it is suspicious enough."""
        now = time.monotonic() if now is None else now
        key = (chat_id, user_id)
        entries = self._data.get(key)
        if entries is not None:
            while entries and now - entries[0][0] > self.window:
                entries.popleft()
        prior = sum(s for _, s in entries) if entries else 0
        if score >= self.min_score:
            if entries is None:
                entries = self._data[key] = deque(maxlen=20)
            entries.append((now, score))
            self._data.move_to_end(key)
            while len(self._data) > self.max_users:
                self._data.popitem(last=False)
        elif entries is not None and not entries:
            del self._data[key]
        return prior + score
