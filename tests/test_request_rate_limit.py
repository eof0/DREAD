import concurrent.futures
import random
import threading
import time

from scanner.request_handler import RequestHandler


def test_rate_limit_reservations_are_thread_safe(monkeypatch):
    handler = RequestHandler(rate_limit=50)
    monkeypatch.setattr(random, "random", lambda: 0.5)
    barrier = threading.Barrier(3)

    def reserve():
        barrier.wait()
        handler._respect_rate_limit()
        return time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        completed = sorted(executor.map(lambda _index: reserve(), range(3)))

    intervals = [later - earlier for earlier, later in zip(completed, completed[1:])]
    assert all(interval >= 0.015 for interval in intervals)
