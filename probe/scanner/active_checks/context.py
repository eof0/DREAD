import json
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable


@dataclass
class OriginState:
    budget: int
    requests: int = 0
    lock: Lock = field(default_factory=Lock)


class ActiveScanContext:
    def __init__(
        self,
        endpoint: str,
        origin: tuple,
        baseline: Any,
        params: dict,
        request: Callable[..., Any],
        endpoint_budget: int = 24,
        baseline_sql: set[str] | None = None,
        origin_budget: int = 240,
        origin_state: OriginState | None = None,
        method: str = "GET",
        location: str = "query",
    ):
        self.endpoint = endpoint
        self.origin = origin
        self.baseline = baseline
        self.params = params
        self.baseline_sql = baseline_sql or set()
        self._request = request
        # How a mutated payload is delivered: GET query string ("query"), POST form
        # body ("form"), or POST JSON body ("json"). The active checks are unchanged;
        # only the transport differs, so one check covers GET and POST alike.
        self.method = (method or "GET").upper()
        self.location = location
        self._endpoint_budget = endpoint_budget
        self._endpoint_requests = 0
        self._origin_state = origin_state or OriginState(origin_budget)
        self._probes: set[tuple[str, str]] = set()
        self._lock = Lock()

    @property
    def origin_state(self):
        return self._origin_state

    def can_probe(self, module: str) -> bool:
        with self._lock, self._origin_state.lock:
            return (
                self._endpoint_requests < self._endpoint_budget
                and self._origin_state.requests < self._origin_state.budget
            )

    def probe(self, params: dict, *, module: str):
        key = (module, json.dumps(params, sort_keys=True, default=str))
        with self._lock, self._origin_state.lock:
            if key in self._probes:
                return None
            if (
                self._endpoint_requests >= self._endpoint_budget
                or self._origin_state.requests >= self._origin_state.budget
            ):
                return None
            self._probes.add(key)
            self._endpoint_requests += 1
            self._origin_state.requests += 1

        payload_kwarg = {"query": "params", "form": "data", "json": "json"}.get(
            self.location, "params"
        )
        return self._request(
            method=self.method,
            url=self.endpoint,
            allow_redirects=False,
            **{payload_kwarg: params},
        )

    def usage(self) -> dict[str, int]:
        with self._lock, self._origin_state.lock:
            return {
                "endpoint_requests": self._endpoint_requests,
                "endpoint_budget": self._endpoint_budget,
                "origin_requests": self._origin_state.requests,
                "origin_budget": self._origin_state.budget,
            }
