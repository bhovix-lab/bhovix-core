"""Fake model: replays recorded answers keyed by ``<document sha256>-<attempt>.json``. An unknown key raises."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from decimal import Decimal
from pathlib import Path
from typing import Any

from hadavin_sdk.config import Route
from hadavin_sdk.models import Reply


class UnknownRecording(KeyError):
    pass


class FakeLLM:
    def __init__(self, recorded_dir: Path, routes: dict[str, Route]) -> None:
        self.recorded_dir = Path(recorded_dir)
        self.routes = routes
        self.calls: list[dict[str, Any]] = []
        self._attempts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        route: str,
        tools: list[dict[str, Any]] | None = None,
        documents: list[bytes] | None = None,
        output_schema: dict[str, Any] | None = None,
    ) -> Reply:
        doc = documents[0] if documents else json.dumps(messages, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(doc).hexdigest()
        with self._lock:
            self._attempts[digest] += 1
            attempt = self._attempts[digest]
            self.calls.append({"route": route, "tools": tools, "messages": messages})
        path = self.recorded_dir / f"{digest}-{attempt}.json"
        if not path.is_file():
            raise UnknownRecording(path.name)
        data = json.loads(path.read_text(encoding="utf-8"))
        r = self.routes[route]
        cost = (
            Decimal(data.get("input_tokens", 0)) * r.input_usd_per_mtok
            + Decimal(data.get("output_tokens", 0)) * r.output_usd_per_mtok
        ) / Decimal(1_000_000)
        return Reply(**data, cost_usd=cost, model_id=r.model_id)
