"""Tamper-evident audit log. Hash-chained, append-only, local file."""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path

class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists(): return "GENESIS"
        try:
            last = self.path.read_text().rstrip().split("\n")[-1]
            return json.loads(last)["hash"]
        except Exception:
            return "GENESIS"

    def append(self, event: dict) -> dict:
        prev = self._last_hash()
        entry = {
            "ts": time.time(),
            "prev": prev,
            "event": event,
        }
        body = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256((body + prev).encode()).hexdigest()
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists(): return True, "Empty log"
        prev = "GENESIS"
        for i, line in enumerate(self.path.read_text().splitlines(), 1):
            try:
                e = json.loads(line)
            except: return False, f"Line {i}: not valid JSON"
            recomputed_body = json.dumps({k:e[k] for k in ("ts","prev","event")}, sort_keys=True, default=str)
            recomputed = hashlib.sha256((recomputed_body + prev).encode()).hexdigest()
            if recomputed != e["hash"]:
                return False, f"Hash mismatch at line {i}"
            if e["prev"] != prev:
                return False, f"Prev mismatch at line {i}"
            prev = e["hash"]
        return True, f"Chain OK ({i} entries)"
