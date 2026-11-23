"""Local asset store with JSON and SQLite backends."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from demo_core.config import StoreConfig
from demo_core.errors import ConfigError
from demo_core.models import Asset


class AssetStore(ABC):
    """Persistent set of discovered assets keyed by ``asset_id``."""

    @abstractmethod
    def upsert_many(self, assets: Iterable[Asset]) -> tuple[int, int]:
        """Insert or update. Returns ``(inserted, updated)``. Preserves ``first_seen``."""

    @abstractmethod
    def list(self) -> list[Asset]: ...

    @abstractmethod
    def get(self, asset_id: str) -> Asset | None: ...

    @abstractmethod
    def clear(self) -> None: ...

    def count(self) -> int:
        return len(self.list())

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


def _carry_first_seen(new: Asset, old: Asset | None) -> Asset:
    if old and old.first_seen:
        new.first_seen = old.first_seen
    return new


class JSONAssetStore(AssetStore):
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8")).get("assets", {})
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigError(f"asset store {self.path} is unreadable: {exc}") from exc

    def _write(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".assets-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "assets": data}, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)  # atomic
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def upsert_many(self, assets: Iterable[Asset]) -> tuple[int, int]:
        ins = upd = 0
        with self._lock:
            data = self._read()
            for a in assets:
                old = Asset.from_dict(data[a.asset_id]) if a.asset_id in data else None
                data[a.asset_id] = _carry_first_seen(a, old).to_dict()
                if old:
                    upd += 1
                else:
                    ins += 1
            self._write(data)
        return ins, upd

    def list(self) -> list[Asset]:
        with self._lock:
            return [Asset.from_dict(v) for _, v in sorted(self._read().items())]

    def get(self, asset_id: str) -> Asset | None:
        with self._lock:
            raw = self._read().get(asset_id)
        return Asset.from_dict(raw) if raw else None

    def clear(self) -> None:
        with self._lock:
            self._write({})


class SQLiteAssetStore(AssetStore):
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS assets (
                 asset_id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, mac TEXT,
                 device_type TEXT, first_seen TEXT, last_seen TEXT, data TEXT NOT NULL)"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac)")
        self._conn.commit()

    def upsert_many(self, assets: Iterable[Asset]) -> tuple[int, int]:
        ins = upd = 0
        with self._lock, self._conn:
            for a in assets:
                row = self._conn.execute(
                    "SELECT data FROM assets WHERE asset_id=?", (a.asset_id,)
                ).fetchone()
                old = Asset.from_dict(json.loads(row[0])) if row else None
                a = _carry_first_seen(a, old)
                self._conn.execute(
                    """INSERT INTO assets(asset_id,hostname,ip,mac,device_type,first_seen,last_seen,data)
                       VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(asset_id) DO UPDATE SET hostname=excluded.hostname, ip=excluded.ip,
                         mac=excluded.mac, device_type=excluded.device_type,
                         first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                         data=excluded.data""",
                    (a.asset_id, a.hostname, a.ip, a.mac, a.device_type, a.first_seen, a.last_seen,
                     json.dumps(a.to_dict(), sort_keys=True)),
                )
                if old:
                    upd += 1
                else:
                    ins += 1
        return ins, upd

    def list(self) -> list[Asset]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM assets ORDER BY asset_id").fetchall()
        return [Asset.from_dict(json.loads(r[0])) for r in rows]

    def get(self, asset_id: str) -> Asset | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
        return Asset.from_dict(json.loads(row[0])) if row else None

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM assets")

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def open_store(cfg: StoreConfig) -> AssetStore:
    if cfg.type == "json":
        return JSONAssetStore(cfg.path)
    if cfg.type == "sqlite":
        return SQLiteAssetStore(cfg.path)
    raise ConfigError(f"unknown store type {cfg.type!r}")
