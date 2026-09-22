"""Almacen de evidencias sobre SQLite.

Toda la informacion de una sesion vive en un unico fichero ``session.sqlite``
mas un directorio de artefactos (scripts descargados, capturas de pantalla,
cuerpos HTTP cuando el operador los habilita explicitamente).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..audit_core.conclusions import Confidence, Severity, Status
from ..audit_core.events import Event, EventType
from ..audit_core.secrets import SecretVault, assert_no_secrets, redact
from . import chain

SCHEMA = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")


@dataclass
class Finding:
    """Hallazgo emitido por el motor de reglas."""

    rule_id: str
    title: str
    status: Status
    severity: Severity
    confidence: Confidence
    summary: str
    detail: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "detail": self.detail,
            "evidence": self.evidence,
            "created_at": round(self.created_at, 3),
        }


@dataclass
class RequestRecord:
    """Request saliente observado por CDP, por el agente o por el proxy."""

    timestamp: float
    method: str
    url: str
    host: str = ""
    registrable: str = ""
    third_party: bool = False
    resource_type: str = ""
    initiator: str = ""
    stack: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body_size: int = 0
    body_digest: str = ""
    body_ref: str = ""
    tags: list[str] = field(default_factory=list)
    status: int | None = None
    response_size: int | None = None
    redirect_from: str = ""
    sensor: str = "cdp"
    context: str = "main"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": round(self.timestamp, 3),
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "registrable_domain": self.registrable,
            "third_party": self.third_party,
            "resource_type": self.resource_type,
            "initiator": self.initiator,
            "stack": self.stack,
            "headers": self.headers,
            "body_size": self.body_size,
            "body_digest": self.body_digest,
            "body_ref": self.body_ref,
            "tags": self.tags,
            "status": self.status,
            "response_size": self.response_size,
            "redirect_from": self.redirect_from,
            "sensor": self.sensor,
            "context": self.context,
        }


@dataclass
class ScriptRecord:
    url: str
    sha256: str
    size: int
    third_party: bool = False
    inline: bool = False
    sourcemap: str = ""
    path: str = ""
    context: str = "main"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "sha256": self.sha256,
            "size": self.size,
            "third_party": self.third_party,
            "inline": self.inline,
            "sourcemap": self.sourcemap,
            "path": self.path,
            "context": self.context,
        }


class EvidenceStore:
    """Persistencia encadenada de la sesion."""

    def __init__(self, root: Path, session_id: str, vault: SecretVault | None = None):
        self.root = Path(root)
        self.session_id = session_id
        self.vault = vault
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in ("scripts", "screenshots", "evidence"):
            (self.root / sub).mkdir(exist_ok=True)
        self.db_path = self.root / "session.sqlite"
        self.db = sqlite3.connect(str(self.db_path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._chain_head = chain.GENESIS
        self._listeners: list = []

    # -- ciclo de vida --------------------------------------------------
    def open_session(self, target: str, config: dict, versions: dict, note: str = "") -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO session (id,target,started_at,config_json,versions_json,chain_head,note)"
            " VALUES (?,?,?,?,?,?,?)",
            (self.session_id, target, time.time(), json.dumps(config, default=str),
             json.dumps(versions, default=str), self._chain_head, note),
        )
        self.db.commit()

    def close_session(self) -> None:
        self.db.execute(
            "UPDATE session SET ended_at=?, chain_head=? WHERE id=?",
            (time.time(), self._chain_head, self.session_id),
        )
        self.db.commit()

    def close(self) -> None:
        try:
            self.db.commit()
        finally:
            self.db.close()

    @property
    def chain_head(self) -> str:
        return self._chain_head

    def subscribe(self, callback) -> None:
        """Registra un callback invocado por cada evento (UI/CLI en vivo)."""
        self._listeners.append(callback)

    # -- eventos --------------------------------------------------------
    def add_event(self, event: Event) -> Event:
        """Persiste un evento, redactandolo y encadenandolo."""
        event.data = redact(event.data, self.vault)
        payload = event.to_dict()
        payload.pop("seq", None)
        serialized = chain.canonical(payload)
        assert_no_secrets(serialized, self.vault)
        digest = chain.link(self._chain_head, payload)
        cur = self.db.execute(
            "INSERT INTO events (id,session,timestamp,type,context,origin,source,sensor,tags_json,data_json,prev_hash,hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event.id, event.session, event.timestamp, event.type.value, event.context,
                event.origin, event.source, event.sensor, json.dumps(event.tags),
                json.dumps(event.data, default=str), self._chain_head, digest,
            ),
        )
        event.seq = int(cur.lastrowid or 0)
        self._chain_head = digest
        self.db.commit()
        for listener in self._listeners:
            try:
                listener(event)
            except Exception:  # pragma: no cover - un listener no debe romper la captura
                pass
        return event

    def events(self, types: Sequence[EventType | str] | None = None) -> list[Event]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if types:
            names = [t.value if isinstance(t, EventType) else str(t) for t in types]
            query += " WHERE type IN (" + ",".join("?" * len(names)) + ")"
            params = names
        query += " ORDER BY seq"
        rows = self.db.execute(query, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        event = Event(
            type=EventType(row["type"]),
            session=row["session"],
            timestamp=row["timestamp"],
            context=row["context"],
            origin=row["origin"],
            source=row["source"],
            sensor=row["sensor"],
            tags=json.loads(row["tags_json"]),
            data=json.loads(row["data_json"]),
            id=row["id"],
        )
        event.seq = row["seq"]
        return event

    # -- requests -------------------------------------------------------
    def add_request(self, record: RequestRecord) -> RequestRecord:
        self.db.execute(
            "INSERT OR REPLACE INTO requests (id,session,timestamp,method,url,host,registrable,third_party,"
            "resource_type,initiator,stack_json,headers_json,body_size,body_digest,body_ref,tags_json,status,"
            "response_size,redirect_from,sensor,context) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record.id, self.session_id, record.timestamp, record.method, record.url, record.host,
                record.registrable, int(record.third_party), record.resource_type, record.initiator,
                json.dumps(record.stack), json.dumps(record.headers), record.body_size, record.body_digest,
                record.body_ref, json.dumps(record.tags), record.status, record.response_size,
                record.redirect_from, record.sensor, record.context,
            ),
        )
        self.db.commit()
        return record

    def update_request(self, request_id: str, **fields: Any) -> None:
        if not fields:
            return
        columns = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(
            f"UPDATE requests SET {columns} WHERE id=?", (*fields.values(), request_id)
        )
        self.db.commit()

    def requests(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM requests ORDER BY timestamp").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["stack"] = json.loads(item.pop("stack_json"))
            item["headers"] = json.loads(item.pop("headers_json"))
            item["tags"] = json.loads(item.pop("tags_json"))
            item["third_party"] = bool(item["third_party"])
            item["registrable_domain"] = item.pop("registrable")
            item.pop("session", None)
            out.append(item)
        return out

    # -- scripts --------------------------------------------------------
    def add_script(self, record: ScriptRecord, body: bytes | None = None) -> ScriptRecord:
        if body is not None:
            name = f"{record.sha256[:16]}.js"
            path = self.root / "scripts" / name
            path.write_bytes(body)
            record.path = f"scripts/{name}"
        self.db.execute(
            "INSERT OR REPLACE INTO scripts (id,session,url,sha256,size,third_party,inline,sourcemap,path,context)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (record.id, self.session_id, record.url, record.sha256, record.size,
             int(record.third_party), int(record.inline), record.sourcemap, record.path, record.context),
        )
        self.db.commit()
        return record

    def scripts(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM scripts ORDER BY url").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item.pop("session", None)
            item["third_party"] = bool(item["third_party"])
            item["inline"] = bool(item["inline"])
            out.append(item)
        return out

    def script_body(self, sha256: str) -> bytes | None:
        path = self.root / "scripts" / f"{sha256[:16]}.js"
        return path.read_bytes() if path.exists() else None

    # -- hallazgos ------------------------------------------------------
    def add_finding(self, finding: Finding) -> Finding:
        self.db.execute(
            "INSERT OR REPLACE INTO findings (id,session,rule_id,title,status,severity,confidence,summary,detail,"
            "evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (finding.id, self.session_id, finding.rule_id, finding.title, finding.status.value,
             finding.severity.value, finding.confidence.value, finding.summary, finding.detail,
             json.dumps(finding.evidence, default=str), finding.created_at),
        )
        self.db.commit()
        return finding

    def findings(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM findings ORDER BY rule_id").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item.pop("session", None)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            out.append(item)
        return out

    # -- artefactos -----------------------------------------------------
    def add_evidence(self, kind: str, name: str, payload: bytes, subdir: str = "evidence") -> dict[str, Any]:
        digest = hashlib.sha256(payload).hexdigest()
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in name)[:80]
        rel = f"{subdir}/{digest[:12]}-{safe}"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        record = {
            "id": uuid.uuid4().hex, "kind": kind, "name": name, "path": rel,
            "sha256": digest, "size": len(payload), "created_at": time.time(),
        }
        self.db.execute(
            "INSERT INTO evidence (id,session,kind,name,path,sha256,size,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (record["id"], self.session_id, kind, name, rel, digest, len(payload), record["created_at"]),
        )
        self.db.commit()
        return record

    def evidence(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM evidence ORDER BY created_at").fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item.pop("session", None)
            items.append(item)
        return items

    # -- checkpoints ----------------------------------------------------
    def add_checkpoint(self, name: str, network: str, detail: str = "", timestamp: float | None = None) -> dict:
        record = {
            "id": uuid.uuid4().hex, "name": name, "network": network,
            "detail": detail, "timestamp": timestamp if timestamp is not None else time.time(),
        }
        self.db.execute(
            "INSERT INTO checkpoints (id,session,name,timestamp,network,detail) VALUES (?,?,?,?,?,?)",
            (record["id"], self.session_id, name, record["timestamp"], network, detail),
        )
        self.db.commit()
        return record

    def checkpoints(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM checkpoints ORDER BY timestamp").fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item.pop("session", None)
            out.append(item)
        return out

    # -- integridad -----------------------------------------------------
    def verify_chain(self) -> tuple[bool, int | None]:
        rows = self.db.execute("SELECT * FROM events ORDER BY seq").fetchall()
        records = []
        for row in rows:
            event = self._row_to_event(row)
            payload = event.to_dict()
            payload.pop("seq", None)
            records.append((payload, row["prev_hash"], row["hash"]))
        return chain.verify(records)

    def session_info(self) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM session WHERE id=?", (self.session_id,)).fetchone()
        if row is None:
            return {}
        info = dict(row)
        info["config"] = json.loads(info.pop("config_json"))
        info["versions"] = json.loads(info.pop("versions_json"))
        return info
