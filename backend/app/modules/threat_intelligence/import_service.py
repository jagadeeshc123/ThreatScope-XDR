import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .models import IndicatorRelationship, ThreatCampaign, ThreatIntelImport
from .normalization import INDICATOR_TYPES
from .service import bounded, clean_tags, create_or_merge_indicator, now


MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 5000
STIX_PATTERN = re.compile(r"^\s*\[\s*([a-z0-9-]+):value\s*=\s*(['\"])(.{1,2048})\2\s*\]\s*$", re.I)
STIX_HASH_PATTERN = re.compile(r"^\s*\[\s*file:hashes\.(['\"]?)(SHA-256|SHA-1|MD5)\1\s*=\s*(['\"])([0-9a-fA-F]{32,64})\3\s*\]\s*$", re.I)
STIX_TYPE_MAP = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url", "email-addr": "email", "file": "sha256"}


def safe_filename(name: str | None) -> str | None:
    if not name:
        return None
    leaf = PurePath(name.replace("\\", "/")).name
    return re.sub(r"[^A-Za-z0-9._ -]", "_", leaf)[:255] or "ioc-import"


def parse_date(value: Any, field: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc


def _record(row: dict[str, Any], source_id: int) -> dict[str, Any]:
    kind = row.get("type") or row.get("indicator_type")
    value = row.get("value") or row.get("indicator_value")
    tags = row.get("tags", [])
    if isinstance(tags, str):
        tags = [part.strip() for part in re.split(r"[,;]", tags) if part.strip()]
    if not isinstance(tags, list):
        raise ValueError("tags must be a list or comma-separated text")
    return {
        "type": kind,
        "value": value,
        "title": bounded(row.get("title"), 240),
        "description": bounded(row.get("description"), 4000),
        "severity": str(row.get("severity") or "medium").lower(),
        "confidence": int(row.get("confidence", 50)),
        "tlp": str(row.get("tlp") or "amber").lower().replace("tlp:", ""),
        "tags": clean_tags(tags),
        "first_seen": parse_date(row.get("first_seen") or row.get("first_seen_at"), "first_seen"),
        "last_seen": parse_date(row.get("last_seen") or row.get("last_seen_at"), "last_seen"),
        "valid_until": parse_date(row.get("valid_until"), "valid_until"),
        "source_id": source_id,
    }


def _parse_stix(data: dict[str, Any], source_id: int):
    if data.get("type") != "bundle" or not isinstance(data.get("objects"), list):
        raise ValueError("STIX input must be a bundle with an objects array")
    records: list[tuple[str | None, dict[str, Any]]] = []
    relationships: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    warnings: list[str] = []
    for obj in data["objects"]:
        if not isinstance(obj, dict):
            warnings.append("Unsupported non-object STIX entry")
            continue
        obj_type = obj.get("type")
        if obj_type == "indicator":
            pattern = str(obj.get("pattern") or "")
            if len(pattern) > 4096:
                warnings.append("STIX indicator pattern exceeded the safe limit")
                continue
            match = STIX_PATTERN.fullmatch(pattern)
            hash_match = STIX_HASH_PATTERN.fullmatch(pattern)
            if hash_match:
                algorithm = {"sha-256": "sha256", "sha-1": "sha1", "md5": "md5"}[hash_match.group(2).lower()]
                labels = obj.get("labels") if isinstance(obj.get("labels"), list) else []
                records.append((str(obj.get("id"))[:120], _record({"type": algorithm, "value": hash_match.group(4), "title": obj.get("name"), "description": obj.get("description"), "confidence": obj.get("confidence", 50), "tags": labels, "first_seen": obj.get("valid_from"), "valid_until": obj.get("valid_until")}, source_id)))
                continue
            if not match or match.group(1).lower() not in STIX_TYPE_MAP:
                warnings.append(f"Unsupported STIX indicator pattern for {str(obj.get('id', 'unknown'))[:80]}")
                continue
            stix_type, value = match.group(1).lower(), match.group(3)
            labels = obj.get("labels") if isinstance(obj.get("labels"), list) else []
            records.append((str(obj.get("id"))[:120], _record({"type": STIX_TYPE_MAP[stix_type], "value": value, "title": obj.get("name"), "description": obj.get("description"), "confidence": obj.get("confidence", 50), "tags": labels, "first_seen": obj.get("valid_from"), "valid_until": obj.get("valid_until")}, source_id)))
        elif obj_type == "relationship":
            relationships.append(obj)
        elif obj_type in {"malware", "threat-actor", "campaign"}:
            contexts.append(obj)
        else:
            warnings.append(f"Unsupported STIX object type: {str(obj_type)[:40]}")
    return records, relationships, contexts, warnings


def parse_content(content: bytes, source_id: int):
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Import must be UTF-8 text") from exc
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        data = json.loads(text)
        if isinstance(data, dict) and data.get("type") == "bundle":
            records, relationships, contexts, warnings = _parse_stix(data, source_id)
            return "stix", records, relationships, contexts, warnings
        rows = data.get("indicators") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("JSON must be an array or contain an indicators array")
        return "json", [(None, _record(row, source_id)) for row in rows if isinstance(row, dict)], [], [], []
    first_line = text.splitlines()[0] if text.splitlines() else ""
    header = {part.strip().lower() for part in first_line.split(",")}
    if {"type", "value"}.issubset(header) or {"indicator_type", "indicator_value"}.issubset(header):
        rows = list(csv.DictReader(io.StringIO(text)))
        return "csv", [(None, _record(row, source_id)) for row in rows], [], [], []
    records = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in INDICATOR_TYPES:
            records.append((None, _record({"type": parts[0], "value": parts[1]}, source_id)))
        else:
            raise ValueError("Plain-text rows must use: <indicator_type> <value>")
    return "text", records, [], [], []


def process_import(db: Session, *, source, user_id: int, filename: str | None, content: bytes) -> ThreatIntelImport:
    if not content:
        raise HTTPException(422, "Import file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Import exceeds the {MAX_UPLOAD_BYTES} byte limit")
    digest = hashlib.sha256(content).hexdigest()
    manifest = ThreatIntelImport(source_id=source.id, filename=safe_filename(filename), format="unknown", status="processing", file_sha256=digest, imported_by_user_id=user_id)
    db.add(manifest)
    db.flush()
    try:
        fmt, records, relationships, contexts, warnings = parse_content(content, source.id)
        if len(records) > MAX_RECORDS:
            raise ValueError(f"Import exceeds the {MAX_RECORDS} record limit")
        manifest.format = fmt
        manifest.total_records = len(records)
        manifest.warning_count = len(warnings)
        errors = list(warnings[:50])
        stix_ids: dict[str, int] = {}
        for index, (external_id, payload) in enumerate(records, 1):
            try:
                indicator, duplicate = create_or_merge_indicator(db, payload, user_id, externally_supplied=True)
                if external_id:
                    stix_ids[external_id] = indicator.id
                if duplicate:
                    manifest.duplicate_records += 1
                else:
                    manifest.accepted_records += 1
            except (HTTPException, ValueError, TypeError) as exc:
                manifest.rejected_records += 1
                if len(errors) < 50:
                    errors.append(f"Record {index}: {str(getattr(exc, 'detail', exc))[:240]}")
        allowed_relationships = {"related_to", "resolves_to", "redirects_to", "communicates_with", "downloads", "drops", "impersonates", "associated_with", "duplicate_of"}
        for rel in relationships[:1000]:
            source_id, target_id = stix_ids.get(str(rel.get("source_ref"))), stix_ids.get(str(rel.get("target_ref")))
            label = re.sub(r"[^a-z0-9_-]", "_", str(rel.get("relationship_type") or "related_to").lower())[:64]
            if label not in allowed_relationships:
                label = "custom"
            if source_id and target_id and source_id != target_id and not db.query(IndicatorRelationship).filter_by(source_indicator_id=source_id, target_indicator_id=target_id, relationship_type=label).first():
                db.add(IndicatorRelationship(source_indicator_id=source_id, target_indicator_id=target_id, relationship_type=label, confidence=int(rel.get("confidence", 50)), description=bounded(rel.get("description"), 2000), created_by_user_id=user_id))
        for context in contexts[:200]:
            name = bounded(context.get("name") or context.get("id"), 200, required=True)
            if not db.query(ThreatCampaign).filter_by(name=name).first():
                db.add(ThreatCampaign(name=name, description=bounded(context.get("description"), 4000), severity="medium", confidence=int(context.get("confidence", 50)), tags_json=json.dumps(clean_tags(context.get("labels") if isinstance(context.get("labels"), list) else [str(context.get("type"))])), created_by_user_id=user_id))
        manifest.error_summary_json = json.dumps(errors, sort_keys=True)
        manifest.status = "completed_with_warnings" if manifest.rejected_records or manifest.warning_count else "completed"
        manifest.completed_at = now()
        source.last_import_at = manifest.completed_at
        db.commit()
        db.refresh(manifest)
        return manifest
    except (json.JSONDecodeError, csv.Error, ValueError, TypeError) as exc:
        db.rollback()
        failed = ThreatIntelImport(source_id=source.id, filename=safe_filename(filename), format="unknown", status="failed", error_summary_json=json.dumps([str(exc)[:500]]), file_sha256=digest, imported_by_user_id=user_id, completed_at=now())
        db.add(failed)
        db.commit()
        raise HTTPException(422, {"message": "Import could not be parsed", "import_id": failed.id, "error": str(exc)[:240]}) from exc
