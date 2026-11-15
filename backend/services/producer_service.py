"""Provision, verify, rotate, and revoke source-bound producer keys."""

import hashlib
import hmac
import re
import secrets
from uuid import uuid4

from sqlalchemy.orm import Session

from ..config import settings
from ..models.base import utc_now
from ..models.producer import EventProducer

_KEY_PATTERN = re.compile(r"^spk_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$")


def _new_key(producer_id: str) -> str:
    return f"spk_{producer_id}.{secrets.token_urlsafe(32)}"


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def provision_producer(db: Session, *, name: str, source: str) -> tuple[EventProducer, str]:
    if (not name or name != name.strip() or len(name) > 128 or not source
            or source != source.strip() or len(source) > 64):
        raise ValueError("A name and v1-compatible source are required")
    if source == "*" and settings.ENVIRONMENT != "testing":
        raise ValueError("Wildcard sources are permitted only in testing")
    producer_id = uuid4().hex
    key = _new_key(producer_id)
    producer = EventProducer(id=producer_id, name=name, source=source, key_hash=_digest(key))
    db.add(producer)
    db.commit()
    db.refresh(producer)
    return producer, key


def verify_producer_key(db: Session, key: str) -> EventProducer | None:
    match = _KEY_PATTERN.fullmatch(key)
    if match is None:
        return None
    producer = db.get(EventProducer, match.group(1))
    if producer is None or not producer.is_active:
        return None
    if not hmac.compare_digest(producer.key_hash, _digest(key)):
        return None
    return producer


def revoke_producer(db: Session, producer_id: str) -> EventProducer | None:
    producer = db.get(EventProducer, producer_id)
    if producer is None:
        return None
    producer.is_active = False
    producer.revoked_at = utc_now()
    db.commit()
    return producer


def rotate_producer(db: Session, producer_id: str) -> tuple[EventProducer, str] | None:
    producer = db.get(EventProducer, producer_id)
    if producer is None or not producer.is_active:
        return None
    key = _new_key(producer_id)
    producer.key_hash = _digest(key)
    db.commit()
    return producer, key
