"""Service layer for recording security audit trail logs."""

from typing import Any
from sqlalchemy.orm import Session

from ..models.audit import AuditLog
from ..models.base import utc_now


def record_audit_log(
    db: Session,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Record an immutable security audit trail entry."""
    log = AuditLog(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=utc_now(),
        details=details,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log
