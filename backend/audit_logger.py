from datetime import datetime, timezone
from models import AuditEntry, ScanSession
from session_store import get_session, update_session


def log(session_id: str, event: str, actor: str, detail: str, phase: str = None) -> None:
    session = get_session(session_id)
    if not session:
        return
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event=event,
        actor=actor,
        detail=detail,
        phase=phase or session.phase,
    )
    session.audit_log.append(entry)
    update_session(session)
