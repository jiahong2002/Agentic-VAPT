import uuid
from datetime import datetime, timezone
from models import ScanSession, ScanState, SDLCPhase

_sessions: dict[str, ScanSession] = {}


def create_session(phase: SDLCPhase, initiated_by: str = "anonymous") -> ScanSession:
    session_id = str(uuid.uuid4())
    session = ScanSession(
        session_id=session_id,
        phase=phase,
        state=ScanState.IDLE,
        initiated_by=initiated_by,
        start_time=datetime.now(timezone.utc).isoformat(),
    )
    _sessions[session_id] = session
    return session


def get_session(session_id: str) -> ScanSession | None:
    return _sessions.get(session_id)


def update_session(session: ScanSession) -> None:
    _sessions[session.session_id] = session


def finalize_session(session: ScanSession) -> None:
    session.end_time = datetime.now(timezone.utc).isoformat()
    _sessions[session.session_id] = session


def push_progress(session_id: str, message: str) -> None:
    """Append a progress message to a session's live log (GIL-safe dict mutation)."""
    session = _sessions.get(session_id)
    if session:
        session.progress_log.append(message)
        _sessions[session_id] = session
