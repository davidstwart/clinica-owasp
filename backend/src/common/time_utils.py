"""
Utilidades de tiempo — ISO/IEC 25010 (fiabilidad).

Todo el sistema usa **UTC sin zona horaria (naive)** para evitar la clase de
defecto "naive vs aware datetime" al comparar valores leídos de la base de
datos. Las fechas mostradas al usuario se convierten en el frontend.
"""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Instante actual en UTC, sin tzinfo (formato de las columnas DateTime)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def a_utc_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
