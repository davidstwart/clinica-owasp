"""
OWASP A09:2021 — Registro y monitoreo
ISO/IEC 27001:2022 — A.8.15 Registro / A.8.16 Monitoreo

Reglas:
  · Nunca se registra una contraseña, un token ni un hash (A.8.15).
  · El `detalle` se trunca a 500 caracteres para respetar el tamaño de columna.
  · La escritura del log es independiente del commit de la operación de
    negocio: un fallo de negocio también queda registrado.
"""
import logging

from sqlalchemy.orm import Session

from .alertas import evaluar_alertas
from .models import AuditoriaLog, NivelLog

logger = logging.getLogger("clinica.auditoria")

MAX_DETALLE = 500


def registrar_log(
    db: Session,
    usuario_id: int | None,
    accion: str,
    tabla: str | None = None,
    registro_id: int | None = None,
    ip: str | None = None,
    detalle: str | None = None,
    nivel: str = NivelLog.INFO.value,
    user_agent: str | None = None,
    request_id: str | None = None,
    evaluar: bool = True,
) -> AuditoriaLog:
    """Registra una acción relevante. Nunca lanza excepción: el registro de
    auditoría no debe impedir la operación de negocio (disponibilidad).

    Tras escribir el evento evalúa automáticamente las reglas de alerta
    (A.8.16); `evaluar=False` evita recursión cuando el propio evento es una
    alerta."""
    try:
        log = AuditoriaLog(
            usuario_id=usuario_id,
            accion=accion[:100],
            nivel=str(nivel),
            tabla_afectada=tabla[:100] if tabla else None,
            registro_id=registro_id,
            ip_address=ip[:50] if ip else None,
            user_agent=user_agent[:200] if user_agent else None,
            detalle=detalle[:MAX_DETALLE] if detalle else None,
            request_id=request_id[:64] if request_id else None,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        logger.info(
            "AUDIT accion=%s usuario=%s recurso=%s:%s ip=%s nivel=%s",
            accion, usuario_id, tabla, registro_id, ip, nivel,
        )
        if evaluar:
            evaluar_alertas(db, accion, ip)
        return log
    except Exception:  # pragma: no cover - ruta de fallo de infraestructura
        db.rollback()
        logger.exception("No se pudo escribir el registro de auditoría accion=%s", accion)
        return None
