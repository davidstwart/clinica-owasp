"""
ISO/IEC 27001:2022 — A.8.16 Monitoreo / OWASP A09:2021.

Reglas automáticas de alerta sobre el registro de auditoría. Se evalúan en el
momento de escribir cada evento, de modo que la alerta **no depende de que
alguien consulte el tablero**: si nadie mira el registro, la alerta ya existe.

| Alerta | Disparador | Ventana |
|---|---|---|
| `ALERTA_INTENTOS_INTRUSION` | ≥5 `LOGIN_FALLIDO` desde la misma IP | 10 min |
| `ALERTA_CUENTA_BLOQUEADA` | ≥1 `LOGIN_CUENTA_BLOQUEADA` (fuerza bruta) | 10 min |
| `ALERTA_EVENTOS_MASIVOS` | ≥20 eventos WARNING/SECURITY (errores masivos) | 5 min |

Cada alerta se emite **una sola vez por ventana y clave**, para que una ráfaga
de fallos no sature el registro (ruido = ausencia de monitoreo efectivo).
"""
import logging
from datetime import timedelta

from sqlalchemy.orm import Session

from ..common.time_utils import utcnow
from .models import AuditoriaLog, NivelLog

logger = logging.getLogger("clinica.auditoria.alertas")

VENTANA_INTRUSION_MIN = 10
UMBRAL_INTRUSION = 5
VENTANA_MASIVA_MIN = 5
UMBRAL_MASIVO = 20

ACCIONES_MASIVAS = ("ACCESO_DENEGADO", "LOGIN_FALLIDO", "MFA_FALLIDO")


def _ya_alertado(db: Session, accion: str, clave: str, minutos: int) -> bool:
    """¿Existe ya una alerta con la misma clave dentro de la ventana?"""
    limite = utcnow() - timedelta(minutes=minutos)
    return (
        db.query(AuditoriaLog)
        .filter(
            AuditoriaLog.accion == accion,
            AuditoriaLog.detalle.like(f"clave={clave} %"),
            AuditoriaLog.created_at >= limite,
        )
        .first()
        is not None
    )


def _emitir(db: Session, accion: str, detalle: str) -> None:
    """Escribe la alerta como un evento CRITICAL del propio registro."""
    from .service import MAX_DETALLE, registrar_log

    registrar_log(
        db, None, accion, None, None, None,
        detalle=detalle[:MAX_DETALLE], nivel=NivelLog.CRITICAL.value,
        evaluar=False,
    )
    logger.warning("ALERTA accion=%s %s", accion, detalle)


def _conteo(db: Session, desde, acciones: tuple | None = None,
            niveles: tuple | None = None, ip: str | None = None) -> int:
    consulta = db.query(AuditoriaLog).filter(AuditoriaLog.created_at >= desde)
    if acciones:
        consulta = consulta.filter(AuditoriaLog.accion.in_(acciones))
    if niveles:
        consulta = consulta.filter(AuditoriaLog.nivel.in_(niveles))
    if ip:
        consulta = consulta.filter(AuditoriaLog.ip_address == ip)
    return consulta.count()


def evaluar_alertas(db: Session, accion: str, ip: str | None) -> None:
    """Evalúa las reglas tras registrar un evento. Nunca lanza excepciones."""
    try:
        if accion == "LOGIN_FALLIDO" and ip:
            if not _ya_alertado(db, "ALERTA_INTENTOS_INTRUSION", f"ip={ip}", VENTANA_INTRUSION_MIN):
                intentos = _conteo(
                    db, utcnow() - timedelta(minutes=VENTANA_INTRUSION_MIN),
                    acciones=("LOGIN_FALLIDO",), ip=ip,
                )
                if intentos >= UMBRAL_INTRUSION:
                    _emitir(
                        db, "ALERTA_INTENTOS_INTRUSION",
                        f"clave=ip={ip} intentos={intentos} ventana={VENTANA_INTRUSION_MIN}min",
                    )
            return

        if accion == "LOGIN_CUENTA_BLOQUEADA":
            if not _ya_alertado(db, "ALERTA_CUENTA_BLOQUEADA", "global", VENTANA_INTRUSION_MIN):
                bloqueos = _conteo(
                    db, utcnow() - timedelta(minutes=VENTANA_INTRUSION_MIN),
                    acciones=("LOGIN_CUENTA_BLOQUEADA",),
                )
                if bloqueos >= 1:
                    _emitir(
                        db, "ALERTA_CUENTA_BLOQUEADA",
                        f"clave=global bloqueos={bloqueos} ventana={VENTANA_INTRUSION_MIN}min",
                    )
            return

        if accion in ACCIONES_MASIVAS:
            if not _ya_alertado(db, "ALERTA_EVENTOS_MASIVOS", "global", VENTANA_MASIVA_MIN):
                masivo = _conteo(
                    db, utcnow() - timedelta(minutes=VENTANA_MASIVA_MIN),
                    niveles=(NivelLog.WARNING.value, NivelLog.SECURITY.value),
                )
                if masivo >= UMBRAL_MASIVO:
                    _emitir(
                        db, "ALERTA_EVENTOS_MASIVOS",
                        f"clave=global eventos={masivo} ventana={VENTANA_MASIVA_MIN}min",
                    )
    except Exception:  # pragma: no cover - la alerta nunca interrumpe el negocio
        db.rollback()
        logger.exception("No se pudieron evaluar las reglas de alerta accion=%s", accion)
