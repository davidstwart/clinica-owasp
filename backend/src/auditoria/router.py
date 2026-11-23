"""
A.8.15 — el registro de auditoría solo se consulta. No existe ningún endpoint
de modificación o eliminación: la trazabilidad es a prueba de manipulación
desde la propia aplicación.

Acceso exclusivo del administrador (OWASP A01).
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth.models import RolUsuario
from ..auth.security import requerir_rol
from ..common.time_utils import utcnow
from ..database import get_db
from ..config import settings
from .models import AuditoriaLog, NivelLog

router = APIRouter(prefix="/api/auditoria", tags=["Auditoría"])

solo_admin = requerir_rol(RolUsuario.admin)


@router.get("/")
def listar_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    nivel: str | None = Query(default=None),
    accion: str | None = Query(default=None, min_length=2, max_length=100),
    usuario_id: int | None = Query(default=None, ge=1),
    desde: datetime | None = Query(default=None),
    hasta: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _usuario=Depends(solo_admin),
):
    """
    A.5.28 / A.8.16 — colección de eventos de seguridad filtrable y paginada.
    El límite superior de `limit` evita extracción masiva del registro.
    """
    q = db.query(AuditoriaLog)

    if nivel:
        try:
            q = q.filter(AuditoriaLog.nivel == NivelLog(nivel).value)
        except ValueError:
            raise HTTPException(
                status_code=422, detail=f"Nivel inválido. Valores: {[n.value for n in NivelLog]}"
            )
    if accion:
        q = q.filter(AuditoriaLog.accion.ilike(f"%{accion}%"))
    if usuario_id is not None:
        q = q.filter(AuditoriaLog.usuario_id == usuario_id)
    if desde is not None:
        q = q.filter(AuditoriaLog.created_at >= desde)
    if hasta is not None:
        q = q.filter(AuditoriaLog.created_at <= hasta)

    total = q.count()
    logs = (
        q.order_by(AuditoriaLog.created_at.desc(), AuditoriaLog.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "retencion_dias": settings.AUDIT_RETENTION_DAYS,
        "resultados": [
            {
                "id": l.id,
                "usuario_id": l.usuario_id,
                "accion": l.accion,
                "nivel": l.nivel,
                "tabla_afectada": l.tabla_afectada,
                "registro_id": l.registro_id,
                "ip_address": l.ip_address,
                "detalle": l.detalle,
                "created_at": l.created_at,
            }
            for l in logs
        ],
    }


@router.get("/alertas")
def listar_alertas(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    desde: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _usuario=Depends(solo_admin),
):
    """
    A.8.16 — panel de alertas automáticas (nivel CRITICAL) generadas por las
    reglas de monitoreo: intentos de intrusión, cuentas bloqueadas y ráfagas
    de eventos de seguridad. Solo lectura.
    """
    q = db.query(AuditoriaLog).filter(AuditoriaLog.accion.like("ALERTA_%"))
    if desde is not None:
        q = q.filter(AuditoriaLog.created_at >= desde)
    total = q.count()
    alertas = q.order_by(AuditoriaLog.created_at.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "resultados": [
            {
                "id": a.id,
                "accion": a.accion,
                "nivel": a.nivel,
                "detalle": a.detalle,
                "created_at": a.created_at,
            }
            for a in alertas
        ],
    }


@router.get("/resumen")
def resumen(db: Session = Depends(get_db), _usuario=Depends(solo_admin)):
    """
    A.8.16 — indicadores de monitoreo: fallos de autenticación, bloqueos,
    cambios de contraseña y accesos en las últimas 24 h.
    """
    desde_24h = utcnow() - timedelta(hours=24)
    base = db.query(AuditoriaLog).filter(AuditoriaLog.created_at >= desde_24h)

    return {
        "eventos_24h": base.count(),
        "logins_exitosos_24h": base.filter(AuditoriaLog.accion == "LOGIN_EXITOSO").count(),
        "logins_fallidos_24h": base.filter(AuditoriaLog.accion == "LOGIN_FALLIDO").count(),
        "cuentas_bloqueadas_24h": base.filter(
            AuditoriaLog.accion == "LOGIN_CUENTA_BLOQUEADA"
        ).count(),
        "cambios_contrasena_24h": base.filter(
            AuditoriaLog.accion == "CAMBIO_CONTRASENA"
        ).count(),
        "eventos_seguridad_24h": base.filter(AuditoriaLog.nivel == NivelLog.SECURITY.value).count(),
    }
