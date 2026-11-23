"""
Reportes — A.5.15 (solo administración), A.8.15 / A.5.34.

Dos operaciones:
  · `GET  /api/reportes/resumen`  — indicadores consolidados de la clínica.
  · `POST /api/reportes/validar`  — sella un reporte emitido con SHA-256 y
    deja constancia auditable de la revisión (`VALIDAR_REPORTE`).

Ambas son de solo lectura sobre el negocio: no modifican datos clínicos.
"""
import hashlib
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..atenciones.models import Atencion
from ..auditoria.models import AuditoriaLog, NivelLog
from ..auditoria.service import registrar_log
from ..auth.models import RolUsuario, Usuario
from ..auth.security import obtener_ip, requerir_rol
from ..citas.models import Cita, EstadoCita
from ..common.time_utils import utcnow
from ..database import get_db
from ..pacientes.models import Paciente
from .schemas import (
    ReporteResumen,
    ValidacionReporteRequest,
    ValidacionReporteResponse,
)

router = APIRouter(prefix="/api/reportes", tags=["Reportes"])

solo_admin = requerir_rol(RolUsuario.admin)


@router.get("/resumen", response_model=ReporteResumen)
def reporte_resumen(db: Session = Depends(get_db), _usuario=Depends(solo_admin)):
    """A.5.34 — indicadores de gestión; no expone datos identificables."""
    ahora = utcnow()

    return ReporteResumen(
        generado_en=ahora,
        pacientes={"total": db.query(Paciente).count()},
        citas=_conteo_citas(db),
        atenciones={"total": db.query(Atencion).count()},
        usuarios=_conteo_usuarios(db),
        auditoria_24h=_conteo_auditoria(db, ahora - timedelta(hours=24)),
    )


def _conteo_citas(db: Session) -> dict[str, int]:
    conteo = {"total": db.query(Cita).count()}
    for estado in EstadoCita:
        conteo[estado.value] = db.query(Cita).filter(Cita.estado == estado).count()
    return conteo


def _conteo_usuarios(db: Session) -> dict[str, int]:
    return {
        "total": db.query(Usuario).count(),
        "activos": db.query(Usuario).filter(Usuario.activo.is_(True)).count(),
        "con_mfa": db.query(Usuario).filter(Usuario.mfa_habilitado.is_(True)).count(),
    }


def _conteo_auditoria(db: Session, desde) -> dict[str, int]:
    base = db.query(AuditoriaLog).filter(AuditoriaLog.created_at >= desde)
    return {
        "eventos_24h": base.count(),
        "logins_exitosos_24h": base.filter(AuditoriaLog.accion == "LOGIN_EXITOSO").count(),
        "logins_fallidos_24h": base.filter(AuditoriaLog.accion == "LOGIN_FALLIDO").count(),
        "alertas": db.query(AuditoriaLog)
        .filter(AuditoriaLog.accion.like("ALERTA_%"))
        .count(),
    }


@router.post("/validar", response_model=ValidacionReporteResponse, status_code=201)
def validar_reporte(
    datos: ValidacionReporteRequest,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(solo_admin),
):
    """
    A.8.15 / A.5.34 — sello de integridad sobre el reporte revisado: se calcula
    SHA-256 sobre la serialización canónica (clave ordenada) y se registra en
    la auditoría. Cualquier cambio posterior al reporte invalida el sello.
    """
    canonico = json.dumps(
        datos.reporte, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")
    )
    digesto = hashlib.sha256(canonico.encode("utf-8")).hexdigest()
    evento = registrar_log(
        db, usuario.id, "VALIDAR_REPORTE", "reportes", None, obtener_ip(request),
        detalle=f"sha256={digesto}", nivel=NivelLog.SECURITY.value,
    )
    return ValidacionReporteResponse(
        hash_sha256=digesto,
        registrado_en=evento.created_at if evento else utcnow(),
    )
