"""
Citas — A.5.15, A.4 (validación), A.8.26 (paginación).
Pruebas: backend/tests/test_06_pacientes_citas_atenciones.py
"""
from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..auditoria.service import registrar_log
from ..auth.models import RolUsuario, Usuario
from ..auth.security import obtener_ip, obtener_user_agent, requerir_rol
from ..common.time_utils import utcnow
from ..database import get_db
from ..middleware.request_context import obtener_request_id
from ..pacientes.models import Paciente
from .models import Cita, EstadoCita
from .schemas import CitaCreate, CitaEstadoUpdate, CitaResponse

router = APIRouter(prefix="/api/citas", tags=["Citas"])

todos = requerir_rol(RolUsuario.admin, RolUsuario.medico, RolUsuario.recepcionista)
solo_admin = requerir_rol(RolUsuario.admin)

DURACION_MINUTOS = 30
MAX_POR_DIA_POR_MEDICO = 16


@router.get("/", response_model=list[CitaResponse])
def listar(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    estado: EstadoCita | None = Query(default=None),
    medico_id: int | None = Query(default=None, ge=1),
    fecha: date | None = Query(default=None, description="Día (YYYY-MM-DD) de la agenda"),
    db: Session = Depends(get_db),
    _usuario=Depends(todos),
):
    """
    A.8.26 — la vista de agenda se filtra por día completo usando un rango de
    fechas (portable entre SQLite y PostgreSQL, sin comparaciones de cadena).
    """
    consulta = db.query(Cita)
    if estado is not None:
        consulta = consulta.filter(Cita.estado == estado)
    if medico_id is not None:
        consulta = consulta.filter(Cita.medico_id == medico_id)
    if fecha is not None:
        inicio = datetime.combine(fecha, time.min)
        consulta = consulta.filter(
            Cita.fecha_hora >= inicio, Cita.fecha_hora < inicio + timedelta(days=1)
        )
    return consulta.order_by(Cita.fecha_hora.desc()).offset(skip).limit(limit).all()


@router.post("/", response_model=CitaResponse, status_code=201)
def crear(
    datos: CitaCreate,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(todos),
):
    """
    A.4 — reglas de negocio verificadas en el servidor: el paciente y el
    médico deben existir, y no se admiten solapamientos en la agenda.
    """
    if not db.query(Paciente).filter(Paciente.id == datos.paciente_id).first():
        raise HTTPException(status_code=404, detail="El paciente no existe")

    medico = db.query(Usuario).filter(Usuario.id == datos.medico_id).first()
    if not medico:
        raise HTTPException(status_code=404, detail="El médico no existe")
    if medico.rol.value != RolUsuario.medico.value and usuario.rol.value != RolUsuario.admin.value:
        raise HTTPException(status_code=400, detail="El usuario asignado no tiene rol de médico")

    inicio = utcnow()
    if datos.fecha_hora.replace(tzinfo=None) < inicio - timedelta(minutes=1):
        raise HTTPException(status_code=400, detail="No se pueden registrar citas en el pasado")

    inicio_ventana = datos.fecha_hora - timedelta(minutes=DURACION_MINUTOS)
    fin_ventana = datos.fecha_hora + timedelta(minutes=DURACION_MINUTOS)
    solapada = (
        db.query(Cita)
        .filter(
            Cita.medico_id == datos.medico_id,
            Cita.estado != EstadoCita.cancelada,
            Cita.fecha_hora > inicio_ventana,
            Cita.fecha_hora < fin_ventana,
        )
        .first()
    )
    if solapada:
        raise HTTPException(
            status_code=409,
            detail=f"Conflicto de agenda: el médico ya tiene una cita el {solapada.fecha_hora:%Y-%m-%d %H:%M}",
        )

    if _excede_agenda_diaria(db, datos.medico_id, datos.fecha_hora):
        raise HTTPException(
            status_code=409, detail=f"El médico alcanzó el máximo de {MAX_POR_DIA_POR_MEDICO} citas del día"
        )

    cita = Cita(**datos.model_dump(), estado=EstadoCita.pendiente)
    db.add(cita)
    db.commit()
    db.refresh(cita)
    registrar_log(
        db, usuario.id, "CREAR_CITA", "citas", cita.id, obtener_ip(request),
        detalle=f"paciente={cita.paciente_id} medico={cita.medico_id}",
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
    return cita


def _excede_agenda_diaria(db: Session, medico_id: int, fecha_hora) -> bool:
    inicio = datetime.combine(fecha_hora.date(), time.min)
    fin = inicio + timedelta(days=1)
    return (
        db.query(Cita)
        .filter(
            Cita.medico_id == medico_id,
            Cita.estado != EstadoCita.cancelada,
            Cita.fecha_hora >= inicio,
            Cita.fecha_hora < fin,
        )
        .count()
        >= MAX_POR_DIA_POR_MEDICO
    )


@router.put("/{id}/estado", response_model=CitaResponse)
def cambiar_estado(
    id: int,
    datos: CitaEstadoUpdate,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(todos),
):
    """
    A01 — solo un médico asignado o un administrador confirma o atiende la cita;
    el recepcionista únicamente puede cancelarla.
    """
    cita = db.query(Cita).filter(Cita.id == id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")

    es_admin = usuario.rol.value == RolUsuario.admin.value
    es_medico_asignado = usuario.id == cita.medico_id
    if datos.estado in (EstadoCita.atendida, EstadoCita.confirmada) and not (es_admin or es_medico_asignado):
        raise HTTPException(
            status_code=403,
            detail="Solo el médico asignado o un administrador puede confirmar o atender la cita",
        )

    if cita.estado == EstadoCita.atendida and datos.estado != EstadoCita.cancelada:
        raise HTTPException(
            status_code=409, detail="Una cita atendida solo puede pasar a cancelada"
        )

    anterior = cita.estado
    cita.estado = datos.estado
    db.commit()
    db.refresh(cita)
    registrar_log(
        db, usuario.id, "CAMBIAR_ESTADO_CITA", "citas", id, obtener_ip(request),
        detalle=f"{anterior.value}->{datos.estado.value}",
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
    return cita


@router.delete("/{id}", status_code=204)
def eliminar(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(solo_admin),
):
    from ..atenciones.models import Atencion

    cita = db.query(Cita).filter(Cita.id == id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="Cita no encontrada")
    if db.query(Atencion).filter(Atencion.cita_id == id).first():
        raise HTTPException(
            status_code=409, detail="La cita tiene una atención registrada; no puede eliminarse"
        )
    db.delete(cita)
    db.commit()
    registrar_log(
        db, usuario.id, "ELIMINAR_CITA", "citas", id, obtener_ip(request),
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
