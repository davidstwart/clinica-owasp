"""
Atenciones (historia clínica) — A.5.15, A.5.33, A.4.
Pruebas: backend/tests/test_06_pacientes_citas_atenciones.py

El `medico_id` **no** se acepta desde el cliente: se toma del token. Aceptarlo
permitiría registrar una atención clínica en nombre de otro profesional.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..auditoria.service import registrar_log
from ..auth.models import RolUsuario, Usuario
from ..auth.security import obtener_ip, obtener_user_agent, requerir_rol
from ..database import get_db
from ..middleware.request_context import obtener_request_id
from ..pacientes.models import Paciente
from .models import Atencion
from .schemas import AtencionCreate, AtencionResponse

router = APIRouter(prefix="/api/atenciones", tags=["Atenciones"])

solo_medico = requerir_rol(RolUsuario.admin, RolUsuario.medico)


@router.get("/", response_model=list[AtencionResponse])
def listar(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    paciente_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    _usuario=Depends(solo_medico),
):
    consulta = db.query(Atencion)
    if paciente_id is not None:
        consulta = consulta.filter(Atencion.paciente_id == paciente_id)
    return consulta.order_by(Atencion.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/paciente/{paciente_id}", response_model=list[AtencionResponse])
def por_paciente(
    paciente_id: int,
    db: Session = Depends(get_db),
    _usuario=Depends(solo_medico),
):
    if not db.query(Paciente).filter(Paciente.id == paciente_id).first():
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return (
        db.query(Atencion)
        .filter(Atencion.paciente_id == paciente_id)
        .order_by(Atencion.created_at.desc())
        .all()
    )


@router.post("/", response_model=AtencionResponse, status_code=201)
def crear(
    datos: AtencionCreate,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(solo_medico),
):
    """
    A.5.26 / A.5.15 — la atención exige una cita existente, del mismo paciente
    y **del médico que la tiene asignada**: registrar clínica en nombre de otro
    profesional o sobre la agenda de otro sería una falsificación de historia
    clínica. El `medico_id` se toma del token, nunca del cuerpo.
    """
    if not db.query(Paciente).filter(Paciente.id == datos.paciente_id).first():
        raise HTTPException(status_code=404, detail="El paciente no existe")

    from ..citas.models import Cita, EstadoCita

    cita = db.query(Cita).filter(Cita.id == datos.cita_id).first()
    if not cita:
        raise HTTPException(status_code=404, detail="La cita no existe")
    if cita.paciente_id != datos.paciente_id:
        raise HTTPException(status_code=409, detail="La cita pertenece a otro paciente")
    if cita.estado == EstadoCita.cancelada:
        raise HTTPException(status_code=409, detail="La cita está cancelada")
    if cita.medico_id != usuario.id:
        raise HTTPException(
            status_code=403,
            detail="Solo el médico asignado a la cita puede registrar la atención",
        )

    atencion = Atencion(
        paciente_id=datos.paciente_id,
        medico_id=usuario.id,
        cita_id=datos.cita_id,
        diagnostico=datos.diagnostico,
        tratamiento=datos.tratamiento,
        observaciones=datos.observaciones,
    )
    db.add(atencion)
    db.commit()
    db.refresh(atencion)
    registrar_log(
        db, usuario.id, "CREAR_ATENCION", "atenciones", atencion.id, obtener_ip(request),
        detalle=f"paciente={atencion.paciente_id}",
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
    return atencion


@router.get("/{id}", response_model=AtencionResponse)
def obtener(id: int, db: Session = Depends(get_db), _usuario=Depends(solo_medico)):
    atencion = db.query(Atencion).filter(Atencion.id == id).first()
    if not atencion:
        raise HTTPException(status_code=404, detail="Atención no encontrada")
    return atencion
