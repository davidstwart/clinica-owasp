"""
Pacientes — A.5.15 (control de acceso), A.5.33 (protección de datos personales).
Pruebas: backend/tests/test_06_pacientes_citas_atenciones.py
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..auditoria.service import registrar_log
from ..auth.models import RolUsuario
from ..auth.security import obtener_ip, obtener_user_agent, requerir_rol
from ..database import get_db
from ..middleware.request_context import obtener_request_id
from .models import Paciente
from .schemas import PacienteCreate, PacienteResponse, PacienteUpdate

router = APIRouter(prefix="/api/pacientes", tags=["Pacientes"])

todos = requerir_rol(RolUsuario.admin, RolUsuario.medico, RolUsuario.recepcionista)
# A.5.15 — el médico consulta el padrón; solo administración y recepción
# crean o editan registros (privilegio mínimo sobre datos administrativos).
editar = requerir_rol(RolUsuario.admin, RolUsuario.recepcionista)
solo_admin = requerir_rol(RolUsuario.admin)

MAX_POR_PAGINA = 200


@router.get("/", response_model=list[PacienteResponse])
def listar(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=MAX_POR_PAGINA),
    q: str | None = Query(default=None, max_length=100),
    db: Session = Depends(get_db),
    _usuario=Depends(todos),
):
    """
    A.8.26 — paginación obligatoria para no exponer el padrón completo en una
    sola respuesta. La búsqueda usa parámetros vinculados (nunca concatenados).
    """
    consulta = db.query(Paciente)
    if q:
        patron = f"%{q}%"
        consulta = consulta.filter(
            Paciente.nombres.ilike(patron)
            | Paciente.apellidos.ilike(patron)
            | Paciente.dni.ilike(patron)
        )
    return consulta.order_by(Paciente.apellidos, Paciente.nombres).offset(skip).limit(limit).all()


@router.get("/{id}", response_model=PacienteResponse)
def obtener(id: int, db: Session = Depends(get_db), _usuario=Depends(todos)):
    p = db.query(Paciente).filter(Paciente.id == id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")
    return p


@router.post("/", response_model=PacienteResponse, status_code=201)
def crear(
    datos: PacienteCreate,
    request: Request,
    db: Session = Depends(get_db),
    usuario=Depends(editar),
):
    if db.query(Paciente).filter(Paciente.dni == datos.dni).first():
        raise HTTPException(status_code=409, detail="Ya existe un paciente con ese DNI")
    paciente = Paciente(**datos.model_dump())
    db.add(paciente)
    db.commit()
    db.refresh(paciente)
    registrar_log(
        db, usuario.id, "CREAR_PACIENTE", "pacientes", paciente.id, obtener_ip(request),
        detalle=f"dni={paciente.dni}",
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
    return paciente


@router.put("/{id}", response_model=PacienteResponse)
def actualizar(
    id: int,
    datos: PacienteUpdate,
    request: Request,
    db: Session = Depends(get_db),
    usuario=Depends(editar),
):
    """
    A.4 — el cuerpo se valida contra un modelo explícito (allow-list), por lo
    que un campo `activo` o `id` inyectado se descarta en lugar de asignarse.
    """
    paciente = db.query(Paciente).filter(Paciente.id == id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    if datos.dni != paciente.dni and db.query(Paciente).filter(Paciente.dni == datos.dni).first():
        raise HTTPException(status_code=409, detail="Ya existe un paciente con ese DNI")

    for campo, valor in datos.model_dump().items():
        setattr(paciente, campo, valor)
    db.commit()
    db.refresh(paciente)
    registrar_log(
        db, usuario.id, "EDITAR_PACIENTE", "pacientes", paciente.id, obtener_ip(request),
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
    return paciente


@router.delete("/{id}", status_code=204)
def eliminar(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario=Depends(solo_admin),
):
    """
    A.5.33 — el paciente tiene historial clínico asociado, por lo que se
    **desvincula lógicamente** (se conserva la trazabilidad) en vez de borrarse.
    """
    from ..atenciones.models import Atencion
    from ..citas.models import Cita

    paciente = db.query(Paciente).filter(Paciente.id == id).first()
    if not paciente:
        raise HTTPException(status_code=404, detail="Paciente no encontrado")

    tiene_historial = db.query(Atencion).filter(Atencion.paciente_id == id).first()
    if tiene_historial:
        raise HTTPException(
            status_code=409,
            detail="El paciente tiene historial clínico; por trazabilidad no puede eliminarse",
        )

    db.query(Cita).filter(Cita.paciente_id == id).delete()
    db.delete(paciente)
    db.commit()
    registrar_log(
        db, usuario.id, "ELIMINAR_PACIENTE", "pacientes", id, obtener_ip(request),
        detalle="sin_historial_clinico",
        user_agent=obtener_user_agent(request), request_id=obtener_request_id(request),
    )
