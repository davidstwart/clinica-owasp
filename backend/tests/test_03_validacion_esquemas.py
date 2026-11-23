"""
Pruebas unitarias — Validación de esquemas (Pydantic).
ISO/IEC 29119-2 nivel componente · OWASP A03 Inyección / A04 Diseño inseguro

La validación en el borde es la barrera que impide que datos malformados
lleguen a la capa de negocio o a la base de datos.

Casos: CP-VAL-001 … CP-VAL-020
"""
from datetime import date

import pytest
from pydantic import ValidationError

from src.atenciones.schemas import AtencionCreate
from src.auth.schemas import CambioPasswordRequest, UsuarioCreate
from src.citas.schemas import CitaCreate, CitaEstadoUpdate
from src.citas.models import EstadoCita
from src.pacientes.schemas import PacienteCreate

pytestmark = pytest.mark.unit

PACIENTE_VALIDO = {
    "nombres": "María Elena",
    "apellidos": "García López",
    "dni": "12345678",
    "fecha_nacimiento": "1985-03-15",
    "telefono": "987654321",
    "email": "maria@email.com",
}


def _p(**cambios):
    return {**PACIENTE_VALIDO, **cambios}


# ── Pacientes ────────────────────────────────────────────────────────────────
def test_CP_VAL_001_paciente_valido_se_acepta():
    p = PacienteCreate(**PACIENTE_VALIDO)
    assert p.dni == "12345678"
    assert p.fecha_nacimiento == date(1985, 3, 15)


@pytest.mark.parametrize("dni", ["1234567", "123456789", "1234567a", "abcdefgh", ""])
def test_CP_VAL_002_dni_invalido_es_rechazado(dni):
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(dni=dni))


def test_CP_VAL_003_telefono_no_numerico_es_rechazado():
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(telefono="98765-4321"))


def test_CP_VAL_004_telefono_demasiado_corto_es_rechazado():
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(telefono="12345"))


def test_CP_VAL_005_fecha_futura_es_rechazada():
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(fecha_nacimiento="2099-01-01"))


def test_CP_VAL_006_edad_inexistente_es_rechazada():
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(fecha_nacimiento="1850-01-01"))


def test_CP_VAL_007_email_invalido_es_rechazado():
    with pytest.raises(ValidationError):
        PacienteCreate(**_p(email="no-es-un-correo"))


def test_CP_VAL_008_campos_obligatorios_faltantes_son_rechazados():
    with pytest.raises(ValidationError):
        PacienteCreate(nombres="Solo", apellidos="Nombre")


def test_CP_VAL_009_espacios_en_texto_se_normalizan():
    """A.4 — la normalización evita registros duplicados por espacios."""
    p = PacienteCreate(**_p(nombres="  María   Elena  "))
    assert p.nombres == "María Elena"


# ── Citas ────────────────────────────────────────────────────────────────────
def test_CP_VAL_010_cita_valida_se_acepta():
    c = CitaCreate(paciente_id=1, medico_id=2,
                   fecha_hora="2030-01-01T09:00:00", motivo="Control general")
    assert c.motivo == "Control general"


def test_CP_VAL_011_motivo_muy_corto_es_rechazado():
    with pytest.raises(ValidationError):
        CitaCreate(paciente_id=1, medico_id=2, fecha_hora="2030-01-01T09:00:00", motivo="x")


def test_CP_VAL_012_identificadores_no_positivos_son_rechazados():
    with pytest.raises(ValidationError):
        CitaCreate(paciente_id=0, medico_id=2, fecha_hora="2030-01-01T09:00:00", motivo="Control")


def test_CP_VAL_013_fecha_anterior_a_2000_es_rechazada():
    with pytest.raises(ValidationError):
        CitaCreate(paciente_id=1, medico_id=2, fecha_hora="1999-01-01T09:00:00", motivo="Control")


def test_CP_VAL_014_estado_pendiente_no_se_acepta_como_transicion():
    with pytest.raises(ValidationError):
        CitaEstadoUpdate(estado=EstadoCita.pendiente)


def test_CP_VAL_015_estado_valido_se_acepta():
    assert CitaEstadoUpdate(estado=EstadoCita.cancelada).estado == EstadoCita.cancelada


# ── Atenciones ───────────────────────────────────────────────────────────────
def test_CP_VAL_016_atencion_valida_se_acepta():
    a = AtencionCreate(paciente_id=1, cita_id=7, diagnostico="Gripe", tratamiento="Paracetamol")
    assert a.diagnostico == "Gripe"


def test_CP_VAL_016b_atencion_sin_cita_es_rechazada():
    """A.5.26 — la historia clínica siempre cuelga de una cita."""
    with pytest.raises(ValidationError):
        AtencionCreate(paciente_id=1, diagnostico="Gripe", tratamiento="Paracetamol")


@pytest.mark.parametrize("campo", ["diagnostico", "tratamiento"])
def test_CP_VAL_017_campos_clinicos_vacios_son_rechazados(campo):
    cuerpo = {"paciente_id": 1, "diagnostico": "Gripe", "tratamiento": "Paracetamol"}
    cuerpo[campo] = "   "
    with pytest.raises(ValidationError):
        AtencionCreate(**cuerpo)


# ── Usuarios ─────────────────────────────────────────────────────────────────
def test_CP_VAL_018_usuario_valido_se_acepta():
    u = UsuarioCreate(nombre="Profesional Clinico",
                      email="profesional@clinica.pe", password="Huancayo#Med2026")
    assert u.rol == "recepcionista"  # rol por defecto = mínimo privilegio
    assert u.debe_cambiar_contrasena is True


def test_CP_VAL_019_contrasena_debil_en_alta_es_rechazada():
    with pytest.raises(ValidationError):
        UsuarioCreate(nombre="Usuario Prueba", email="prueba@clinica.pe", password="corta1")


def test_CP_VAL_020_cambio_de_contrasena_valido_se_acepta():
    c = CambioPasswordRequest(password_actual="Vieja#Clave2026", password_nueva="Huancayo#Root2026")
    assert c.password_nueva == "Huancayo#Root2026"