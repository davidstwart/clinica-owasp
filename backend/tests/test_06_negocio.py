"""
Pruebas de integración — Reglas de negocio de pacientes, citas y atenciones.
ISO/IEC 29119-2 nivel sistema · ISO/IEC 25010 (funcionalidad, fiabilidad)

Verifica que las reglas de dominio se aplican en el servidor y no solo en la
interfaz: el cliente no es una frontera de confianza (OWASP A01/A04).

Casos: CP-NEG-001 … CP-NEG-026
"""
from datetime import timedelta

import pytest

from src.atenciones.models import Atencion
from src.citas.models import EstadoCita
from src.common.time_utils import utcnow
from src.pacientes.models import Paciente

pytestmark = pytest.mark.integration


def _dentro_de(dias: int) -> str:
    """Marca temporal futura usada para agendar sin chocar con otras pruebas."""
    return (utcnow() + timedelta(days=dias, hours=1)).isoformat()


# ── Pacientes ────────────────────────────────────────────────────────────────
def test_CP_NEG_001_crear_paciente_devuelve_201(cliente, admin, nuevo_paciente):
    r = cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente)
    assert r.status_code == 201
    assert r.json()["dni"] == nuevo_paciente["dni"]
    assert r.json()["nombres"] == "Pedro Luis"


def test_CP_NEG_002_dni_duplicado_devuelve_409(cliente, admin, datos, nuevo_paciente):
    nuevo_paciente["dni"] = datos["pacientes"][0].dni
    r = cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente)
    assert r.status_code == 409


def test_CP_NEG_003_eliminar_paciente_sin_historial_lo_borra(cliente, admin, db_session, datos):
    """A.5.33 — sin historial clínico, el borrado es físico."""
    objetivo = datos["pacientes"][0]
    assert cliente.delete(f"/api/pacientes/{objetivo.id}", headers=admin).status_code == 204
    assert db_session.get(Paciente, objetivo.id) is None


def test_CP_NEG_004_paciente_con_historial_clinico_no_se_elimina(cliente, admin, medico, datos):
    """ISO/IEC 25010 fiabilidad + A.5.33: la historia clínica es irremplazable."""
    objetivo = datos["pacientes"][0]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(20), "motivo": "Cita para historial",
    }).json()
    assert cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Gripe estacional",
        "tratamiento": "Paracetamol 500mg",
    }).status_code == 201

    r = cliente.delete(f"/api/pacientes/{objetivo.id}", headers=admin)
    assert r.status_code == 409
    assert "historial" in r.json()["detail"].lower()


def test_CP_NEG_005_al_eliminar_paciente_se_retiran_sus_citas(cliente, admin, medico, datos):
    """A.5.33 — las citas sin atención se eliminan en cascada lógica junto al paciente."""
    objetivo = datos["pacientes"][1]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(4), "motivo": "Consulta previa a baja",
    })
    assert cita.status_code == 201
    assert cliente.delete(f"/api/pacientes/{objetivo.id}", headers=admin).status_code == 204
    assert cliente.get(f"/api/citas/{cita.json()['id']}", headers=admin).status_code in (404, 405)


def test_CP_NEG_006_lista_paginada_respeta_limites(cliente, admin, datos):
    total = cliente.get("/api/pacientes/?limit=100", headers=admin).json()
    assert len(total) == len(datos["pacientes"])
    assert len(cliente.get("/api/pacientes/?skip=1&limit=1", headers=admin).json()) == 1


def test_CP_NEG_007_lista_rechaza_paginacion_excesiva(cliente, admin):
    """A.8.26 — se acota el consumo de recursos por petición."""
    assert cliente.get("/api/pacientes/?limit=5000", headers=admin).status_code == 422
    assert cliente.get("/api/pacientes/?limit=0", headers=admin).status_code == 422
    assert cliente.get("/api/pacientes/?skip=-1", headers=admin).status_code == 422


def test_CP_NEG_008_busqueda_por_nombre_apellido_o_dni(cliente, admin, datos):
    objetivo = datos["pacientes"][0]
    for termino in ("María", "García", objetivo.dni):
        r = cliente.get(f"/api/pacientes/?q={termino}", headers=admin)
        assert r.status_code == 200
        assert objetivo.id in [p["id"] for p in r.json()], termino


def test_CP_NEG_009_busqueda_sin_coincidencias_devuelve_lista_vacia(cliente, admin):
    r = cliente.get("/api/pacientes/?q=zzzzz-inexistente", headers=admin)
    assert r.status_code == 200
    assert r.json() == []


def test_CP_NEG_010_paciente_inexistente_devuelve_404(cliente, admin):
    assert cliente.get("/api/pacientes/999999", headers=admin).status_code == 404


def test_CP_NEG_011_actualizar_no_acepta_campos_injectados(cliente, admin, datos):
    """A.4 — allow-list de campos: `id` y `created_at` enviados por el cliente se descartan."""
    objetivo = datos["pacientes"][0]
    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=admin, json={
        "nombres": "María Elena", "apellidos": "García López",
        "dni": objetivo.dni, "id": 4242, "created_at": "1999-01-01T00:00:00",
    })
    assert r.status_code == 200
    assert r.json()["id"] == objetivo.id
    assert r.json()["created_at"] != "1999-01-01T00:00:00"


def test_CP_NEG_012_actualizar_a_un_dni_ya_usado_devuelve_409(cliente, admin, datos):
    objetivo = datos["pacientes"][0]
    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=admin, json={
        "nombres": "María Elena", "apellidos": "García López",
        "dni": datos["pacientes"][1].dni,
    })
    assert r.status_code == 409


# ── Citas ────────────────────────────────────────────────────────────────────
def test_CP_NEG_013_crear_cita_devuelve_201_en_estado_pendiente(cliente, admin, datos):
    r = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(5), "motivo": "Control de presión arterial",
    })
    assert r.status_code == 201
    assert r.json()["estado"] == EstadoCita.pendiente.value


def test_CP_NEG_014_cita_con_paciente_inexistente_devuelve_404(cliente, admin, datos):
    r = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": 999999, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(5), "motivo": "Cita con paciente inexistente",
    })
    assert r.status_code == 404


def test_CP_NEG_015_cita_con_medico_inexistente_devuelve_404(cliente, admin, datos):
    r = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id, "medico_id": 999999,
        "fecha_hora": _dentro_de(5), "motivo": "Cita con médico inexistente",
    })
    assert r.status_code == 404


def test_CP_NEG_016_no_se_asigna_un_no_medico_como_medico(cliente, recepcionista, admin, datos):
    """A.5.15 — coherencia de privilegios: solo se agenda con usuarios de rol médico."""
    r = cliente.post("/api/citas/", headers=recepcionista, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["recepcionista"].id,
        "fecha_hora": _dentro_de(5), "motivo": "Cita con profesional no médico",
    })
    assert r.status_code == 400


def test_CP_NEG_017_cita_en_el_pasado_devuelve_400(cliente, admin, datos):
    r = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": (utcnow() - timedelta(days=2)).isoformat(),
        "motivo": "Cita en el pasado",
    })
    assert r.status_code == 400


def test_CP_NEG_018_solapamiento_de_cita_devuelve_409(cliente, admin, datos):
    """Regla clínica: un médico no puede tener dos consultas simultáneas."""
    cuerpo = {
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(9),
        "motivo": "Primera consulta del día",
    }
    assert cliente.post("/api/citas/", headers=admin, json=cuerpo).status_code == 201
    cuerpo["motivo"] = "Consulta simultánea no permitida"
    r = cliente.post("/api/citas/", headers=admin, json=cuerpo)
    assert r.status_code == 409
    assert "conflicto" in r.json()["detail"].lower()


def test_CP_NEG_019_agenda_diaria_limitada_a_16_citas(cliente, admin, datos):
    """A.8.26 — la agenda del día se acota para proteger la disponibilidad del profesional."""
    dia = (utcnow() + timedelta(days=15)).replace(hour=9, minute=0, second=0, microsecond=0)
    medico_id = datos["usuarios"]["medico"].id
    aceptadas = 0
    for i in range(18):
        r = cliente.post("/api/citas/", headers=admin, json={
            "paciente_id": datos["pacientes"][0].id,
            "medico_id": medico_id,
            "fecha_hora": (dia + timedelta(minutes=45 * i)).isoformat(),
            "motivo": f"Consulta numero {i + 1}",
        })
        if r.status_code == 201:
            aceptadas += 1
        else:
            assert r.status_code == 409
            break
    assert aceptadas == 16


def test_CP_NEG_020_transicion_valida_a_confirmada_por_el_medico(cliente, admin, medico, datos):
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(10), "motivo": "Consulta de seguimiento",
    }).json()

    r = cliente.put(f"/api/citas/{cita['id']}/estado", headers=medico,
                    json={"estado": "confirmada"})
    assert r.status_code == 200
    assert r.json()["estado"] == "confirmada"


def test_CP_NEG_021_recepcionista_no_confirma_ni_atiende(cliente, admin, recepcionista, medico, datos):
    """A.5.15 — el recepcionista gestiona la agenda; el médico la cierra."""
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(11), "motivo": "Consulta de control",
    }).json()

    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=recepcionista,
                       json={"estado": "confirmada"}).status_code == 403
    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=recepcionista,
                       json={"estado": "atendida"}).status_code == 403
    # Sí puede cancelarla.
    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=recepcionista,
                       json={"estado": "cancelada"}).status_code == 200


def test_CP_NEG_022_una_cita_atendida_solo_puede_cancelarse(cliente, admin, medico, datos):
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(12), "motivo": "Consulta concluida",
    }).json()

    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=medico,
                       json={"estado": "atendida"}).status_code == 200
    r = cliente.put(f"/api/citas/{cita['id']}/estado", headers=medico,
                    json={"estado": "confirmada"})
    assert r.status_code == 409
    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=admin,
                       json={"estado": "cancelada"}).status_code == 200


def test_CP_NEG_023_una_cita_cancelada_libera_el_hueco(cliente, admin, datos):
    """A.4 — la comprobación de solapamiento ignora las citas canceladas."""
    cuerpo = {
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(13), "motivo": "Cita que se cancelara",
    }
    cita = cliente.post("/api/citas/", headers=admin, json=cuerpo).json()
    assert cliente.put(f"/api/citas/{cita['id']}/estado", headers=admin,
                       json={"estado": "cancelada"}).status_code == 200

    cuerpo["motivo"] = "Cita que reutiliza el hueco"
    assert cliente.post("/api/citas/", headers=admin, json=cuerpo).status_code == 201


def test_CP_NEG_024_cita_con_atencion_no_se_elimina(cliente, admin, medico, datos):
    objetivo = datos["pacientes"][0]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(14), "motivo": "Consulta con atención",
    }).json()
    assert cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Cefalea tensional", "tratamiento": "Paracetamol",
    }).status_code == 201

    assert cliente.delete(f"/api/citas/{cita['id']}", headers=admin).status_code == 409


# ── Atenciones ───────────────────────────────────────────────────────────────
def _cita_de(cliente, headers, datos, dias: int, paciente=None) -> dict:
    """Agenda una cita futura con el médico asignado (requisito de atención)."""
    return cliente.post("/api/citas/", headers=headers, json={
        "paciente_id": (paciente or datos["pacientes"][0]).id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(dias),
        "motivo": "Consulta para atención clínica",
    }).json()


def test_CP_NEG_025_el_medico_de_la_atencion_se_toma_del_token(cliente, admin, medico, datos):
    """A.5.15 — el `medico_id` no se acepta del cliente (el cuerpo's `medico_id` se ignora)."""
    cita = _cita_de(cliente, admin, datos, 21)
    r = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": datos["pacientes"][0].id, "cita_id": cita["id"],
        "medico_id": 999999,
        "diagnostico": "Hipertensión arterial", "tratamiento": "Enalapril 10mg",
    })
    assert r.status_code == 201
    assert r.json()["medico_id"] == datos["usuarios"]["medico"].id


def test_CP_NEG_025b_un_medico_distinto_no_registra_la_atencion_de_otro(cliente, admin, medico, datos, db_session):
    """A.5.15 — la atención solo puede registrarla el médico asignado a la cita."""
    from src.auth.models import RolUsuario, Usuario
    from src.auth.security import hashear_password

    otro = Usuario(nombre="Otro Medico", email="otro@medico.pe",
                   password_hash=hashear_password("OtroMed#2026"),
                   rol=RolUsuario.medico, activo=True, debe_cambiar_contrasena=False)
    db_session.add(otro)
    db_session.commit()
    db_session.refresh(otro)

    cita = _cita_de(cliente, admin, datos, 22)
    from tests.conftest import _autenticar

    cabeceras_otro = _autenticar(cliente, otro.email, "OtroMed#2026")
    r = cliente.post("/api/atenciones/", headers=cabeceras_otro, json={
        "paciente_id": datos["pacientes"][0].id, "cita_id": cita["id"],
        "diagnostico": "Intento de suplantación", "tratamiento": "Ninguno",
    })
    assert r.status_code == 403
    assert "asignado" in r.json()["detail"].lower()


def test_CP_NEG_026_atencion_valida_y_historial_por_paciente(cliente, admin, medico, datos):
    objetivo = datos["pacientes"][0]
    for indice, diagnostico in enumerate(("Primera consulta", "Segunda consulta"), start=23):
        cita = _cita_de(cliente, admin, datos, indice)
        assert cliente.post("/api/atenciones/", headers=medico, json={
            "paciente_id": objetivo.id, "cita_id": cita["id"],
            "diagnostico": diagnostico, "tratamiento": "Pauta farmacológica",
            "observaciones": "Paciente colaborador",
        }).status_code == 201

    r = cliente.get(f"/api/atenciones/paciente/{objetivo.id}", headers=medico)
    assert r.status_code == 200
    cuerpo = r.json()
    assert len(cuerpo) == 2
    # Orden inverso por fecha de registro (más reciente primero).
    assert cuerpo[0]["created_at"] >= cuerpo[1]["created_at"]


def test_CP_NEG_027_atencion_para_paciente_inexistente_devuelve_404(cliente, admin, medico, datos):
    cita = _cita_de(cliente, admin, datos, 24)
    r = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": 999999, "cita_id": cita["id"],
        "diagnostico": "Diagnóstico", "tratamiento": "Tratamiento",
    })
    assert r.status_code == 404


def test_CP_NEG_028_atencion_con_datos_incompletos_devuelve_422(cliente, medico, datos):
    r = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": datos["pacientes"][0].id, "diagnostico": "Solo diagnóstico",
    })
    assert r.status_code == 422


def test_CP_NEG_029_atencion_no_puede_usar_una_cita_de_otro_paciente(cliente, admin, medico, datos):
    """A.5.26 — integridad referencial verificada en la capa de negocio."""
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(16), "motivo": "Cita de un paciente",
    }).json()

    r = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": datos["pacientes"][1].id, "cita_id": cita["id"],
        "diagnostico": "Diagnóstico cruzado", "tratamiento": "Tratamiento",
    })
    assert r.status_code == 409
    assert "otro paciente" in r.json()["detail"].lower()


def test_CP_NEG_030_atencion_no_puede_usar_una_cita_cancelada(cliente, admin, medico, datos):
    objetivo = datos["pacientes"][0]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": _dentro_de(17), "motivo": "Cita cancelada previa",
    }).json()
    cliente.put(f"/api/citas/{cita['id']}/estado", headers=admin, json={"estado": "cancelada"})

    r = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Diagnóstico posterior", "tratamiento": "Tratamiento",
    })
    assert r.status_code == 409


def test_CP_NEG_031_historial_de_paciente_inexistente_devuelve_404(cliente, medico):
    assert cliente.get("/api/atenciones/paciente/999999", headers=medico).status_code == 404


def test_CP_NEG_032_atencion_inexistente_devuelve_404(cliente, medico):
    assert cliente.get("/api/atenciones/999999", headers=medico).status_code == 404


# ── Sonda de disponibilidad ──────────────────────────────────────────────────
def test_CP_NEG_033_health_check_no_expone_informacion_sensible(cliente):
    """A.8.16 — sonda demonitorización que no filtra technology, rutas ni credenciales."""
    r = cliente.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_CP_NEG_034_la_atencion_creada_queda_auditada(cliente, admin, medico, datos):
    """A.8.15 — toda acción sobre datos clínicos deja rastro verificable."""
    objetivo = datos["pacientes"][0]
    cita = _cita_de(cliente, admin, datos, 25)
    atencion = cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Asma leve", "tratamiento": "Salbutamol",
    })
    assert atencion.status_code == 201

    r = cliente.get("/api/auditoria/?accion=CREAR_ATENCION", headers=admin)
    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["total"] >= 1
    assert cuerpo["resultados"][0]["accion"] == "CREAR_ATENCION"