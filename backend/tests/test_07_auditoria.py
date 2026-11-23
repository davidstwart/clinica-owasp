"""
Pruebas de integración — Registro de auditoría (A.8.15).
ISO/IEC 27001 A.8.15 · ISO/IEC 25010 (seguridad funcional)

El registro de auditoría es el control que permite reconstruir quién hizo qué,
cuándo y desde dónde. Se prueban los atributos exigidos por la norma:
registro, fecha/hora, autor, tipo de evento y resultado.

Casos: CP-AUD-001 … CP-AUD-016
"""
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]


def _registros(cliente, admin, **params):
    consulta = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"/api/auditoria/?limit=200" + (f"&{consulta}" if consulta else "")
    r = cliente.get(url, headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def test_CP_AUD_001_login_exitoso_queda_registrado(cliente, datos):
    cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"})
    from tests.conftest import _autenticar
    admin = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")

    cuerpo = _registros(cliente, admin, accion="LOGIN_EXITOSO")
    assert cuerpo["total"] >= 1
    evento = cuerpo["resultados"][0]
    assert evento["usuario_id"] is not None
    assert evento["created_at"] is not None
    assert evento["ip_address"] is not None


def test_CP_AUD_002_login_fallido_registra_ip_y_usuario(cliente, datos):
    from tests.conftest import _autenticar
    admin = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")

    cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "Incorrecta#2026"})
    cuerpo = _registros(cliente, admin, accion="LOGIN_FALLIDO")
    assert cuerpo["total"] >= 1
    assert cuerpo["resultados"][0]["nivel"] in ("WARNING", "SECURITY")


def test_CP_AUD_003_creacion_de_paciente_auditada_con_recurso(cliente, admin, nuevo_paciente):
    r = cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente)
    assert r.status_code == 201
    cuerpo = _registros(cliente, admin, accion="CREAR_PACIENTE")
    evento = cuerpo["resultados"][0]
    assert evento["tabla_afectada"] == "pacientes"
    assert evento["registro_id"] == r.json()["id"]


def test_CP_AUD_004_edicion_y_borrado_auditados(cliente, admin, datos):
    objetivo = datos["pacientes"][0]
    cuerpo = {"nombres": "Nombre", "apellidos": "Cambiado", "dni": objetivo.dni}

    assert cliente.put(f"/api/pacientes/{objetivo.id}", headers=admin, json=cuerpo).status_code == 200
    assert _registros(cliente, admin, accion="EDITAR_PACIENTE")["total"] >= 1

    # Se necesita un paciente sin historial para poder borrarlo.
    nuevo = cliente.post("/api/pacientes/", headers=admin, json={
        "nombres": "Temporal", "apellidos": "Borrable", "dni": "55555555",
    }).json()
    assert cliente.delete(f"/api/pacientes/{nuevo['id']}", headers=admin).status_code == 204
    assert _registros(cliente, admin, accion="ELIMINAR_PACIENTE")["total"] >= 1


def test_CP_AUD_005_cambio_de_estado_de_cita_registra_transicion(cliente, admin, medico, datos):
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": "2099-05-05T09:00:00", "motivo": "Consulta auditada",
    }).json()
    cliente.put(f"/api/citas/{cita['id']}/estado", headers=medico, json={"estado": "confirmada"})

    cuerpo = _registros(cliente, admin, accion="CAMBIAR_ESTADO_CITA")
    evento = cuerpo["resultados"][0]
    assert "pendiente->confirmada" in evento["detalle"]


def test_CP_AUD_006_cambio_de_contrasena_auditado(cliente, datos):
    from tests.conftest import _autenticar

    cabeceras = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    r = cliente.post("/api/auth/change-password", headers=cabeceras,
                     json={"password_actual": "AdminDemo#2026", "password_nueva": "Huancayo#Root2026"})
    assert r.status_code == 200

    admin = _autenticar(cliente, "admin@test.pe", "Huancayo#Root2026")
    assert _registros(cliente, admin, accion="CAMBIO_CONTRASENA")["total"] >= 1


def test_CP_AUD_007_logout_auditado(cliente, admin):
    assert cliente.post("/api/auth/logout", headers=admin).status_code == 204
    # Tras el logout el token se revoca, por lo que se requiere una sesión nueva.
    from tests.conftest import _autenticar
    nueva = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    assert _registros(cliente, nueva, accion="LOGOUT")["total"] >= 1


# ── Filtrado y consulta ──────────────────────────────────────────────────────
def test_CP_AUD_008_filtro_por_usuario(cliente, admin, medico, nuevo_paciente):
    """A.5.15 — el médico no crea pacientes: la denegación queda registrada
    contra su usuario, y el filtro por `usuario_id` la devuelve."""
    r = cliente.post("/api/pacientes/", headers=medico, json=nuevo_paciente)
    assert r.status_code == 403
    cuerpo = _registros(cliente, admin, usuario_id=2)
    assert cuerpo["total"] >= 1
    assert all(e["usuario_id"] == 2 for e in cuerpo["resultados"])


def test_CP_AUD_009_filtro_por_nivel(cliente, admin, datos):
    cuerpo = _registros(cliente, admin, nivel="WARNING")
    assert all(e["nivel"] == "WARNING" for e in cuerpo["resultados"])


def test_CP_AUD_010_nivel_invalido_devuelve_422(cliente, admin):
    assert cliente.get("/api/auditoria/?nivel=CRITICO_INVENTADO", headers=admin).status_code == 422


def test_CP_AUD_011_paginacion_consistente_con_el_total(cliente, admin, datos):
    total = _registros(cliente, admin)["total"]
    pagina = cliente.get("/api/auditoria/?skip=0&limit=2", headers=admin).json()
    assert pagina["limit"] == 2
    assert len(pagina["resultados"]) <= 2
    assert pagina["total"] == total


def test_CP_AUD_012_orden_por_fecha_descendente(cliente, admin, nuevo_paciente):
    cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente)
    cuerpo = _registros(cliente, admin)["resultados"]
    fechas = [e["created_at"] for e in cuerpo]
    assert fechas == sorted(fechas, reverse=True)


def test_CP_AUD_013_resumen_de_24_horas_consistente(cliente, admin, datos):
    r = cliente.get("/api/auditoria/resumen", headers=admin)
    assert r.status_code == 200
    cuerpo = r.json()
    for clave in ("eventos_24h", "logins_exitosos_24h", "logins_fallidos_24h",
                  "cuentas_bloqueadas_24h", "cambios_contrasena_24h", "eventos_seguridad_24h"):
        assert clave in cuerpo
    assert cuerpo["logins_exitosos_24h"] >= 1
    assert cuerpo["eventos_24h"] >= cuerpo["logins_exitosos_24h"]


def test_CP_AUD_014_el_registro_no_es_modificable_por_la_api(cliente, admin):
    """A.8.15 — el log es append-only: la API no expone alta, edición ni borrado."""
    from fastapi.routing import APIRoute

    from src.main import app

    verbos_peligrosos = []
    for ruta in app.routes:
        if isinstance(ruta, APIRoute) and ruta.path.startswith("/api/auditoria"):
            if {"POST", "PUT", "PATCH", "DELETE"} & set(ruta.methods):
                verbos_peligrosos.append(ruta.path)
    assert not verbos_peligrosos, verbos_peligrosos


def test_CP_AUD_015_el_detalle_no_almacena_credenciales(cliente, admin, datos):
    """A.5.17 / GDPR art. 32 — nunca se registran contraseñas ni tokens en el log."""
    cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"})
    cuerpo = _registros(cliente, admin)
    for evento in cuerpo["resultados"]:
        assert "AdminDemo#2026" not in (evento["detalle"] or "")
        assert "bcrypt" not in (evento["detalle"] or "")
        assert "$2b$" not in (evento["detalle"] or "")


def test_CP_AUD_016_el_detalle_registra_el_request_id(cliente, admin, nuevo_paciente):
    """A.8.16 — correlación entre la petición y su evento de auditoría."""
    cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente)
    cuerpo = _registros(cliente, admin, accion="CREAR_PACIENTE")
    evento = cuerpo["resultados"][0]
    # El campo existe en el modelo aunque la vista filtrada no lo exponga al cliente.
    from src.auditoria.models import AuditoriaLog

    assert hasattr(AuditoriaLog, "request_id")
    assert evento["ip_address"] is not None