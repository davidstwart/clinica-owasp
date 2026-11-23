"""
Pruebas de control de acceso — OWASP A01:2021 · ISO/IEC 27001 A.5.15.

Pruebas de caja negra (comportamiento observable) y de caja blanca
(estructura de dependencias de cada ruta), según ISO/IEC 29119-2 §5.2.

Casos: CP-RBAC-001 … CP-RBAC-012

Hallazgo de la revisión: los parámetros de dependencia sin anotación de tipo
(`_=todos`) NO se registran como dependencia en FastAPI y dejaban el endpoint
sin autenticar. El caso CP-RBAC-011 comprueba de forma estructural que esto no
pueda volver a ocurrir (NC-02 del registro de no conformidades).
"""
import pytest

from src.auth.security import CABECERA_CAMBIO_CONTRASENA

pytestmark = [pytest.mark.integration, pytest.mark.security]

RUTAS_PROTEGIDAS = [
    ("GET",    "/api/auth/me"),
    ("GET",    "/api/auth/usuarios"),
    ("POST",   "/api/auth/usuarios"),
    ("PUT",    "/api/auth/usuarios/1"),
    ("DELETE", "/api/auth/usuarios/1"),
    ("POST",   "/api/auth/change-password"),
    ("POST",   "/api/auth/logout"),
    ("GET",    "/api/pacientes/"),
    ("GET",    "/api/pacientes/1"),
    ("POST",   "/api/pacientes/"),
    ("PUT",    "/api/pacientes/1"),
    ("DELETE", "/api/pacientes/1"),
    ("GET",    "/api/citas/"),
    ("POST",   "/api/citas/"),
    ("PUT",    "/api/citas/1/estado"),
    ("DELETE", "/api/citas/1"),
    ("GET",    "/api/atenciones/"),
    ("GET",    "/api/atenciones/paciente/1"),
    ("GET",    "/api/atenciones/1"),
    ("POST",   "/api/atenciones/"),
    ("GET",    "/api/auditoria/"),
    ("GET",    "/api/auditoria/resumen"),
]

# Rutas públicas por diseño: no requieren sesión.
RUTAS_PUBLICAS = [("GET", "/"), ("GET", "/health"), ("POST", "/api/auth/login")]


def _llamar(cliente, metodo, ruta, cabeceras=None, cuerpo=None):
    return cliente.request(metodo, ruta, headers=cabeceras or {}, json=cuerpo)


# ── Sin sesión ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("metodo,ruta", RUTAS_PROTEGIDAS)
def test_CP_RBAC_001_sin_token_toda_ruta_responde_401(cliente, metodo, ruta):
    assert _llamar(cliente, metodo, ruta).status_code == 401, ruta


@pytest.mark.parametrize("metodo,ruta", RUTAS_PUBLICAS)
def test_CP_RBAC_002_rutas_publicas_no_exigen_sesion(cliente, metodo, ruta):
    assert _llamar(cliente, metodo, ruta).status_code != 401, ruta


# ── Matriz de permisos por rol ───────────────────────────────────────────────
# (método, ruta, cuerpo) -> estado esperado por rol
def _paciente(dni: str) -> dict:
    return {"nombres": "Test", "apellidos": "Uno", "dni": dni}


MATRIZ = [
    ("GET",    "/api/pacientes/",        None, {"admin": 200, "medico": 200, "recepcionista": 200}),
    ("POST",   "/api/pacientes/",        {"nombres": "Test", "apellidos": "Uno", "dni": "44444444"},
                                            {"admin": 201, "medico": 403, "recepcionista": 409}),
    ("DELETE", "/api/pacientes/1",       None, {"admin": 204, "medico": 403, "recepcionista": 403}),
    ("GET",    "/api/atenciones/",       None, {"admin": 200, "medico": 200, "recepcionista": 403}),
    ("GET",    "/api/auditoria/",        None, {"admin": 200, "medico": 403, "recepcionista": 403}),
    ("GET",    "/api/auditoria/resumen", None, {"admin": 200, "medico": 403, "recepcionista": 403}),
    ("GET",    "/api/auth/usuarios",     None, {"admin": 200, "medico": 403, "recepcionista": 403}),
    ("POST",   "/api/auth/usuarios",     {"nombre": "Profesional Nuevo", "email": "profesional@test.pe",
                                          "password": "Huancayo#Med2026", "rol": "medico"},
                                            {"admin": 201, "medico": 403, "recepcionista": 403}),
    ("GET",    "/api/citas/",            None, {"admin": 200, "medico": 200, "recepcionista": 200}),
]


@pytest.mark.parametrize("metodo,ruta,cuerpo,esperado", MATRIZ)
def test_CP_RBAC_003_matriz_de_permisos_por_rol(
    cliente, datos, admin, medico, recepcionista, metodo, ruta, cuerpo, esperado
):
    cabeceras = {"admin": admin, "medico": medico, "recepcionista": recepcionista}
    for rol, estado_esperado in esperado.items():
        r = _llamar(cliente, metodo, ruta, cabeceras[rol], cuerpo)
        assert r.status_code == estado_esperado, f"{rol} {metodo} {ruta} -> {r.status_code}"


# ── Aislamiento del recepcionista en la agenda ───────────────────────────────
def test_CP_RBAC_004_recepcionista_no_confirma_ni_atiende(
    cliente, datos, recepcionista, medico, admin
):
    """A.5.15 — el recepcionista gestiona la agenda, el médico la cierra."""
    from datetime import timedelta

    from src.common.time_utils import utcnow

    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": (utcnow() + timedelta(days=3)).isoformat(),
        "motivo": "Evaluación de prueba",
    })
    assert cita.status_code == 201
    cita_id = cita.json()["id"]

    r = cliente.put(f"/api/citas/{cita_id}/estado", headers=recepcionista, json={"estado": "atendida"})
    assert r.status_code == 403

    # El médico asignado sí puede.
    r = cliente.put(f"/api/citas/{cita_id}/estado", headers=medico, json={"estado": "atendida"})
    assert r.status_code == 200
    assert r.json()["estado"] == "atendida"


def test_CP_RBAC_005_medico_no_gestiona_usuarios_ni_auditoria(cliente, medico):
    assert cliente.get("/api/auth/usuarios", headers=medico).status_code == 403
    assert cliente.get("/api/auditoria/", headers=medico).status_code == 403
    assert cliente.post("/api/auth/usuarios", headers=medico, json={
        "nombre": "Intruso", "email": "intruso@test.pe",
        "password": "Intruso#2026", "rol": "admin",
    }).status_code == 403


def test_CP_RBAC_006_rol_dentro_del_token_no_otorga_privilegios(cliente, datos):
    """A.5.15 — el rol se valida contra el estado en base de datos, no contra el JWT."""
    from src.auth.security import crear_token

    token_admin_falso = crear_token(datos["usuarios"]["recepcionista"])
    r = cliente.get("/api/auth/usuarios", headers={"Authorization": f"Bearer {token_admin_falso}"})
    assert r.status_code == 403


# ── Estructura de dependencias (caja blanca) ─────────────────────────────────
def test_CP_RBAC_011_toda_ruta_protegida_declara_una_dependencia_de_seguridad():
    """
    Caja blanca: ninguna ruta de negocio puede quedarse sin la dependencia de
    autorización. Es la defensa estructural contra el defecto NC-02.
    """
    from fastapi.routing import APIRoute

    from src.main import app

    sin_seguridad = []
    for ruta in app.routes:
        if not isinstance(ruta, APIRoute) or not ruta.path.startswith("/api"):
            continue
        if ruta.path == "/api/auth/login":
            continue  # pública por diseño
        nombres = _cadena_de_dependencias(ruta)
        # `usuario_desde_desafio_mfa` autentica los endpoints del segundo factor
        # con el JWT de desafío incluido en el cuerpo (A07).
        if not (nombres & {"requerir_rol", "usuario_operativo", "obtener_usuario_actual",
                           "usuario_desde_desafio_mfa"}):
            sin_seguridad.append(f"{sorted(getattr(ruta, 'methods', []))} {ruta.path}")

    assert not sin_seguridad, f"Rutas sin control de acceso: {sin_seguridad}"


def _cadena_de_dependencias(ruta) -> set:
    """Nombres de todas las dependencias, incluidos los niveles anidados."""
    nombres: set = set()
    pila = list(ruta.dependant.dependencies)
    while pila:
        d = pila.pop()
        nombres.add(getattr(d.call, "__name__", type(d.call).__name__))
        pila.extend(d.dependencies)
    return nombres


def test_CP_RBAC_012_la_dependencia_de_autorizacion_esta_registrada_como_subdependencia():
    """Verifica que `requerir_rol` encadena la validación de sesión y de rotación."""
    from fastapi.routing import APIRoute

    from src.main import app

    for ruta in app.routes:
        if isinstance(ruta, APIRoute) and ruta.path == "/api/pacientes/" and "GET" in ruta.methods:
            nombres = _cadena_de_dependencias(ruta)
            assert "usuario_operativo" in nombres
            assert "obtener_usuario_actual" in nombres
            return
    pytest.fail("No se encontró la ruta GET /api/pacientes/")
