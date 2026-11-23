"""
Pruebas de integración — Autenticación.
ISO/IEC 29119-2 nivel sistema · OWASP A07 · ISO/IEC 27001 A.5.17, A.5.25, A.8.5

Casos: CP-AUT-001 … CP-AUT-014
"""
import pytest

from src.auth.models import Usuario
from src.config import settings
from tests.conftest import _autenticar

pytestmark = pytest.mark.integration


# ── Éxito ────────────────────────────────────────────────────────────────────
def test_CP_AUT_001_login_valido_devuelve_token(cliente, datos):
    # A07 — la cuenta administrativa no entrega sesión directa: exige el
    # segundo factor (el token todavía no existe en la respuesta).
    r = cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"})
    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["token_type"] == "bearer"
    assert cuerpo["rol"] == "admin"
    assert cuerpo["expira_en_minutos"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES
    assert cuerpo["mfa_requerido"] is True
    assert cuerpo["mfa_pendiente"] is False
    assert cuerpo["access_token"] is None
    assert len(cuerpo["mfa_token"].split(".")) == 3

    # El resto de la operativa entrega sesión tras validar el segundo factor.
    r2 = cliente.post("/api/auth/login", json={"email": "recepcion@test.pe", "password": "RecepcionDemo#2026"})
    assert r2.status_code == 200
    assert len(r2.json()["access_token"].split(".")) == 3


def test_CP_AUT_001b_mfa_completado_devuelve_el_token(cliente, datos):
    from tests.conftest import _autenticar

    cabeceras = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 200


def test_CP_AUT_001c_codigo_mfa_invalido_es_401(cliente, datos):
    r = cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"})
    assert r.json()["mfa_requerido"] is True
    r2 = cliente.post("/api/auth/mfa/verificar", json={
        "mfa_token": r.json()["mfa_token"], "codigo": "000000",
    })
    assert r2.status_code == 401


def test_CP_AUT_001d_token_mfa_no_sirve_como_sesion(cliente, datos):
    """A07 — el desafío MFA no es un token de sesión (prop=mfa)."""
    r = cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"})
    mfa_token = r.json()["mfa_token"]
    assert cliente.get("/api/auth/me", headers={"Authorization": f"Bearer {mfa_token}"}).status_code == 401


def test_CP_AUT_002_login_es_case_insensitive_en_el_correo(cliente, datos):
    r = cliente.post("/api/auth/login", json={"email": "ADMIN@TEST.PE", "password": "AdminDemo#2026"})
    assert r.status_code == 200


def test_CP_AUT_003_login_registra_el_evento(cliente, datos, db_session):
    from src.auditoria.models import AuditoriaLog
    from tests.conftest import _autenticar

    _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    log = db_session.query(AuditoriaLog).filter(AuditoriaLog.accion == "LOGIN_EXITOSO").first()
    assert log is not None
    assert log.usuario_id == datos["usuarios"]["admin"].id
    assert log.ip_address


# ── Fallos ───────────────────────────────────────────────────────────────────
def test_CP_AUT_004_contrasena_incorrecta_es_401(cliente, datos):
    r = cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "Incorrecta#2026"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Correo o contraseña incorrectos"


def test_CP_AUT_005_correo_inexistente_da_el_mismo_mensaje(cliente, datos):
    """A.5.17 — la respuesta no revela qué correos están registrados."""
    inexistente = cliente.post(
        "/api/auth/login", json={"email": "nadie@test.pe", "password": "Huancayo#Root2026"}
    )
    existente = cliente.post(
        "/api/auth/login", json={"email": "admin@test.pe", "password": "Incorrecta#2026"}
    )
    assert inexistente.status_code == existente.status_code == 401
    assert inexistente.json()["detail"] == existente.json()["detail"]


def test_CP_AUT_006_bloqueo_tras_cinco_intentos(cliente, datos):
    """A07 — bloqueo temporal de la cuenta al alcanzar el umbral."""
    limite = settings.MAX_INTENTOS_LOGIN
    for i in range(limite - 1):
        r = cliente.post("/api/auth/login", json={"email": "medico@test.pe", "password": "Mala#2026"})
        assert r.status_code == 401, f"intento {i + 1}"

    # El intento que alcanza el umbral ya recibe 429 y la cuenta queda bloqueada.
    r = cliente.post("/api/auth/login", json={"email": "medico@test.pe", "password": "Mala#2026"})
    assert r.status_code == 429
    assert "bloqueada" in r.json()["detail"].lower()

    # Incluso con la contraseña correcta la cuenta sigue bloqueada.
    r_ok = cliente.post("/api/auth/login", json={"email": "medico@test.pe", "password": "MedicoDemo#2026"})
    assert r_ok.status_code == 429


def test_CP_AUT_007_bloqueo_registra_ip_y_nivel_seguridad(cliente, datos, db_session):
    from src.auditoria.models import AuditoriaLog

    for _ in range(settings.MAX_INTENTOS_LOGIN):
        cliente.post("/api/auth/login", json={"email": "medico@test.pe", "password": "Mala#2026"})
    log = db_session.query(AuditoriaLog).filter(
        AuditoriaLog.accion == "LOGIN_CUENTA_BLOQUEADA"
    ).first()
    assert log is not None
    assert log.nivel == "SECURITY"
    assert log.ip_address == "testclient"


def test_CP_AUT_008_usuario_inactivo_es_403(cliente, datos, db_session):
    u = datos["usuarios"]["medico"]
    u.activo = False
    db_session.commit()
    r = cliente.post("/api/auth/login", json={"email": "medico@test.pe", "password": "MedicoDemo#2026"})
    assert r.status_code == 403


def test_CP_AUT_009_campos_invalidos_son_422(cliente, datos):
    for cuerpo in [
        {"email": "no-es-correo", "password": "Algo#2026"},
        {"email": "admin@test.pe"},
        {"email": "admin@test.pe", "password": ""},
    ]:
        assert cliente.post("/api/auth/login", json=cuerpo).status_code == 422


# ── Sesión y revocación ──────────────────────────────────────────────────────
def test_CP_AUT_010_me_devuelve_el_usuario_autenticado(cliente, admin, datos):
    r = cliente.get("/api/auth/me", headers=admin)
    assert r.status_code == 200
    assert r.json()["email"] == "admin@test.pe"
    assert "password_hash" not in r.json()


def test_CP_AUT_011_logout_invalida_el_token(cliente, admin):
    assert cliente.get("/api/auth/me", headers=admin).status_code == 200
    assert cliente.post("/api/auth/logout", headers=admin).status_code == 204
    """A.5.25 — el token deja de ser válido en el servidor, no solo en el cliente."""
    assert cliente.get("/api/auth/me", headers=admin).status_code == 401


def test_CP_AUT_012_token_ausente_o_invalido_es_401(cliente, datos):
    assert cliente.get("/api/auth/me").status_code == 401
    assert cliente.get("/api/auth/me", headers={"Authorization": "Bearer invalido"}).status_code == 401
    assert cliente.get("/api/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401


def test_CP_AUT_013_cambio_de_contrasena_requiere_la_actual(cliente, admin):
    r = cliente.post("/api/auth/change-password",
                     headers=admin, json={"password_actual": "Equivocada#2026", "password_nueva": "NuevaClave#2026"})
    assert r.status_code == 400


def test_CP_AUT_014_cambio_de_contrasena_revoca_sesiones(cliente, admin, datos):
    r = cliente.post("/api/auth/change-password",
                     headers=admin, json={"password_actual": "AdminDemo#2026", "password_nueva": "NuevaClave#2026"})
    assert r.status_code == 200
    assert r.json()["debe_cambiar_contrasena"] is False
    # Token anterior invalidado y la contraseña antigua deja de ser válida.
    assert cliente.get("/api/auth/me", headers=admin).status_code == 401
    _autenticar(cliente, "admin@test.pe", "NuevaClave#2026")
    assert cliente.post(
        "/api/auth/login", json={"email": "admin@test.pe", "password": "AdminDemo#2026"}
    ).status_code == 401


def test_CP_AUT_015_cambio_de_contrasena_rechaza_politica_débil(cliente, admin):
    for nueva in ["corta1A", "sinmayusculas1", "SinDigitos#", "Admin@test.pe#1"]:
        r = cliente.post("/api/auth/change-password",
                         headers=admin, json={"password_actual": "AdminDemo#2026", "password_nueva": nueva})
        assert r.status_code in (400, 422), nueva


def test_CP_AUT_016_cambio_de_contrasena_rechaza_la_misma(cliente, admin):
    r = cliente.post("/api/auth/change-password",
                     headers=admin, json={"password_actual": "AdminDemo#2026", "password_nueva": "AdminDemo#2026"})
    assert r.status_code == 400


def test_CP_AUT_017_cuenta_pendiente_de_rotacion_no_accede_a_operaciones(
    cliente, datos, db_session
):
    """A.5.17 — la contraseña inicial debe rotarse antes de operar."""
    u = datos["usuarios"]["recepcionista"]
    u.debe_cambiar_contrasena = True
    db_session.commit()
    cabeceras = _autenticar(cliente, "recepcion@test.pe", "RecepcionDemo#2026")

    # /auth/me y /auth/change-password siguen accesibles
    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 200
    # El resto de la API queda bloqueado con un código de error identificable
    r = cliente.get("/api/pacientes/", headers=cabeceras)
    assert r.status_code == 403
    assert r.headers.get("X-Auth-Error-Code") == "DEBE_CAMBIAR_CONTRASENA"


def test_CP_AUT_018_token_conserva_rol_pero_el_servidor_lo_verifica(cliente, datos):
    """A01 — el rol del token es informativo; la decisión usa el estado real."""
    from src.auth.security import crear_token

    u = datos["usuarios"]["recepcionista"]
    token = crear_token(u)  # el token dice "recepcionista"
    cabeceras = {"Authorization": f"Bearer {token}"}
    # Intentamos el endpoint exclusivo de admin: debe denegar por rol real.
    assert cliente.get("/api/auth/usuarios", headers=cabeceras).status_code == 403


def test_CP_AUT_019_deshabilitar_usuario_invalida_sesiones_activas(cliente, datos, db_session):
    cabeceras = _autenticar(cliente, "recepcion@test.pe", "RecepcionDemo#2026")
    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 200
    u = datos["usuarios"]["recepcionista"]
    u.activo = False
    db_session.commit()
    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 401


def test_CP_AUT_020_ultimo_acceso_se_actualiza(cliente, datos, db_session):
    from tests.conftest import _autenticar

    _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    db_session.expire_all()
    assert db_session.query(Usuario).filter(Usuario.email == "admin@test.pe").one().ultimo_acceso is not None
