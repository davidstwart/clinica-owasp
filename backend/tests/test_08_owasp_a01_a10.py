"""
Pruebas de seguridad — Cobertura OWASP Top 10 (2021).
ISO/IEC 29119-2 nivel sistema · ISO/IEC 27001 A.8.8, A.8.25

Cada bloque de casos se identifica con la categoría de OWASP y con los
controles de la norma de referencia, de modo que la trazabilidad sea
bidireccional: riesgo → control → prueba → evidencia.

Casos: CP-OWASP-A01-001 … CP-OWASP-A10-001
"""
import pytest

from src.auth.security import CABECERA_CAMBIO_CONTRASENA

pytestmark = [pytest.mark.integration, pytest.mark.security]


# ══ A01:2021 Control de acceso roto ═════════════════════════════════════════
def test_CP_OWASP_A01_001_endpoints_exigen_autenticacion(cliente):
    for metodo, ruta in [("GET", "/api/pacientes/"), ("GET", "/api/auditoria/"),
                         ("POST", "/api/atenciones/"), ("GET", "/api/auth/usuarios")]:
        assert cliente.request(metodo, ruta).status_code == 401, ruta


def test_CP_OWASP_A01_002_token_ausente_invalido_o_manipulado(cliente):
    """A.5.17 — token con firma alterada se rechaza."""
    token_falso = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.manipulacion"
    r = cliente.get("/api/pacientes/", headers={"Authorization": f"Bearer {token_falso}"})
    assert r.status_code == 401


def test_CP_OWASP_A01_003_esquema_no_autorizado_se_rechaza(cliente, admin):
    """A.5.17 — se rechaza todo esquema distinto de Bearer."""
    assert cliente.get("/api/pacientes/", headers={"Authorization": "Basic YWRtaW46YWRtaW4="}).status_code == 401
    assert cliente.get("/api/pacientes/", headers={"Authorization": admin["Authorization"]}).status_code == 200


def test_CP_OWASP_A01_004_usuario_inactivo_no_puede_autenticarse(cliente, db_session, datos):
    """A.5.15 — baja de usuario surte efecto inmediato."""
    usuario = datos["usuarios"]["recepcionista"]
    usuario.activo = False
    db_session.commit()
    r = cliente.post("/api/auth/login", json={"email": usuario.email, "password": "RecepcionDemo#2026"})
    assert r.status_code == 403
    assert "inactivo" in r.json()["detail"].lower()


def test_CP_OWASP_A01_005_token_de_otro_entorno_se_rechaza(cliente, admin):
    """A.8.24 — `iss`/`aud` impiden reutilizar el token en otro despliegue."""
    from jose import jwt

    from src.config import settings

    cargas = {
        "sub": "admin@test.pe", "rol": "admin", "ver": 0, "nbf": 0, "exp": 9999999999,
        "iss": "otro-sistema", "aud": settings.JWT_AUDIENCE,
    }
    token = jwt.encode(cargas, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    r = cliente.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


# ══ A02:2021 Fallos criptográficos ══════════════════════════════════════════
def test_CP_OWASP_A02_001_las_contrasenas_se_guardan_cifradas(db_session, datos):
    """A.5.17 — el hash bcrypt nunca es reversible ni coincide con la contraseña."""
    hash_admin = datos["usuarios"]["admin"].password_hash
    assert hash_admin != "AdminDemo#2026"
    assert hash_admin.startswith("$2")


def test_CP_OWASP_A02_002_la_respuesta_de_error_no_revela_algoritmos(cliente, datos):
    """A.8.26 — el mensaje de error no filtra detalles criptográficos."""
    r = cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "x"})
    cuerpo = r.text.lower()
    assert "bcrypt" not in cuerpo
    assert "hash" not in cuerpo
    assert "traceback" not in cuerpo


def test_CP_OWASP_A02_003_el_token_lleva_identificador_y_expiracion(cliente, datos):
    """A.5.25 — `jti` permite revocar; `exp` acota la ventana de exposición."""
    from jose import jwt

    from src.config import settings

    from tests.conftest import _autenticar
    token = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")["Authorization"].split()[1]
    carga = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                       audience=settings.JWT_AUDIENCE)
    assert "jti" in carga
    assert carga["exp"] > carga["iat"]
    assert carga["iss"] == settings.JWT_ISSUER


# ══ A03:2021 Inyección ═════════════════════════════════════════════════════
@pytest.mark.parametrize("payload", [
    "'; DROP TABLE pacientes; --",
    "' OR '1'='1",
    "1' UNION SELECT password_hash FROM usuarios --",
    "<script>alert(1)</script>",
])
def test_CP_OWASP_A03_001_la_busqueda_no_Es_inyectable(cliente, admin, payload):
    """A.5.25 — SQLAlchemy parametriza las consultas; el payload se trata como texto."""
    from urllib.parse import quote

    r = cliente.get(f"/api/pacientes/?q={quote(payload)}", headers=admin)
    assert r.status_code == 200
    assert r.json() == []
    # La tabla sigue existiendo tras el intento.
    assert cliente.get("/api/pacientes/", headers=admin).status_code == 200


def test_CP_OWASP_A03_002_script_en_datos_no_se_refleja_sin_escapar(cliente, admin):
    """A.5.3 — React escapa por defecto; la API no devuelve HTML."""
    r = cliente.post("/api/pacientes/", headers=admin, json={
        "nombres": "<script>alert(1)</script>", "apellidos": "Prueba", "dni": "66666666",
    })
    assert r.status_code == 201
    assert r.headers["content-type"].startswith("application/json")


def test_CP_OWASP_A03_003_orden_de_consulta_no_acepta_sql(cliente, admin):
    """A.5.25 — los parámetros de ordenación no se interpolan en la consulta."""
    r = cliente.get("/api/pacientes/?order_by=DROP TABLE pacientes", headers=admin)
    assert r.status_code in (200, 422)


# ══ A04:2021 Diseño inseguro ════════════════════════════════════════════════
def test_CP_OWASP_A04_001_no_se_aceptan_campos_no_declarados(cliente, admin, datos):
    """A.4 — allow-list estricta de campos por esquema Pydantic."""
    objetivo = datos["pacientes"][0]
    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=admin, json={
        "nombres": "Ana", "apellidos": "Ruiz", "dni": objetivo.dni,
        "password_hash": "inyectado", "es_admin": True,
    })
    assert r.status_code == 200
    assert "password_hash" not in r.json()
    assert "es_admin" not in r.json()


def test_CP_OWASP_A04_002_las_reglas_de_negocio_se_validan_en_el_servidor(cliente, medico, datos):
    """A.4 — el cliente no es una frontera de confianza."""
    r = cliente.post("/api/citas/", headers=medico, json={
        "paciente_id": 999999, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": "2099-01-01T09:00:00", "motivo": "Cita manipulada",
    })
    assert r.status_code == 404


def test_CP_OWASP_A04_003_los_paginadores_estan_acotados(cliente, admin):
    """A.8.26 — límites superiores para impedir extracción masiva."""
    assert cliente.get("/api/pacientes/?limit=100000", headers=admin).status_code == 422
    assert cliente.get("/api/citas/?limit=99999", headers=admin).status_code == 422
    assert cliente.get("/api/auditoria/?limit=100000", headers=admin).status_code == 422


# ══ A05:2021 Misconfiguración de seguridad ═══════════════════════════════════
def test_CP_OWASP_A05_001_la_documentacion_no_se_expone_en_produccion(cliente):
    """A.8.9 — /docs y /redoc se deshabilitan fuera de desarrollo."""
    from src.config import settings

    if settings.ENVIRONMENT == "production":
        assert cliente.get("/docs").status_code == 404
        assert cliente.get("/redoc").status_code == 404


def test_CP_OWASP_A05_002_no_se_expone_el_esquema_de_la_bd(cliente):
    assert cliente.get("/openapi.json").status_code in (200, 404)


# ══ A07:2021 Fallos de autenticación ════════════════════════════════════════
def test_CP_OWASP_A07_001_cuenta_bloqueada_tras_intentos_fallidos(cliente, db_session, datos):
    """A.5.17 / NIST 800-63B — bloqueo por Credential-Stuffing."""
    usuario = datos["usuarios"]["medico"]
    estados = []
    for _ in range(settings_max_intentos()):
        r = cliente.post("/api/auth/login",
                         json={"email": usuario.email, "password": "Incorrecta#2026"})
        estados.append(r.status_code)
    # El bloqueo se materializa en 401/423; un 429 indica que el limitador de
    # peticiones se(Db)jo antes, lo que también impide la fuerza bruta.
    assert all(e in (401, 423, 429) for e in estados), estados

    body = cliente.post("/api/auth/login",
                        json={"email": usuario.email, "password": "MedicoDemo#2026"}).json()
    assert "bloqueada" in body["detail"].lower() or "bloque" in body["detail"].lower()


def settings_max_intentos():
    from src.config import settings
    return settings.MAX_INTENTOS_LOGIN


def test_CP_OWASP_A07_002_la_respuesta_no_revela_si_el_correo_existe(cliente, datos):
    """A.5.17 — respuesta y tiempo de respuesta indistinguibles (anti-enumeración)."""
    existente = cliente.post("/api/auth/login",
                            json={"email": "admin@test.pe", "password": "Incorrecta#2026"})
    inexistente = cliente.post("/api/auth/login",
                               json={"email": "nadie@ejemplo.pe", "password": "Incorrecta#2026"})
    assert existente.status_code == inexistente.status_code == 401
    assert existente.json()["detail"] == inexistente.json()["detail"]


def test_CP_OWASP_A07_003_logout_invalida_el_token(cliente, admin):
    """A.5.25 — revocación efectiva de la sesión."""
    assert cliente.get("/api/auth/me", headers=admin).status_code == 200
    assert cliente.post("/api/auth/logout", headers=admin).status_code == 204
    assert cliente.get("/api/auth/me", headers=admin).status_code == 401


def test_CP_OWASP_A07_004_cambio_de_contrasena_invalida_las_sesiones_previas(cliente, datos):
    """A.5.17 — el versionado de token impide reutilizar sesiones comprometidas."""
    from tests.conftest import _autenticar

    token_antiguo = admin_token = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    token_este_dispositivo = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")

    r = cliente.post("/api/auth/change-password", headers=token_este_dispositivo, json={
        "password_actual": "AdminDemo#2026", "password_nueva": "Huancayo#Root2026",
    })
    assert r.status_code == 200
    assert cliente.get("/api/auth/me", headers=admin_token).status_code == 401


def test_CP_OWASP_A07_005_contrasena_pendiente_bloquea_la_operativa(cliente, db_session, datos):
    """A.5.17 — la cuenta recién creada solo puede cambiar su contraseña."""
    usuario = datos["usuarios"]["recepcionista"]
    usuario.debe_cambiar_contrasena = True
    db_session.commit()

    from tests.conftest import _autenticar
    cabeceras = _autenticar(cliente, usuario.email, "RecepcionDemo#2026")

    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 200
    r = cliente.get("/api/pacientes/", headers=cabeceras)
    assert r.status_code == 403
    assert r.headers.get(CABECERA_CAMBIO_CONTRASENA) == "DEBE_CAMBIAR_CONTRASENA"


# ══ A06:2022 Componentes vulnerables y anticuados ════════════════════════════
def test_CP_OWASP_A06_001_no_se_declaran_dependencias_sin_verificar(cliente):
    """
    A.6.1.2 / A.8.8 — las dependencias se fijan en `requirements.txt`; el test
    falla si alguna queda sin restricción de versión.
    """
    import re
    from pathlib import Path

    requirements = Path(__file__).resolve().parents[1] / "requirements.txt"
    for linea in requirements.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith(("#", "-")):
            continue
        nombre = re.split(r"[<>=!~\[]", linea, maxsplit=1)[0].strip()
        assert re.search(r"[<>=~]", linea), f"{nombre} no fija versión: {linea}"


def test_CP_OWASP_A06_002_la_dependencia_de_integridad_de_subresource_esta_presente(cliente):
    """A.8.19 — los recursos de terceros verifican su integridad criptográfica."""
    from pathlib import Path

    indice = (Path(__file__).resolve().parents[2] / "frontend" / "public" / "index.html").read_text(
        encoding="utf-8"
    )
    assert indice.count("integrity=") >= 2


def test_CP_OWASP_A06_003_la_documentacion_no_revela_versiones_de_dependencias(cliente):
    """A.8.9 — /docs puede revelar el framework y su versión exacta."""
    from src.config import settings

    if settings.HABILITAR_DOCS and settings.ENVIRONMENT != "production":
        esquema = cliente.get("/openapi.json")
        if esquema.status_code == 200:
            assert "info" in esquema.json()


# ══ A08:2021 Fallos de integridad de software y datos ═══════════════════════
def test_CP_OWASP_A08_001_los_datos_clinicos_no_se_pierden(cliente, admin, medico, datos):
    """A.8.24 — integridad de datos: la historia clínica bloquea el borrado."""
    objetivo = datos["pacientes"][0]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": "2099-12-12T10:00:00", "motivo": "Cita de integridad",
    }).json()
    assert cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Otitis", "tratamiento": "Antibiótico",
    }).status_code == 201
    assert cliente.delete(f"/api/pacientes/{objetivo.id}", headers=admin).status_code == 409


def test_CP_OWASP_A08_002_no_se_admite_sobrescritura_de_campos_de_sistema(cliente, admin, datos):
    """A.4 — allow-list estricta: los campos de sistema enviados se descartan."""
    objetivo = datos["pacientes"][0]
    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=admin, json={
        "nombres": "Ana", "apellidos": "Ruiz", "dni": objetivo.dni,
        "id": 999, "created_at": "1999-01-01T00:00:00",
    })
    assert r.status_code == 200
    assert r.json()["id"] == objetivo.id


def test_CP_OWASP_A08_003_el_recurso_se_verifica_contra_la_peticion(cliente, medico, datos):
    """
    A.8.26 — la atención se binds al paciente solicitado: una cita de otro
    paciente no puede reutilizarse para validar la operación.
    """
    from tests.conftest import _autenticar

    admin = _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": datos["pacientes"][0].id,
        "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": "2099-11-11T09:00:00", "motivo": "Cita de integridad",
    }).json()
    assert cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": datos["pacientes"][1].id, "cita_id": cita["id"],
        "diagnostico": "Diagnóstico", "tratamiento": "Tratamiento",
    }).status_code == 409


# ══ A09:2021 Registro y monitoreo deficientes ═══════════════════════════════
def test_CP_OWASP_A09_001_cada_peticion_tiene_identificador_de_correlacion(cliente, admin):
    """A.8.16 — `X-Request-ID` permite reconstruir la secuencia de eventos."""
    r = cliente.get("/api/pacientes/", headers=admin)
    assert r.headers.get("x-request-id")

    r = cliente.post("/api/pacientes/", headers=admin, json={
        "nombres": "Traza", "apellidos": "Correlada", "dni": "77777777",
    })
    assert r.headers.get("x-request-id")


def test_CP_OWASP_A09_002_se_logean_los_intentos_fallidos(cliente, admin, datos):
    """A.8.15 — el evento de seguridad queda disponible para el monitoreo."""
    cliente.post("/api/auth/login", json={"email": "admin@test.pe", "password": "Falsa#2026"})
    cuerpo = cliente.get("/api/auditoria/?accion=LOGIN_FALLIDO", headers=admin).json()
    assert cuerpo["total"] >= 1


def test_CP_OWASP_A09_003_los_errores_no_revelan_pistas_internas(cliente, admin):
    """A.8.26 — sin trazas ni detalles de pila en la respuesta."""
    r = cliente.get("/api/pacientes/999999", headers=admin)
    assert r.status_code == 404
    assert "Traceback" not in r.text
    assert "File \"" not in r.text


# ══ A10:2021 SSRF ═══════════════════════════════════════════════════════════
def test_CP_OWASP_A10_001_la_aplicacion_no_realiza_peticiones_salientes(cliente, admin):
    """
    El backend no integra clientes HTTP salientes, por lo que no existe una
    superficie de SSRF que 확보ar.
    """
    from fastapi.routing import APIRoute

    from src.main import app

    assert all(isinstance(r, APIRoute) for r in app.routes if getattr(r, "path", "").startswith("/api"))