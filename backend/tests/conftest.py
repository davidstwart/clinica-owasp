"""
Fixtures compartidas — ISO/IEC 29119-2 §5.2 (entorno de pruebas).

Las pruebas de integración usan una base SQLite en memoria con `StaticPool`
para que todas las sesiones compartan el mismo almacén dentro de una prueba,
lo que hace la suite determinista y sin dependencia de PostgreSQL.

El orden de ejecución de los archivos (`test_01_...` → `test_10_...`) es
significativo: los casos de seguridad se_placean al final para no alterar el
estado compartido.
"""
import os
import sys

import pytest

# El entorno de pruebas se declara ANTES de importar la aplicación: la
# configuración valida el ambiente al construirse (ISO/IEC 27001 A.8.9).
os.environ["ENVIRONMENT"] = "testing"
os.environ.setdefault("SECRET_KEY", "clave-de-pruebas-iso29119-no-usar-en-produccion-0001")
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["BCRYPT_ROUNDS"] = "4"          # reduce el tiempo de la suite
os.environ["LOG_LEVEL"] = "CRITICAL"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import database as database_module  # noqa: E402
from src.atenciones.models import Atencion  # noqa: E402
from src.auditoria.models import AuditoriaLog  # noqa: E402
from src.auth.models import RolUsuario, Usuario  # noqa: E402
from src.auth.security import hashear_password  # noqa: E402
from src.citas.models import Cita  # noqa: E402
from src.config import settings  # noqa: E402
from src.main import app  # noqa: E402
from src.pacientes.models import Paciente  # noqa: E402

CONTRASENA_PRUEBA = "Prueba#Segura2026"

# Secretos TOTP de las cuentas del catálogo de pruebas: permiten a los helpers
# completar el segundo factor obligatorio del rol administrativo (A07) sin
# repartir el secreto en cada caso de prueba. Se limpia en cada `datos`.
SECRETOS_MFA: dict[str, str] = {}


# ── Base de datos aislada por prueba ─────────────────────────────────────────
@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    database_module.Base.metadata.create_all(bind=engine)

    sesion = TestingSession()

    # Los routers dependen de `get_db`; FastAPI solo trata la dependencia como
    # generador si la propia función lo es (ISO/IEC 29119 §5.2.2 aislamiento).
    def _get_db():
        yield sesion

    app.dependency_overrides[database_module.get_db] = _get_db
    try:
        yield sesion
    finally:
        app.dependency_overrides.clear()
        sesion.close()
        engine.dispose()


@pytest.fixture
def datos(db_session):
    """Catálogo base: un usuario por rol y dos pacientes."""
    from datetime import date

    from src.auth.mfa import generar_secreto

    SECRETOS_MFA.clear()
    usuarios = {}
    for nombre, email, rol, contrasena in [
        ("Admin Demo", "admin@test.pe", RolUsuario.admin, "AdminDemo#2026"),
        ("Medico Demo", "medico@test.pe", RolUsuario.medico, "MedicoDemo#2026"),
        ("Recepcion Demo", "recepcion@test.pe", RolUsuario.recepcionista, "RecepcionDemo#2026"),
    ]:
        # A07 — toda cuenta administrativa nace con segundo factor activo.
        secreto = generar_secreto() if rol == RolUsuario.admin else None
        u = Usuario(
            nombre=nombre,
            email=email,
            password_hash=hashear_password(contrasena),
            rol=rol,
            activo=True,
            debe_cambiar_contrasena=False,
            mfa_secreto=secreto,
            mfa_habilitado=bool(secreto),
        )
        db_session.add(u)
        usuarios[rol.value] = u
        if secreto:
            SECRETOS_MFA[email] = secreto

    p1 = Paciente(nombres="María Elena", apellidos="García López", dni="11111111",
                  fecha_nacimiento=date(1985, 3, 15), telefono="987654321")
    p2 = Paciente(nombres="Juan Carlos", apellidos="Pérez Torres", dni="22222222",
                  fecha_nacimiento=date(1990, 7, 22), telefono="912345678")
    db_session.add_all([p1, p2])
    db_session.commit()
    db_session.refresh(p1)
    db_session.refresh(p2)
    return {"usuarios": usuarios, "pacientes": [p1, p2]}


@pytest.fixture
def cliente(db_session):
    return TestClient(app, raise_server_exceptions=False)


# ── Helpers de autenticación ─────────────────────────────────────────────────
def _autenticar(cliente, email, contrasena):
    """Login completo. Si el servidor exige el segundo factor (A07) canjea el
    desafío con el secreto TOTP registrado por el catálogo de pruebas."""
    r = cliente.post("/api/auth/login", json={"email": email, "password": contrasena})
    assert r.status_code == 200, f"login falló: {r.status_code} {r.text}"
    cuerpo = r.json()
    if not cuerpo.get("mfa_requerido"):
        return {"Authorization": f"Bearer {cuerpo['access_token']}"}

    secreto = SECRETOS_MFA.get(email.lower())
    assert secreto, f"{email} exige MFA y su secreto no está en SECRETOS_MFA"
    import pyotp

    verificacion = cliente.post("/api/auth/mfa/verificar", json={
        "mfa_token": cuerpo["mfa_token"],
        "codigo": pyotp.TOTP(secreto).now(),
    })
    assert verificacion.status_code == 200, (
        f"verificación MFA falló: {verificacion.status_code} {verificacion.text}"
    )
    return {"Authorization": f"Bearer {verificacion.json()['access_token']}"}


@pytest.fixture
def admin(cliente, datos):
    return _autenticar(cliente, "admin@test.pe", "AdminDemo#2026")


@pytest.fixture
def medico(cliente, datos):
    return _autenticar(cliente, "medico@test.pe", "MedicoDemo#2026")


@pytest.fixture
def recepcionista(cliente, datos):
    return _autenticar(cliente, "recepcion@test.pe", "RecepcionDemo#2026")


@pytest.fixture
def nuevo_paciente():
    """Datos válidos mínimos para crear un paciente (CP-PAC-001)."""
    return {
        "nombres": "Pedro Luis",
        "apellidos": "Quispe Cóndor",
        "dni": "33333333",
        "fecha_nacimiento": "2001-05-30",
        "telefono": "944332211",
        "direccion": "Jr. Lima 123, Huancayo",
        "email": "pedro.quispe@email.com",
    }
