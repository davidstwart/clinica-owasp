"""
Pruebas de gestión de cuentas — A.01 (privilegio mínimo) · A.5.15.
ISO/IEC 27001:2022 · ISO/IEC 29119-2 nivel sistema

Cubre el ciclo de vida de las cuentas de usuario: alta, edición, baja,
restablecimiento de contraseña y control de las acciones críticas de un
administrador sobre las cuentas ajenas.

Casos: CP-USR-001 … CP-USR-014
"""
import pytest

pytestmark = pytest.mark.integration

ALTA = {
    "nombre": "Profesional Nuevo",
    "email": "profesional@clinica.pe",
    "password": "Huancayo#Med2026",
    "rol": "medico",
}


def test_CP_USR_001_alta_de_usuario_devuelve_201_y_exige_rotacion(cliente, admin):
    r = cliente.post("/api/auth/usuarios", headers=admin, json=ALTA)
    assert r.status_code == 201
    cuerpo = r.json()
    assert cuerpo["email"] == "profesional@clinica.pe"
    assert cuerpo["rol"] == "medico"
    # A.5.17 — toda cuenta nace con la contraseña pendiente de cambio.
    assert cuerpo["debe_cambiar_contrasena"] is True


def test_CP_USR_002_la_respuesta_nunca_expone_el_hash(cliente, admin):
    """A.5.17 / GDPR art. 32 — el hash nunca cruza el límite de la aplicación."""
    r = cliente.post("/api/auth/usuarios", headers=admin, json=ALTA)
    cuerpo = r.json()
    assert "password" not in cuerpo
    assert "password_hash" not in cuerpo
    assert "$2b$" not in r.text


def test_CP_USR_003_correo_duplicado_se_rechaza(cliente, admin, datos):
    r = cliente.post("/api/auth/usuarios", headers=admin, json={
        **ALTA, "email": datos["usuarios"]["medico"].email,
    })
    assert r.status_code == 400
    assert "registrado" in r.json()["detail"].lower()


def test_CP_USR_004_correo_no_valido_se_rechaza(cliente, admin):
    r = cliente.post("/api/auth/usuarios", headers=admin, json={**ALTA, "email": "no-es-correo"})
    assert r.status_code == 422


def test_CP_USR_005_contrasena_debil_se_rechaza(cliente, admin):
    r = cliente.post("/api/auth/usuarios", headers=admin, json={**ALTA, "password": "debil"})
    assert r.status_code == 422


def test_CP_USR_006_rol_desconocido_se_rechaza(cliente, admin):
    """A.5.15 — no se pueden crear cuentas con privilegios no previstos."""
    r = cliente.post("/api/auth/usuarios", headers=admin, json={**ALTA, "rol": "superusuario"})
    assert r.status_code == 422


def test_CP_USR_007_la_edicion_de_usuario_inexistente_devuelve_404(cliente, admin):
    r = cliente.put("/api/auth/usuarios/999999", headers=admin, json={"nombre": "Fantasma"})
    assert r.status_code == 404


def test_CP_USR_008_el_admin_no_puede_otorgarse_un_rol_inexistente(cliente, admin):
    """A.5.15 — la actualización de cuentas aplica la misma lista blanca de roles."""
    id_admin = cliente.get("/api/auth/me", headers=admin).json()["id"]
    r = cliente.put(f"/api/auth/usuarios/{id_admin}", headers=admin, json={"rol": "superusuario"})
    assert r.status_code == 422


def test_CP_USR_009_resetear_contrasena_inexige_rotacion_y_revoca_sesiones(cliente, admin, db_session, datos):
    """
    A.5.17 — el restablecimiento administrativo fuerza el cambio y invalida
    cualquier sesión que el usuario pudiera tener abierta.
    """
    from tests.conftest import _autenticar

    cabeceras_medico = _autenticar(cliente, "medico@test.pe", "MedicoDemo#2026")
    id_medico = datos["usuarios"]["medico"].id
    assert cliente.get("/api/auth/me", headers=cabeceras_medico).status_code == 200

    r = cliente.put(f"/api/auth/usuarios/{id_medico}", headers=admin,
                    json={"password": "Huancayo#Med2026"})
    assert r.status_code == 200
    assert r.json()["debe_cambiar_contrasena"] is True

    # La sesión previa queda revocada.
    assert cliente.get("/api/auth/me", headers=cabeceras_medico).status_code == 401


def test_CP_USR_010_no_se_puede_eliminar_la_propia_cuenta(cliente, admin):
    """A.5.15 — el administrador no puede quedarse sin acceso al sistema."""
    id_admin = cliente.get("/api/auth/me", headers=admin).json()["id"]
    r = cliente.delete(f"/api/auth/usuarios/{id_admin}", headers=admin)
    assert r.status_code == 400
    assert "propia cuenta" in r.json()["detail"].lower()


def test_CP_USR_011_no_se_puede_eliminar_un_usuario_con_historial_clinico(cliente, admin, medico, datos):
    """A.5.33 — las atenciones son irremplazables; se desactiva en su lugar."""
    objetivo = datos["pacientes"][0]
    id_medico = datos["usuarios"]["medico"].id
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": id_medico,
        "fecha_hora": "2099-10-10T09:00:00", "motivo": "Cita con historial",
    }).json()
    assert cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Dermatitis", "tratamiento": "Pomada",
    }).status_code == 201

    r = cliente.delete(f"/api/auth/usuarios/{id_medico}", headers=admin)
    assert r.status_code == 409
    assert "historial clínico" in r.json()["detail"].lower()


def test_CP_USR_012_usuario_sin_historial_se_puede_eliminar(cliente, admin, datos):
    nuevo = cliente.post("/api/auth/usuarios", headers=admin, json=ALTA).json()
    assert cliente.delete(f"/api/auth/usuarios/{nuevo['id']}", headers=admin).status_code == 204
    assert cliente.get("/api/auth/usuarios", headers=admin).status_code == 200


def test_CP_USR_013_usuario_eliminado_no_puede_autenticarse(cliente, admin, datos):
    """A.5.15 — la baja surte efecto inmediato."""
    nuevo = cliente.post("/api/auth/usuarios", headers=admin, json=ALTA).json()
    assert cliente.delete(f"/api/auth/usuarios/{nuevo['id']}", headers=admin).status_code == 204

    r = cliente.post("/api/auth/login",
                     json={"email": nuevo["email"], "password": "Huancayo#Med2026"})
    assert r.status_code == 401


def test_CP_USR_014_las_cuentas_nuevas_no_pueden_operar_sin_rotatear(cliente, admin):
    """A.5.17 — el flujo de alta exige la rotación antes de operar."""
    nuevo = cliente.post("/api/auth/usuarios", headers=admin, json=ALTA).json()
    cabeceras = {"Authorization": "Bearer " + _login(cliente, nuevo["email"], "Huancayo#Med2026")}

    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 200
    assert cliente.get("/api/pacientes/", headers=cabeceras).status_code == 403


def _login(cliente, email, contrasena) -> str:
    r = cliente.post("/api/auth/login", json={"email": email, "password": contrasena})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]