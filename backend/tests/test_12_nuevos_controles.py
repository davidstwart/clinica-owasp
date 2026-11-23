"""
Pruebas de los controles añadidos en la revisión de brechas — ISO/IEC 29119-2
nivel sistema · ISO/IEC 27001 A.5.15, A.5.17, A.8.15, A.8.16, A.8.24.

Cubren: segundo factor TOTP (A07), aprobación de accesos, alertas automáticas
de monitoreo, cifrado en reposo, filtro de agenda por día, reportes gerenciales
y forzado de HTTPS (A.8.24).

Casos: CP-MFA-001 … CP-TLS-002
"""
import hashlib

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]


# ── Segundo factor (TOTP) ────────────────────────────────────────────────────
def test_CP_MFA_001_alta_de_admin_entrega_el_secreto_una_sola_vez(cliente, admin):
    """A07 — el secreto TOTP se devuelve solo en el alta y nunca en lectura."""
    r = cliente.post("/api/auth/usuarios", headers=admin, json={
        "nombre": "Admin Nuevo", "email": "admin.nuevo@clinica.pe",
        "password": "Huancayo#Root2026", "rol": "admin",
    })
    assert r.status_code == 201
    secreto = r.json()["mfa_secreto"]
    assert secreto and len(secreto) >= 16

    # En la lista de usuarios el secreto jamás aparece.
    lista = cliente.get("/api/auth/usuarios", headers=admin)
    assert "mfa_secreto" not in lista.text
    assert all("mfa_secreto" not in u for u in lista.json())


def test_CP_MFA_002_alta_de_admin_requiere_el_codigo_en_el_primer_acceso(cliente, admin):
    """A07 — el secreto entregado en el alta habilita el desafío inmediato."""
    import pyotp

    secreto = cliente.post("/api/auth/usuarios", headers=admin, json={
        "nombre": "Admin Operativo", "email": "admin.operativo@clinica.pe",
        "password": "Huancayo#Root2026", "rol": "admin",
    }).json()["mfa_secreto"]

    login = cliente.post("/api/auth/login", json={
        "email": "admin.operativo@clinica.pe", "password": "Huancayo#Root2026",
    }).json()
    assert login["mfa_requerido"] is True
    assert login["mfa_pendiente"] is False
    assert login["access_token"] is None

    # Código incorrecto: no hay sesión.
    assert cliente.post("/api/auth/mfa/verificar", json={
        "mfa_token": login["mfa_token"], "codigo": "000000",
    }).status_code == 401

    verificacion = cliente.post("/api/auth/mfa/verificar", json={
        "mfa_token": login["mfa_token"], "codigo": pyotp.TOTP(secreto).now(),
    })
    assert verificacion.status_code == 200
    assert len(verificacion.json()["access_token"].split(".")) == 3


def test_CP_MFA_002b_cuenta_sin_secreto_configura_y_activa_el_mfa(cliente, datos, db_session):
    """A07 — cuenta administrativa heredada (sin TOTP): flujo de alta pendiente."""
    import pyotp

    admin_legacy = datos["usuarios"]["admin"]
    admin_legacy.mfa_secreto = None
    admin_legacy.mfa_habilitado = False
    db_session.commit()

    login = cliente.post("/api/auth/login", json={
        "email": "admin@test.pe", "password": "AdminDemo#2026",
    }).json()
    assert login["mfa_requerido"] is True
    assert login["mfa_pendiente"] is True
    assert login["access_token"] is None

    configurado = cliente.post("/api/auth/mfa/configurar", json={
        "mfa_token": login["mfa_token"],
    })
    assert configurado.status_code == 200
    clave = configurado.json()["clave"]

    codigo = pyotp.TOTP(clave).now()
    activado = cliente.post("/api/auth/mfa/activar", json={
        "mfa_token": login["mfa_token"], "codigo": codigo,
    })
    assert activado.status_code == 200
    assert activado.json()["mfa_habilitado"] is True

    verificacion = cliente.post("/api/auth/mfa/verificar", json={
        "mfa_token": login["mfa_token"], "codigo": codigo,
    })
    assert verificacion.status_code == 200
    assert len(verificacion.json()["access_token"].split(".")) == 3


def test_CP_MFA_003_el_secreto_no_se_almacena_en_claro(cliente, admin, db_session):
    """A.8.24 — el secreto TOTP se persiste cifrado con AES-256-GCM."""
    from sqlalchemy import text

    from src.security.cifrado import es_cifrado

    cliente.post("/api/auth/usuarios", headers=admin, json={
        "nombre": "Admin Cifrado", "email": "admin.cifrado@clinica.pe",
        "password": "Huancayo#Root2026", "rol": "admin",
    })
    bruto = db_session.execute(
        text("SELECT mfa_secreto FROM usuarios WHERE email = :email"),
        {"email": "admin.cifrado@clinica.pe"},
    ).scalar_one()
    assert es_cifrado(bruto)


def test_CP_MFA_004_el_desafio_no_es_un_token_de_sesion(cliente, admin):
    """A07 — el JWT del desafío lleva `prop=mfa` y se rechaza como sesión."""
    login = cliente.post("/api/auth/login", json={
        "email": "admin@test.pe", "password": "AdminDemo#2026",
    }).json()
    cabeceras = {"Authorization": f"Bearer {login['mfa_token']}"}
    assert cliente.get("/api/auth/me", headers=cabeceras).status_code == 401


# ── Aprobación de accesos (A.5.15) ──────────────────────────────────────────
def test_CP_ACC_001_cuenta_pendiente_se_aprueba(cliente, admin):
    alta = cliente.post("/api/auth/usuarios", headers=admin, json={
        "nombre": "Cuenta Pendiente", "email": "pendiente@clinica.pe",
        "password": "Huancayo#Med2026", "rol": "recepcionista", "activo": False,
    }).json()
    assert alta["activo"] is False

    # Sin aprobar no puede operar.
    r = cliente.post("/api/auth/login", json={
        "email": alta["email"], "password": "Huancayo#Med2026",
    })
    assert r.status_code == 403

    aprobado = cliente.post(f"/api/auth/usuarios/{alta['id']}/aprobar", headers=admin)
    assert aprobado.status_code == 200
    assert aprobado.json()["activo"] is True
    assert aprobado.json()["aprobado_por"] >= 1

    assert cliente.post("/api/auth/login", json={
        "email": alta["email"], "password": "Huancayo#Med2026",
    }).status_code == 200

    # Doble aprobación es un error de negocio, no un silencio.
    assert cliente.post(
        f"/api/auth/usuarios/{alta['id']}/aprobar", headers=admin
    ).status_code == 400


def test_CP_ACC_002_solo_el_admin_aprueba(cliente, medico, recepcionista):
    assert cliente.post("/api/auth/usuarios/1/aprobar", headers=medico).status_code == 403
    assert cliente.post("/api/auth/usuarios/1/aprobar", headers=recepcionista).status_code == 403


# ── Alertas de monitoreo (A.8.16) ────────────────────────────────────────────
def test_CP_MON_001_intrusion_genera_alerta_critica(cliente, datos, db_session):
    """Cinco fallos desde la misma IP levantan ALERTA_INTENTOS_INTRUSION."""
    from src.auditoria.models import AuditoriaLog

    for _ in range(5):
        cliente.post("/api/auth/login", json={
            "email": "medico@test.pe", "password": "Incorrecta#2026",
        })

    alerta = db_session.query(AuditoriaLog).filter(
        AuditoriaLog.accion == "ALERTA_INTENTOS_INTRUSION"
    ).first()
    assert alerta is not None
    assert alerta.nivel == "CRITICAL"
    assert "ip=testclient" in alerta.detalle


def test_CP_MON_002_el_panel_de_alertas_es_de_solo_admin(cliente, admin, medico, datos, db_session):
    from src.auditoria.models import AuditoriaLog

    for _ in range(5):
        cliente.post("/api/auth/login", json={
            "email": "recepcion@test.pe", "password": "Incorrecta#2026",
        })
    assert db_session.query(AuditoriaLog).filter(
        AuditoriaLog.accion.like("ALERTA_%")
    ).count() >= 1

    assert cliente.get("/api/auditoria/alertas", headers=medico).status_code == 403
    r = cliente.get("/api/auditoria/alertas", headers=admin)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    assert all(a["accion"].startswith("ALERTA_") for a in r.json()["resultados"])
    assert all(a["nivel"] == "CRITICAL" for a in r.json()["resultados"])


def test_CP_MON_003_una_rafaga_no_satura_el_registro(cliente, datos, db_session):
    """La alerta se emite una sola vez por ventana: deduplicado."""
    from src.auditoria.models import AuditoriaLog

    for _ in range(12):
        cliente.post("/api/auth/login", json={
            "email": "medico@test.pe", "password": "Incorrecta#2026",
        })

    intrusion = db_session.query(AuditoriaLog).filter(
        AuditoriaLog.accion == "ALERTA_INTENTOS_INTRUSION"
    ).count()
    assert intrusion == 1


# ── Cifrado en reposo (A.8.24) ──────────────────────────────────────────────
def test_CP_CIF_001_los_datos_clinicos_se_cifran_en_la_base(cliente, admin, medico, datos, db_session):
    from sqlalchemy import text

    from src.security.cifrado import es_cifrado

    objetivo = datos["pacientes"][0]
    cita = cliente.post("/api/citas/", headers=admin, json={
        "paciente_id": objetivo.id, "medico_id": datos["usuarios"]["medico"].id,
        "fecha_hora": "2099-09-09T09:00:00", "motivo": "Cifrado en reposo",
    }).json()
    cliente.post("/api/atenciones/", headers=medico, json={
        "paciente_id": objetivo.id, "cita_id": cita["id"],
        "diagnostico": "Diagnostico sensible", "tratamiento": "Tratamiento sensible",
    })

    diagnostico_bruto = db_session.execute(
        text("SELECT diagnostico FROM atenciones ORDER BY id DESC LIMIT 1")
    ).scalar_one()
    assert es_cifrado(diagnostico_bruto)
    assert "Diagnostico sensible" not in diagnostico_bruto


def test_CP_CIF_002_la_direccion_del_paciente_se_cifra(cliente, admin, nuevo_paciente, db_session):
    from sqlalchemy import text

    from src.security.cifrado import es_cifrado

    creado = cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente).json()
    direccion_bruta = db_session.execute(
        text("SELECT direccion FROM pacientes WHERE id = :id"), {"id": creado["id"]}
    ).scalar_one()
    assert es_cifrado(direccion_bruta)
    assert nuevo_paciente["direccion"] not in direccion_bruta


def test_CP_CIF_003_lectura_transparente_para_la_aplicacion(cliente, admin, nuevo_paciente):
    """La API devuelve el dato en claro aunque esté cifrado en la base."""
    creado = cliente.post("/api/pacientes/", headers=admin, json=nuevo_paciente).json()
    assert creado["direccion"] == nuevo_paciente["direccion"]


# ── Agenda: filtro por día ───────────────────────────────────────────────────
def test_CP_CIT_001_filtro_de_agenda_por_fecha(cliente, admin, datos):
    """A.8.26 — la vista de agenda se acota a un día concreto."""
    del_1 = "2099-03-03T10:00:00"
    del_2 = "2099-04-04T11:00:00"
    for marca, motivo in ((del_1, "Cita del día 3"), (del_2, "Cita del día 4")):
        assert cliente.post("/api/citas/", headers=admin, json={
            "paciente_id": datos["pacientes"][0].id,
            "medico_id": datos["usuarios"]["medico"].id,
            "fecha_hora": marca, "motivo": motivo,
        }).status_code == 201

    r = cliente.get("/api/citas/?fecha=2099-03-03", headers=admin)
    assert r.status_code == 200
    motivos = [c["motivo"] for c in r.json()]
    assert "Cita del día 3" in motivos
    assert "Cita del día 4" not in motivos

    assert cliente.get("/api/citas/?fecha=2099-12-31", headers=admin).json() == []


# ── Reportes gerenciales (A.5.34) ───────────────────────────────────────────
def test_CP_REP_001_resumen_solo_admin(cliente, admin, medico):
    assert cliente.get("/api/reportes/resumen", headers=medico).status_code == 403
    r = cliente.get("/api/reportes/resumen", headers=admin)
    assert r.status_code == 200
    cuerpo = r.json()
    for clave in ("generado_en", "pacientes", "citas", "atenciones", "usuarios", "auditoria_24h"):
        assert clave in cuerpo
    assert cuerpo["pacientes"]["total"] >= 1
    assert cuerpo["usuarios"]["total"] >= 3


def test_CP_REP_002_validar_sella_el_reporte(cliente, admin, db_session):
    """A.8.15 — la validación deja un sello SHA-256 auditable."""
    from src.auditoria.models import AuditoriaLog

    reporte = {"tipo": "resumen", "periodo": "2026-10", "pacientes": 4}
    r = cliente.post("/api/reportes/validar", headers=admin, json={"reporte": reporte})
    assert r.status_code == 201
    cuerpo = r.json()
    esperado = hashlib.sha256(
        '{"pacientes":4,"periodo":"2026-10","tipo":"resumen"}'.encode()
    ).hexdigest()
    assert cuerpo["hash_sha256"] == esperado

    evento = db_session.query(AuditoriaLog).filter(
        AuditoriaLog.accion == "VALIDAR_REPORTE"
    ).first()
    assert evento is not None
    assert esperado in evento.detalle


def test_CP_REP_003_reporte_vacio_o_no_admin_se_rechaza(cliente, admin, medico):
    assert cliente.post(
        "/api/reportes/validar", headers=medico, json={"reporte": {"a": 1}}
    ).status_code == 403
    assert cliente.post(
        "/api/reportes/validar", headers=admin, json={"reporte": {}}
    ).status_code == 422


# ── Forzado de HTTPS (A.8.24) ───────────────────────────────────────────────
@pytest.mark.parametrize(
    "esquema,forwarded,forzar,esperado",
    [
        ("http", None, True, True),
        ("http", "https", True, False),        # proxy TLS delante del servicio
        ("https", "https, http", True, False),  # gana el primer valor (origen)
        ("http", "http, https", True, True),
        ("https", None, True, False),
        ("http", None, False, False),          # fuera de producción
        (None, None, True, True),
    ],
)
def test_CP_TLS_001_logica_de_redireccion(esquema, forwarded, forzar, esperado):
    from src.middleware.tls_redirect import debe_redireccionar

    assert debe_redireccionar(esquema, forwarded, forzar) is esperado


def test_CP_TLS_002_en_produccion_redirige_a_https(cliente, monkeypatch):
    """El middleware devuelve 308 con el esquema https cuando corresponde."""
    from src.config import settings

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    r = cliente.get("/health", follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"].startswith("https://")


# ── RBAC de pacientes (A.5.15) ──────────────────────────────────────────────
def test_CP_PAC_001_el_medico_consulta_pero_no_edita(cliente, medico, datos):
    objetivo = datos["pacientes"][0]
    assert cliente.get("/api/pacientes/", headers=medico).status_code == 200

    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=medico, json={
        "nombres": "Intento", "apellidos": "Editado", "dni": objetivo.dni,
    })
    assert r.status_code == 403

    r = cliente.post("/api/pacientes/", headers=medico, json={
        "nombres": "Nuevo", "apellidos": "Paciente", "dni": "77112233",
    })
    assert r.status_code == 403


def test_CP_PAC_002_la_recepcion_si_edita(cliente, recepcionista, datos):
    objetivo = datos["pacientes"][0]
    r = cliente.put(f"/api/pacientes/{objetivo.id}", headers=recepcionista, json={
        "nombres": objetivo.nombres, "apellidos": objetivo.apellidos,
        "dni": objetivo.dni, "telefono": "911111111",
    })
    assert r.status_code == 200
    assert r.json()["telefono"] == "911111111"
