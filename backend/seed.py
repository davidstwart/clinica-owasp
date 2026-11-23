"""
Carga de datos inicial — ISO/IEC 9001 §8.5.1 (información documentada).

Es **idempotente**: puede ejecutarse varias veces sin duplicar registros.
Uso:
    python seed.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import date, datetime, timedelta

from src.atenciones.models import Atencion
from src.auth.mfa import generar_secreto, uri_autenticador
from src.auth.models import RolUsuario, Usuario
from src.auth.policy import evaluar_contrasena
from src.auth.security import hashear_password
from src.auditoria.models import AuditoriaLog
from src.citas.models import Cita, EstadoCita
from src.common.time_utils import utcnow
from src.config import settings
from src.database import Base, SessionLocal, asegurar_esquema, engine
from src.pacientes.models import Paciente

Base.metadata.create_all(bind=engine)
asegurar_esquema()
db = SessionLocal()

# ── Usuarios ──────────────────────────────────────────────────────────────────
# Contraseñas de demostración. Todas cumplen la política de A.5.17 y se marcan
# con `debe_cambiar_contrasena=True`: el usuario debe rotarlas al primer acceso.
USUARIOS_DEMO = [
    {"nombre": "Administrador Sistema", "email": "admin@clinica.pe",
     "password": "Huancayo#Root2026", "rol": RolUsuario.admin},
    {"nombre": "Dr. Carlos Mendoza Rios", "email": "medico@clinica.pe",
     "password": "Huancayo#Dr2026", "rol": RolUsuario.medico},
    {"nombre": "Ana Torres Recepcion", "email": "recep@clinica.pe",
     "password": "Huancayo#Agenda2026", "rol": RolUsuario.recepcionista},
]

print("=" * 62)
print("  CARGA DE DATOS INICIALES — SISTEMA CLÍNICA ISO")
print("=" * 62)

for datos in USUARIOS_DEMO:
    fallos = evaluar_contrasena(datos["password"], datos["email"])
    if fallos:
        print(f"  ✗ Contraseña de demo inválida para {datos['email']}: {fallos}")
        sys.exit(1)

    existente = db.query(Usuario).filter(Usuario.email == datos["email"]).first()
    if existente:
        print(f"  • Ya existe: {datos['email']}")
        # A07 — una cuenta administrativa heredada todavía sin TOTP recibe su
        # secreto aquí (una sola vez) y pasa a exigir el segundo factor.
        if existente.rol == RolUsuario.admin and not existente.mfa_secreto:
            secreto = generar_secreto()
            existente.mfa_secreto = secreto
            existente.mfa_habilitado = True
            db.commit()
            print("    → MFA (TOTP) generado — regístrelo en su autenticador AHORA:")
            print(f"       clave: {secreto}")
            print(f"       URI:   {uri_autenticador(secreto, existente.email)}")
        elif existente.rol == RolUsuario.admin:
            print("       (MFA TOTP ya configurado; el secreto no vuelve a mostrarse)")
        continue

    # A07 — el administrador nace con TOTP activo; el secreto se muestra aquí
    # por única vez (queda cifrado con AES-256-GCM desde su alta).
    secreto_mfa = generar_secreto() if datos["rol"] == RolUsuario.admin else None

    nuevo = Usuario(
        nombre=datos["nombre"],
        email=datos["email"],
        password_hash=hashear_password(datos["password"]),
        rol=datos["rol"],
        debe_cambiar_contrasena=True,
        password_actualizada_en=utcnow(),
        mfa_secreto=secreto_mfa,
        mfa_habilitado=bool(secreto_mfa),
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    print(f"  ✓ Usuario creado: {nuevo.email} [{nuevo.rol.value}]")
    if secreto_mfa:
        print("    → Segundo factor (TOTP) — regístrelo en su autenticador AHORA:")
        print(f"       clave: {secreto_mfa}")
        print(f"       URI:   {uri_autenticador(secreto_mfa, nuevo.email)}")

# ── Pacientes ─────────────────────────────────────────────────────────────────
PACIENTES = [
    {"nombres": "María Elena", "apellidos": "García López", "dni": "12345678",
     "fecha_nacimiento": date(1985, 3, 15), "telefono": "987654321",
     "direccion": "Av. Giráldez 234, Huancayo", "email": "maria.garcia@email.com"},
    {"nombres": "Juan Carlos", "apellidos": "Pérez Torres", "dni": "87654321",
     "fecha_nacimiento": date(1990, 7, 22), "telefono": "912345678",
     "direccion": "Jr. Cusco 456, Huancayo", "email": "juan.perez@email.com"},
    {"nombres": "Rosa Amelia", "apellidos": "Huanca Mamani", "dni": "45678912",
     "fecha_nacimiento": date(1978, 11, 8), "telefono": "998877665",
     "direccion": "Av. Ferrocarril 789, Huancayo", "email": None},
    {"nombres": "Pedro Luis", "apellidos": "Quispe Cóndor", "dni": "32165498",
     "fecha_nacimiento": date(2001, 5, 30), "telefono": "944332211",
     "direccion": "Jr. Lima 123, Huancayo", "email": "pedro.quispe@email.com"},
]

for datos in PACIENTES:
    if db.query(Paciente).filter(Paciente.dni == datos["dni"]).first():
        print(f"  • Ya existe paciente DNI {datos['dni']}")
        continue
    paciente = Paciente(**datos)
    db.add(paciente)
    db.commit()
    db.refresh(paciente)
    db.add(AuditoriaLog(
        usuario_id=None, accion="SEED_PACIENTE", nivel="INFO",
        tabla_afectada="pacientes", registro_id=paciente.id,
        detalle="carga inicial",
    ))
    db.commit()
    print(f"  ✓ Paciente: {paciente.nombres} {paciente.apellidos} — DNI {paciente.dni}")

# ── Citas ─────────────────────────────────────────────────────────────────────
medico = db.query(Usuario).filter(Usuario.rol == RolUsuario.medico).first()
pacientes = db.query(Paciente).order_by(Paciente.id).all()
cita_ejemplo = None

if medico and len(pacientes) >= 3:
    manana = (utcnow() + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
    CITAS = [
        {"paciente": pacientes[0], "hora": manana, "motivo": "Control general y chequeo preventivo",
         "estado": EstadoCita.confirmada},
        {"paciente": pacientes[1], "hora": manana + timedelta(minutes=60),
         "motivo": "Dolor de cabeza persistente", "estado": EstadoCita.pendiente},
        {"paciente": pacientes[2], "hora": manana - timedelta(hours=2),
         "motivo": "Seguimiento de presión arterial", "estado": EstadoCita.atendida},
    ]
    for item in CITAS:
        existe = db.query(Cita).filter(
            Cita.paciente_id == item["paciente"].id,
            Cita.fecha_hora == item["hora"],
        ).first()
        if existe:
            print(f"  • Ya existe cita de {item['paciente'].id} a las {item['hora']:%H:%M}")
            if item["estado"] == EstadoCita.confirmada:
                cita_ejemplo = existe
            continue
        cita = Cita(
            paciente_id=item["paciente"].id, medico_id=medico.id,
            fecha_hora=item["hora"], motivo=item["motivo"], estado=item["estado"],
        )
        db.add(cita)
        db.commit()
        if item["estado"] == EstadoCita.confirmada:
            cita_ejemplo = cita
        print(f"  ✓ Cita: paciente #{item['paciente'].id} — {item['motivo'][:40]}")

# ── Atención de ejemplo (historia clínica) ────────────────────────────────────
# A.5.26 — no existen atenciones huérfanas: siempre cuelgan de una cita.
if medico and cita_ejemplo and not db.query(Atencion).first():
    db.add(Atencion(
        paciente_id=cita_ejemplo.paciente_id, medico_id=medico.id, cita_id=cita_ejemplo.id,
        diagnostico="Hipertensión arterial leve",
        tratamiento="Losartán 50 mg / día y control mensual de presión arterial",
        observaciones="Paciente refiere adherencia irregular. Reforzar educación Nutricional.",
    ))
    db.commit()
    print("  ✓ Atención clínica de ejemplo registrada")

db.close()

print("=" * 62)
print("  DATOS CARGADOS — SERVIDOR:")
print("    python -m uvicorn src.main:app --reload --port 8000")
print(f"  Documentación interactiva: http://localhost:8000/docs "
      f"({'habilitada' if settings.HABILITAR_DOCS else 'deshabilitada'})")
print("=" * 62)
print("  CREDENCIALES DE DEMOSTRACIÓN (requieren cambio en el primer acceso):")
for datos in USUARIOS_DEMO:
    print(f"    {datos['rol'].value:14s} {datos['email']:20s} {datos['password']}")
print("=" * 62)
