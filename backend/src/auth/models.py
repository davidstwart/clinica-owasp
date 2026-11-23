import enum

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
from sqlalchemy.sql import func

from ..database import Base
from ..security.cifrado import TextoCifrado


class RolUsuario(str, enum.Enum):
    admin = "admin"
    medico = "medico"
    recepcionista = "recepcionista"


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    rol = Column(Enum(RolUsuario), default=RolUsuario.recepcionista, nullable=False)
    activo = Column(Boolean, default=True, nullable=False)

    # OWASP A07 — bloqueo por intentos fallidos
    intentos_fallidos = Column(Integer, default=0, nullable=False)
    bloqueado_hasta = Column(DateTime, nullable=True)

    # ISO/IEC 27001 A.5.17 — gestión de la información de autenticación
    debe_cambiar_contrasena = Column(Boolean, default=False, nullable=False)
    password_actualizada_en = Column(DateTime, nullable=True)
    ultimo_acceso = Column(DateTime, nullable=True)

    # ISO/IEC 27001 A.5.25 / A.8.5 — revocación de sesiones
    token_version = Column(Integer, default=0, nullable=False)

    # OWASP A07 — segundo factor (TOTP) cifrado en reposo con AES-256-GCM
    mfa_secreto = Column(TextoCifrado, nullable=True)
    mfa_habilitado = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
