"""Esquemas de entrada/salida de autenticación — ISO/IEC 29119 (contratos de prueba)."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from .models import RolUsuario
from .policy import evaluar_contrasena


class LoginRequest(BaseModel):
    """ISO 29119 — CP-AUT-001: entrada de login acotada."""

    email: EmailStr = Field(max_length=150)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """ISO/IEC 27001 A.5.17 — el cliente debe rotar la contraseña inicial.

    Cuando el segundo factor está pendiente, `access_token` llega vacío y el
    servidor devuelve `mfa_requerido` con un token de desafío de corta vida."""

    access_token: Optional[str] = None
    token_type: str = "bearer"
    id: int
    rol: str
    nombre: str
    email: str
    debe_cambiar_contrasena: bool = False
    expira_en_minutos: int
    mfa_requerido: bool = False
    mfa_pendiente: bool = False
    mfa_token: Optional[str] = None


class MfaVerificarRequest(BaseModel):
    """CP-AUT-MFA-002 — canje del código TOTP por el token de sesión."""

    mfa_token: str = Field(min_length=20, max_length=2000)
    codigo: str = Field(min_length=6, max_length=6)

    @field_validator("codigo")
    @classmethod
    def codigo_numerico(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit():
            raise ValueError("El código MFA debe contener solo dígitos")
        return v


class MfaConfiguracionRequest(BaseModel):
    """Generación/rotación del secreto TOTP.

    Se autentica con el token de sesión normal o, durante el alta pendiente de
    MFA, con el `mfa_token` del desafío."""

    mfa_token: Optional[str] = Field(default=None, max_length=2000)


class MfaActivarRequest(MfaConfiguracionRequest):
    """Confirma el secreto demostrando posesión con un código válido."""

    codigo: str = Field(min_length=6, max_length=6)

    @field_validator("codigo")
    @classmethod
    def codigo_numerico(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit():
            raise ValueError("El código MFA debe contener solo dígitos")
        return v


class MfaConfiguracionResponse(BaseModel):
    """El secreto se expone **solo** en esta respuesta (una sola vez)."""

    email: str
    clave: str
    otpauth_uri: str
    mfa_habilitado: bool


class AprobacionResponse(BaseModel):
    """A.5.15 — aprobación de accesos por el administrador."""

    id: int
    email: str
    activo: bool
    aprobado_por: int


class CambioPasswordRequest(BaseModel):
    """ISO 29119 — CP-AUT-006: cambio de contraseña con verificación de la actual."""

    password_actual: str = Field(min_length=1, max_length=128)
    password_nueva: str = Field(min_length=1, max_length=128)

    @field_validator("password_nueva")
    @classmethod
    def password_fuerte(cls, v):
        fallos = evaluar_contrasena(v)
        if fallos:
            raise ValueError("; ".join(fallos))
        return v


class UsuarioCreate(BaseModel):
    nombre: str = Field(min_length=3, max_length=100)
    email: EmailStr = Field(max_length=150)
    password: str = Field(min_length=1, max_length=128)
    rol: RolUsuario = RolUsuario.recepcionista
    debe_cambiar_contrasena: bool = True
    # A.5.15 — el alta puede quedar pendiente de aprobación por el administrador.
    activo: bool = True

    @field_validator("nombre")
    @classmethod
    def nombre_valido(cls, v):
        if not v.strip():
            raise ValueError("El nombre no puede estar vacío")
        return v.strip()

    # OWASP A07 / ISO 27001 A.5.17 — política de contraseña fuerte
    @field_validator("password")
    @classmethod
    def password_fuerte(cls, v, info):
        email = info.data.get("email")
        fallos = evaluar_contrasena(v, str(email) if email else None)
        if fallos:
            raise ValueError("; ".join(fallos))
        return v


class UsuarioResponse(BaseModel):
    id: int
    nombre: str
    email: str
    rol: RolUsuario
    activo: bool
    debe_cambiar_contrasena: bool = False
    mfa_habilitado: bool = False
    ultimo_acceso: Optional[datetime] = None

    class Config:
        from_attributes = True


class UsuarioCreateResponse(UsuarioResponse):
    """Alta de cuenta: incluye el secreto MFA **una sola vez** cuando el rol
    exige segundo factor (A07). Nunca vuelve a exponerse."""

    mfa_secreto: Optional[str] = None


class MedicoResponse(BaseModel):
    """A.5.15 — vista mínima del personal médico para agendar citas.

    Recepción y médicos necesitan elegir al profesional tratante, pero no
    deben acceder al padrón completo de cuentas (correos, estado de MFA,
    último acceso). Solo se exponen los campos imprescindibles."""

    id: int
    nombre: str

    class Config:
        from_attributes = True


class UsuarioUpdate(BaseModel):
    """
    ISO 29119 — CP-AUT-004: actualización parcial.
    Solo el administrador puede cambiar `rol` o `activo` (A.5.15).
    """

    nombre: Optional[str] = Field(default=None, min_length=3, max_length=100)
    email: Optional[EmailStr] = Field(default=None, max_length=150)
    rol: Optional[RolUsuario] = None
    activo: Optional[bool] = None
    password: Optional[str] = Field(default=None, max_length=128)
    # A.5.17 — recuperación de una cuenta administrativa que perdió su autenticador.
    reiniciar_mfa: Optional[bool] = None

    @field_validator("password")
    @classmethod
    def password_fuerte(cls, v):
        if v is None or v == "":
            return None
        fallos = evaluar_contrasena(v)
        if fallos:
            raise ValueError("; ".join(fallos))
        return v
