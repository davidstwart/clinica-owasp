"""
ISO/IEC 27001:2022 — A.8.5 Autenticación segura / A.8.24 Uso de la criptografía
ISO/IEC 25010:2023 — Seguridad (característica de calidad)

Controles:
  A01 Broken Access Control → control de acceso por roles (RBAC)
  A02 Cryptographic Failures → bcrypt con coste configurable + JWT firmado
  A07 Identification and Authentication Failures → bloqueo de cuenta,
       rotación obligatoria de contraseña, tokens revocables

Medidas adicionales de A07:
  · Verificación de `iss` y `aud` en el token (previene reutilización de token
    emitido para otro sistema).
  · `jti` + `ver` (versión de token) → revocación inmediata al cerrar sesión o
    al cambiar la contraseña.
  · Hash señuelo (dummy hash) cuando el usuario no existe → el tiempo de
    respuesta no revela qué correos están registrados (anti-enumeración).
"""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from ..auditoria.service import registrar_log
from ..config import settings
from ..database import get_db
from ..middleware.request_context import obtener_request_id
from .models import RolUsuario, Usuario

logger = logging.getLogger("clinica.auth")

# OWASP A02 / A07 — bcrypt para contraseñas (coste ajustable desde configuración)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=settings.BCRYPT_ROUNDS)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
# Variante sin error automático: permite endpoints que aceptan también el
# token de desafío MFA en el cuerpo (flujo de configuración del segundo factor).
oauth2_opcional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

MAX_INTENTOS = settings.MAX_INTENTOS_LOGIN
BLOQUEO_MINUTOS = settings.BLOQUEO_MINUTOS

# Hash señuelo: coste equivalente al de un usuario real. Permite que el tiempo
# de respuesta de un login con correo inexistente sea similar al de uno válido.
_HASH_SENUELO = pwd_context.hash("clave-senuelo-sin-usuario-000000000000")
CABECERA_CAMBIO_CONTRASENA = "X-Auth-Error-Code"


# ── Contraseñas ───────────────────────────────────────────────────────────────
def verificar_password(plano: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plano, hashed)
    except ValueError:
        # bcrypt no puede verificar hashes malformados: se trata como fallido.
        logger.warning("Hash de contraseña con formato inesperado")
        return False


def hashear_password(password: str) -> str:
    return pwd_context.hash(password)


def verificar_password_sin_usuario(plano: str) -> None:
    """Consume tiempo equivalente a una verificación real (anti-enumeración)."""
    pwd_context.verify(plano, _HASH_SENUELO)


# ── Tokens ───────────────────────────────────────────────────────────────────
def _cargas_base(usuario: Usuario) -> dict:
    ahora = datetime.now(timezone.utc)
    return {
        "sub": usuario.email,
        "rol": usuario.rol.value if hasattr(usuario.rol, "value") else usuario.rol,
        "ver": usuario.token_version,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": uuid4().hex,
        "iat": ahora,
        "nbf": ahora,
        "exp": ahora + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }


def crear_token(usuario: Usuario) -> str:
    return jwt.encode(_cargas_base(usuario), settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def crear_token_mfa(usuario: Usuario) -> str:
    """Token de desafío MFA: vida corta (5 min) y marca `prop=mfa` para que no
    pueda usarse como token de sesión en el resto de la API."""
    cargas = _cargas_base(usuario)
    cargas["prop"] = "mfa"
    cargas["exp"] = datetime.now(timezone.utc) + timedelta(
        minutes=settings.MFA_TOKEN_EXPIRE_MINUTES
    )
    return jwt.encode(cargas, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decodificar_token(token: str) -> dict:
    """Verifica firma, algoritmo, emisor, audiencia y vigencia."""
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        options={"require_exp": True, "require_iat": True, "require_sub": True},
    )


def revocar_tokens(usuario: Usuario) -> None:
    """Invalida todos los tokens emitidos previamente al usuario."""
    usuario.token_version = (usuario.token_version or 0) + 1


def generar_codigo_unico() -> str:
    return secrets.token_hex(16)


# ── Dependencias de autenticación ────────────────────────────────────────────
def _401() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales o token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def usuario_desde_token(token: str, db: Session) -> Usuario:
    """Valida un token de sesión (A07) y devuelve el usuario activo asociado."""
    try:
        payload = decodificar_token(token)
    except JWTError as exc:
        logger.info("Token rechazado: %s", type(exc).__name__)
        raise _401()

    # Un token de desafío MFA no es un token de sesión.
    if payload.get("prop") == "mfa":
        logger.info("Token MFA usado como token de sesión")
        raise _401()

    email = payload.get("sub")
    version = payload.get("ver", 0)
    if not email or not isinstance(email, str):
        raise _401()

    usuario = db.query(Usuario).filter(Usuario.email == email).first()
    if not usuario or not usuario.activo:
        raise _401()

    # Token emitido antes del último cierre de sesión / cambio de contraseña.
    if version != usuario.token_version:
        logger.info("Token revocado para usuario_id=%s", usuario.id)
        raise _401()

    return usuario


def usuario_desde_token_mfa(token_mfa: str, db: Session) -> Usuario:
    """Valida el token de desafío MFA de corta vida."""
    try:
        payload = decodificar_token(token_mfa)
    except JWTError as exc:
        logger.info("Token MFA rechazado: %s", type(exc).__name__)
        raise _401()

    if payload.get("prop") != "mfa":
        raise _401()

    email = payload.get("sub")
    if not email or not isinstance(email, str):
        raise _401()

    usuario = db.query(Usuario).filter(Usuario.email == email).first()
    if not usuario or not usuario.activo:
        raise _401()
    if payload.get("ver", 0) != usuario.token_version:
        raise _401()
    return usuario


def obtener_usuario_actual(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Usuario:
    """A07 — valida el token y devuelve el usuario asociado activo."""
    return usuario_desde_token(token, db)


def usuario_operativo(usuario: Usuario = Depends(obtener_usuario_actual)) -> Usuario:
    """
    A.5.17 — un usuario con contraseña inicial o caducada solo puede usar
    /api/auth/me, /api/auth/change-password y /api/auth/logout.
    """
    if usuario.debe_cambiar_contrasena and settings.EXIGIR_CAMBIO_CONTRASENA_INICIAL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Debe actualizar su contraseña antes de continuar",
            headers={CABECERA_CAMBIO_CONTRASENA: "DEBE_CAMBIAR_CONTRASENA"},
        )
    return usuario


# OWASP A01 — control de acceso por roles
def requerir_rol(*roles: RolUsuario):
    allowed = {r.value if hasattr(r, "value") else r for r in roles}

    def verificador(
        request: Request,
        usuario: Usuario = Depends(usuario_operativo),
        db: Session = Depends(get_db),
    ):
        rol = usuario.rol.value if hasattr(usuario.rol, "value") else usuario.rol
        if rol not in allowed:
            logger.info(
                "Acceso denegado usuario_id=%s rol=%s recurso_permitido=%s",
                usuario.id, rol, sorted(allowed),
            )
            # A.8.15 — la denegación de acceso es un evento de seguridad y queda
            # registrada en la auditoría (alimenta las alertas de intrusión).
            registrar_log(
                db, usuario.id, "ACCESO_DENEGADO", None, None, obtener_ip(request),
                detalle=f"{request.method} {request.url.path} rol={rol}",
                request_id=obtener_request_id(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permiso para realizar esta acción",
            )
        return usuario

    return verificador


def obtener_ip(request: Request) -> str:
    """IP del cliente normalizada y recortada (A.8.16)."""
    return (request.client.host if request.client else "desconocida")[:50]


def obtener_user_agent(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    return ua[:200] if ua else None
