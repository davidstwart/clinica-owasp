"""
Autenticación — OWASP A01 / A02 / A07, ISO/IEC 27001 A.5.17 y A.8.5.

Pruebas asociadas: backend/tests/test_04_auth_api.py (ISO/IEC 29119)
"""
import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from ..atenciones.models import Atencion
from ..auditoria.service import registrar_log
from ..common.time_utils import utcnow
from ..config import settings
from ..database import get_db
from .mfa import generar_secreto, uri_autenticador, verificar_codigo
from .models import RolUsuario, Usuario
from .policy import evaluar_contrasena
from .schemas import (
    AprobacionResponse,
    CambioPasswordRequest,
    LoginRequest,
    MfaActivarRequest,
    MfaConfiguracionRequest,
    MfaConfiguracionResponse,
    MfaVerificarRequest,
    MedicoResponse,
    TokenResponse,
    UsuarioCreate,
    UsuarioCreateResponse,
    UsuarioResponse,
    UsuarioUpdate,
)
from .security import (
    BLOQUEO_MINUTOS,
    MAX_INTENTOS,
    crear_token,
    crear_token_mfa,
    hashear_password,
    obtener_ip,
    obtener_user_agent,
    obtener_usuario_actual,
    oauth2_opcional,
    requerir_rol,
    revocar_tokens,
    usuario_desde_token,
    usuario_desde_token_mfa,
    verificar_password,
    verificar_password_sin_usuario,
)

logger = logging.getLogger("clinica.auth")
router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

# A.8.6 — limitador dedicado al endpoint de login, por IP. `enabled` se toma de
# la configuración para que el entorno de pruebas pueda aislar el bloqueo de
# cuenta (A07) del límite de peticiones sin desactivar ninguno de los dos.
limiter = Limiter(key_func=get_remote_address, enabled=settings.RATE_LIMIT_ENABLED)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(request: Request, datos: LoginRequest, db: Session = Depends(get_db)):
    """
    A07 + A09 + A.8.6 — Inicio de sesión con límite de tasa por IP, bloqueo
    por intentos y registro de auditoría. Los mensajes de error son uniformes:
    no revelan si el correo existe (anti-enumeración).
    """
    ip = obtener_ip(request)
    email = str(datos.email).lower()
    usuario = db.query(Usuario).filter(Usuario.email == email).first()

    # ── Cuenta bloqueada temporalmente ────────────────────────────────────────
    if usuario and usuario.bloqueado_hasta and utcnow() < usuario.bloqueado_hasta:
        minutos = int((usuario.bloqueado_hasta - utcnow()).total_seconds() / 60) + 1
        registrar_log(
            db, usuario.id, "LOGIN_BLOQUEADO", "usuarios", usuario.id, ip,
            detalle=f"intento={email}", nivel="WARNING",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Cuenta bloqueada temporalmente. Intente en {minutos} minuto(s).",
        )

    # ── Verificación de credenciales ──────────────────────────────────────────
    if not usuario:
        # Se consume el mismo tiempo de CPU que con un usuario real.
        verificar_password_sin_usuario(datos.password)
        registrar_log(
            db, None, "LOGIN_FALLIDO", "usuarios", None, ip,
            detalle="correo_no_registrado", nivel="WARNING",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
        )

    if not verificar_password(datos.password, usuario.password_hash):
        usuario.intentos_fallidos = (usuario.intentos_fallidos or 0) + 1
        alcanzo_umbral = usuario.intentos_fallidos >= MAX_INTENTOS
        if alcanzo_umbral:
            usuario.bloqueado_hasta = utcnow() + timedelta(minutes=BLOQUEO_MINUTOS)
        db.commit()

        # A.8.16 — TODOS los intentos fallidos quedan registrados, incluido el
        # que dispara el bloqueo: sin él, la regla de alerta de intrusión no
        # alcanzaría su umbral justo en el intento decisivo.
        registrar_log(
            db, None, "LOGIN_FALLIDO", "usuarios", None, ip,
            detalle=f"intentos={usuario.intentos_fallidos}", nivel="WARNING",
        )

        if alcanzo_umbral:
            registrar_log(
                db, None, "LOGIN_CUENTA_BLOQUEADA", "usuarios", None, ip,
                detalle=f"intentos={usuario.intentos_fallidos}", nivel="SECURITY",
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Cuenta bloqueada por {MAX_INTENTOS} intentos fallidos. "
                    f"Intente en {BLOQUEO_MINUTOS} minutos."
                ),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos",
        )

    # ── Usuario inactivo ──────────────────────────────────────────────────────
    if not usuario.activo:
        registrar_log(
            db, usuario.id, "LOGIN_USUARIO_INACTIVO", "usuarios", usuario.id, ip, nivel="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo. Contacte al administrador.",
        )

    # ── Segundo factor (A07) — obligatorio para cuentas administrativas ──────
    if _exige_mfa(usuario):
        usuario.intentos_fallidos = 0
        usuario.bloqueado_hasta = None
        db.commit()
        return TokenResponse(
            id=usuario.id,
            rol=usuario.rol.value,
            nombre=usuario.nombre,
            email=usuario.email,
            debe_cambiar_contrasena=bool(usuario.debe_cambiar_contrasena),
            expira_en_minutos=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            mfa_requerido=True,
            mfa_pendiente=not bool(usuario.mfa_secreto),
            mfa_token=crear_token_mfa(usuario),
        )

    # ── Éxito ─────────────────────────────────────────────────────────────────
    usuario.intentos_fallidos = 0
    usuario.bloqueado_hasta = None
    usuario.ultimo_acceso = utcnow()
    db.commit()

    registrar_log(
        db, usuario.id, "LOGIN_EXITOSO", "usuarios", usuario.id, ip,
        detalle=obtener_user_agent(request), nivel="INFO",
    )
    return _respuesta_token(usuario)


def _exige_mfa(usuario: Usuario) -> bool:
    """A07 — las cuentas administrativas siempre exigen segundo factor."""
    if usuario.mfa_habilitado and usuario.mfa_secreto:
        return True
    return settings.MFA_EXIGIR_ADMIN and usuario.rol == RolUsuario.admin


def _respuesta_token(usuario: Usuario) -> TokenResponse:
    return TokenResponse(
        access_token=crear_token(usuario),
        id=usuario.id,
        rol=usuario.rol.value,
        nombre=usuario.nombre,
        email=usuario.email,
        debe_cambiar_contrasena=bool(usuario.debe_cambiar_contrasena),
        expira_en_minutos=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


# ── Segundo factor (TOTP) ────────────────────────────────────────────────────
async def usuario_desde_desafio_mfa(
    request: Request,
    token: str | None = Depends(oauth2_opcional),
    db: Session = Depends(get_db),
) -> Usuario:
    """
    Dependencia de autenticación de los endpoints MFA (A07 / A.5.15).

    Acepta el token de desafío `mfa_token` incluido en el cuerpo de la
    petición o, si la cuenta ya tenía sesión, el token normal de la cabecera
    `Authorization`. El cuerpo se lee desde la caché de Starlette, por lo que
    el endpoint sigue recibiendo su modelo pydantic sin volver a leerlo.
    """
    try:
        cuerpo = await request.json()
    except Exception:  # cuerpo ausente o no JSON
        cuerpo = None
    if isinstance(cuerpo, dict) and cuerpo.get("mfa_token"):
        return usuario_desde_token_mfa(str(cuerpo["mfa_token"]), db)
    if token:
        return usuario_desde_token(token, db)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Se requiere autenticación para configurar el MFA",
    )


@router.post("/mfa/verificar", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def verificar_mfa(
    request: Request,
    datos: MfaVerificarRequest,
    usuario: Usuario = Depends(usuario_desde_desafio_mfa),
    db: Session = Depends(get_db),
):
    """
    A07 — canjea el código TOTP por el token de sesión. El desafío es de corta
    vida y las fallidas consumen el mismo contador de intentos que el login,
    de modo que la fuerza bruta sobre el segundo factor también se bloquea.
    """
    ip = obtener_ip(request)

    if usuario.bloqueado_hasta and utcnow() < usuario.bloqueado_hasta:
        minutos = int((usuario.bloqueado_hasta - utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Cuenta bloqueada temporalmente. Intente en {minutos} minuto(s).",
        )

    if not usuario.mfa_secreto or not verificar_codigo(usuario.mfa_secreto, datos.codigo):
        usuario.intentos_fallidos = (usuario.intentos_fallidos or 0) + 1
        if usuario.intentos_fallidos >= MAX_INTENTOS:
            usuario.bloqueado_hasta = utcnow() + timedelta(minutes=BLOQUEO_MINUTOS)
            db.commit()
            registrar_log(
                db, usuario.id, "LOGIN_CUENTA_BLOQUEADA", "usuarios", usuario.id, ip,
                detalle=f"intentos_mfa={usuario.intentos_fallidos}", nivel="SECURITY",
            )
        else:
            db.commit()
        registrar_log(
            db, usuario.id, "MFA_FALLIDO", "usuarios", usuario.id, ip,
            detalle="codigo_totp_invalido", nivel="SECURITY",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA incorrecto",
        )

    usuario.intentos_fallidos = 0
    usuario.bloqueado_hasta = None
    usuario.ultimo_acceso = utcnow()
    db.commit()
    registrar_log(
        db, usuario.id, "LOGIN_EXITOSO", "usuarios", usuario.id, ip,
        detalle="mfa=totp", nivel="INFO",
    )
    return _respuesta_token(usuario)


@router.post("/mfa/configurar", response_model=MfaConfiguracionResponse)
def configurar_mfa(
    datos: MfaConfiguracionRequest,
    request: Request,
    usuario: Usuario = Depends(usuario_desde_desafio_mfa),
    db: Session = Depends(get_db),
):
    """
    A07 / A.8.24 — genera el secreto TOTP. Solo se devuelve **una vez**, en esta
    respuesta; se almacena cifrado con AES-256-GCM y queda inactivo hasta que
    se confirme con un código válido (`/mfa/activar`).
    """
    if usuario.mfa_habilitado:
        raise HTTPException(
            status_code=409,
            detail="El MFA ya está activo; el administrador debe reiniciarlo para rotarlo",
        )
    secreto = generar_secreto()
    usuario.mfa_secreto = secreto
    usuario.mfa_habilitado = False
    db.commit()
    registrar_log(
        db, usuario.id, "MFA_CONFIGURADO", "usuarios", usuario.id,
        obtener_ip(request), detalle="secreto_totp_generado", nivel="SECURITY",
    )
    return MfaConfiguracionResponse(
        email=usuario.email,
        clave=secreto,
        otpauth_uri=uri_autenticador(secreto, usuario.email),
        mfa_habilitado=False,
    )


@router.post("/mfa/activar", response_model=MfaConfiguracionResponse)
def activar_mfa(
    datos: MfaActivarRequest,
    request: Request,
    usuario: Usuario = Depends(usuario_desde_desafio_mfa),
    db: Session = Depends(get_db),
):
    """Confirma la posesión del secreto con un código TOTP y activa el MFA."""
    ip = obtener_ip(request)
    if not usuario.mfa_secreto or not verificar_codigo(usuario.mfa_secreto, datos.codigo):
        registrar_log(
            db, usuario.id, "MFA_FALLIDO", "usuarios", usuario.id, ip,
            detalle="activacion_codigo_invalido", nivel="SECURITY",
        )
        raise HTTPException(
            status_code=401, detail="Código MFA incorrecto; verifique la sincronización del reloj"
        )
    usuario.mfa_habilitado = True
    db.commit()
    registrar_log(
        db, usuario.id, "MFA_ACTIVADO", "usuarios", usuario.id, ip, nivel="SECURITY"
    )
    return MfaConfiguracionResponse(
        email=usuario.email,
        clave=usuario.mfa_secreto,
        otpauth_uri=uri_autenticador(usuario.mfa_secreto, usuario.email),
        mfa_habilitado=True,
    )


@router.post("/change-password", response_model=UsuarioResponse)
def cambiar_contrasena(
    datos: CambioPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """
    ISO 27001 A.5.17 / A.8.5 — rotación de contraseña.
    Exige la contraseña actual, valida la nueva contra la política y revoca
    todos los tokens previos del usuario.
    """
    if not verificar_password(datos.password_actual, usuario.password_hash):
        registrar_log(
            db, usuario.id, "CAMBIO_CONTRASENA_FALLIDO", "usuarios", usuario.id,
            obtener_ip(request), nivel="SECURITY",
        )
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta")

    if verificar_password(datos.password_nueva, usuario.password_hash):
        raise HTTPException(
            status_code=400, detail="La contraseña nueva debe ser distinta de la actual"
        )

    # El validador del esquema no conoce la identidad del usuario: la regla de
    # no reutilizar partes del correo se aplica aquí (A.5.17).
    fallos_identidad = [
        f for f in evaluar_contrasena(datos.password_nueva, usuario.email)
        if "correo electrónico" in f
    ]
    if fallos_identidad:
        raise HTTPException(status_code=400, detail=fallos_identidad[0])

    usuario.password_hash = hashear_password(datos.password_nueva)
    usuario.debe_cambiar_contrasena = False
    usuario.password_actualizada_en = utcnow()
    revocar_tokens(usuario)
    db.commit()

    registrar_log(
        db, usuario.id, "CAMBIO_CONTRASENA", "usuarios", usuario.id, obtener_ip(request),
        nivel="SECURITY",
    )
    return usuario


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """A.5.25 — el cierre de sesión invalida el token en el servidor."""
    revocar_tokens(usuario)
    db.commit()
    registrar_log(
        db, usuario.id, "LOGOUT", "usuarios", usuario.id, obtener_ip(request), nivel="INFO"
    )


@router.post("/usuarios", response_model=UsuarioCreateResponse, status_code=201)
def crear_usuario(
    datos: UsuarioCreate,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(requerir_rol(RolUsuario.admin)),
):
    """
    A01 — solo el administrador crea cuentas (privilegio mínimo).
    A07 — una cuenta administrativa nace con MFA (TOTP) activo y el secreto se
    devuelve únicamente en esta respuesta, cifrado en reposo desde su alta.
    """
    email = str(datos.email).lower()
    if db.query(Usuario).filter(Usuario.email == email).first():
        raise HTTPException(status_code=400, detail="El correo ya está registrado")

    secreto_mfa = None
    exige_mfa = settings.MFA_EXIGIR_ADMIN and datos.rol == RolUsuario.admin
    if exige_mfa:
        secreto_mfa = generar_secreto()

    nuevo = Usuario(
        nombre=datos.nombre,
        email=email,
        password_hash=hashear_password(datos.password),
        rol=datos.rol,
        activo=datos.activo,
        debe_cambiar_contrasena=datos.debe_cambiar_contrasena,
        mfa_secreto=secreto_mfa,
        mfa_habilitado=bool(secreto_mfa),
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    registrar_log(
        db, usuario.id, "CREAR_USUARIO", "usuarios", nuevo.id, obtener_ip(request),
        detalle=f"rol={nuevo.rol.value} activo={nuevo.activo}", nivel="SECURITY",
    )
    return UsuarioCreateResponse.model_validate(nuevo).model_copy(
        update={"mfa_secreto": secreto_mfa}
    )


@router.get("/medicos", response_model=list[MedicoResponse])
def listar_medicos(
    db: Session = Depends(get_db),
    _usuario=Depends(
        requerir_rol(RolUsuario.admin, RolUsuario.medico, RolUsuario.recepcionista)
    ),
):
    """
    A.5.15 — directorio mínimo de médicos activos para agendar citas.

    Antes, la interfaz usaba `/usuarios` (solo administrador) y el selector de
    médico quedaba vacío para recepción. Este endpoint expone únicamente
    `id` y `nombre` y exige sesión con rol operativo.
    """
    return (
        db.query(Usuario)
        .filter(Usuario.rol == RolUsuario.medico, Usuario.activo.is_(True))
        .order_by(Usuario.nombre)
        .all()
    )


@router.get("/usuarios", response_model=list[UsuarioResponse])
def listar_usuarios(
    db: Session = Depends(get_db),
    _usuario=Depends(requerir_rol(RolUsuario.admin)),
):
    return db.query(Usuario).order_by(Usuario.nombre).all()


@router.post("/usuarios/{id}/aprobar", response_model=AprobacionResponse)
def aprobar_acceso(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(requerir_rol(RolUsuario.admin)),
):
    """A.5.15 — el administrador aprueba el acceso de las cuentas dadas de alta
    como pendientes; la aprobación queda auditada."""
    u = db.query(Usuario).filter(Usuario.id == id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.activo:
        raise HTTPException(status_code=400, detail="La cuenta ya está aprobada")
    u.activo = True
    db.commit()
    db.refresh(u)
    registrar_log(
        db, usuario.id, "APROBAR_ACCESO", "usuarios", u.id, obtener_ip(request),
        detalle=f"cuenta={u.email}", nivel="SECURITY",
    )
    return AprobacionResponse(id=u.id, email=u.email, activo=u.activo, aprobado_por=usuario.id)


@router.put("/usuarios/{id}", response_model=UsuarioResponse)
def actualizar_usuario(
    id: int,
    datos: UsuarioUpdate,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(requerir_rol(RolUsuario.admin)),
):
    u = db.query(Usuario).filter(Usuario.id == id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    cambios = datos.model_dump(exclude_unset=True)

    if "email" in cambios and cambios["email"]:
        cambios["email"] = str(cambios["email"]).lower()
        if cambios["email"] != u.email and db.query(Usuario).filter(
            Usuario.email == cambios["email"]
        ).first():
            raise HTTPException(status_code=400, detail="El correo ya está registrado")

    nueva_contrasena = cambios.pop("password", None)
    cambios.pop("debe_cambiar_contrasena", None)
    reiniciar_mfa = cambios.pop("reiniciar_mfa", None)

    for k, v in cambios.items():
        setattr(u, k, v)

    if nueva_contrasena:
        u.password_hash = hashear_password(nueva_contrasena)
        u.password_actualizada_en = utcnow()
        # El admin que restablece una contraseña debe forzar su cambio y las
        # sesiones activas del usuario dejan de ser válidas.
        u.debe_cambiar_contrasena = True
        revocar_tokens(u)

    if reiniciar_mfa:
        # A.5.17 — recuperación de cuenta cuyo autenticador se perdió: el
        # secreto se borra y el administrador debe volver a entregarlo.
        u.mfa_secreto = None
        u.mfa_habilitado = False
        revocar_tokens(u)

    db.commit()
    db.refresh(u)
    registrar_log(
        db, usuario.id, "EDITAR_USUARIO", "usuarios", u.id, obtener_ip(request),
        detalle=f"campos={','.join(sorted(cambios)) or 'contraseña'}"
                f"{'+mfa' if reiniciar_mfa else ''}",
        nivel="SECURITY",
    )
    return u


@router.delete("/usuarios/{id}", status_code=204)
def eliminar_usuario(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(requerir_rol(RolUsuario.admin)),
):
    u = db.query(Usuario).filter(Usuario.id == id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.id == usuario.id:
        raise HTTPException(status_code=400, detail="No puede eliminar su propia cuenta")
    if db.query(Atencion).filter(Atencion.medico_id == u.id).first():
        raise HTTPException(
            status_code=409,
            detail="El usuario tiene historial clínico asociado; desactívelo en lugar de eliminarlo",
        )
    db.delete(u)
    db.commit()
    registrar_log(
        db, usuario.id, "ELIMINAR_USUARIO", "usuarios", id, obtener_ip(request), nivel="SECURITY"
    )


@router.get("/me", response_model=UsuarioResponse)
def mi_perfil(usuario: Usuario = Depends(obtener_usuario_actual)):
    return usuario
