"""
OWASP A07:2021 — segundo factor de autenticación (MFA) basado en TOTP
(RFC 6238) para las cuentas administrativas, e ISO/IEC 27001 A.5.17.

El secreto TOTP:
  · Se genera con `secrets` (pyotp) y se almacena **cifrado** con AES-256-GCM.
  · Solo se devuelve al cliente en el momento de generarlo (nunca se expone en
    la API de lectura de usuarios).
  · Verifica una ventana de ±1 periodo de 30 s para absorber el desfase de
    reloj entre el servidor y el autenticador.
"""
import pyotp

from ..config import settings

LONGITUD_CODIGO = 6


def generar_secreto() -> str:
    """Genera un secreto TOTP base32 de 160 bits (RFC 4226, mínimo recomendado)."""
    return pyotp.random_base32()


def verificar_codigo(secreto: str, codigo: str) -> bool:
    """Valida el código de 6 dígitos contra el secreto con ventana ±1."""
    if not secreto or not codigo:
        return False
    codigo = str(codigo).strip().replace(" ", "")
    if len(codigo) != LONGITUD_CODIGO or not codigo.isdigit():
        return False
    try:
        return bool(pyotp.TOTP(secreto).verify(codigo, valid_window=1))
    except Exception:  # noqa: BLE001 — secreto o código malformados
        return False


def uri_autenticador(secreto: str, email: str) -> str:
    """URI `otpauth://` para enlazar el secreto desde un autenticador móvil."""
    return pyotp.TOTP(secreto).provisioning_uri(
        name=email,
        issuer_name=settings.APP_NAME,
    )
