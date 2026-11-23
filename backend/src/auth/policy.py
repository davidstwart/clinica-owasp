"""
ISO/IEC 27001:2022 — A.5.17 Información de autenticación
  A.8.5  Autenticación segura

Política de contraseñas centralizada y configurable. La misma función se usa en:
  - creación y actualización de usuarios  (auth/schemas.py)
  - cambio de contraseña del propio usuario (auth/router.py)
  - validación del script de carga inicial (seed.py)

Centralizarla garantiza que ninguna vía de alta de credenciales eluda la
política (ISO/IEC 25010 — Adecuación funcional, y ISO 9001 §8.5.1).
"""
import re

from ..config import settings

# Contraseñas comprometidas conocidas — rechazo explícito (A.5.17).
CONTRASENAS_PROHIBIDAS = {
    "password", "password1", "12345678", "123456789", "qwerty123",
    "admin1234", "medico1234", "recep1234", "clinica1234", "1234567890",
    "contrasena", "contraseña", "abc12345", "qwertyui", "iloveyou",
}

# Secuencias triviales de teclado o de conteo presentes en contraseñas descartadas
# por análisis de frecuencia (NC-01, registro de no conformidades). Se incluyen
# tanto ascendentes como descendentes ("1234" y "4321").
SECUENCIAS_TRIVIALES = frozenset(
    bloque[i:i + 4]
    for alfabeto in ("abcdefghijklmnopqrstuvwxyz", "0123456789")
    for bloque in (alfabeto, alfabeto[::-1])
    for i in range(len(alfabeto) - 3)
) | frozenset(
    fila[i:i + 4]
    for fila in ("qwertyuiop", "asdfghjkl", "zxcvbnm")
    for i in range(len(fila) - 3)
)


def evaluar_contrasena(contrasena: str, email: str | None = None) -> list[str]:
    """
    Devuelve la lista de incumplimientos. Lista vacía = contraseña conforme.
    Nunca registra ni lanza la contraseña evaluada.
    """
    fallos: list[str] = []

    if not isinstance(contrasena, str) or not contrasena:
        return ["La contraseña no puede estar vacía"]

    if len(contrasena) < settings.PASSWORD_MIN_LENGTH:
        fallos.append(f"La contraseña debe tener al menos {settings.PASSWORD_MIN_LENGTH} caracteres")
    if len(contrasena) > settings.PASSWORD_MAX_LENGTH:
        fallos.append(
            f"La contraseña no puede superar {settings.PASSWORD_MAX_LENGTH} caracteres"
        )
    if settings.EXIGIR_MAYUSCULA and not any(c.isupper() for c in contrasena):
        fallos.append("La contraseña debe contener al menos una letra mayúscula")
    if settings.EXIGIR_MINUSCULA and not any(c.islower() for c in contrasena):
        fallos.append("La contraseña debe contener al menos una letra minúscula")
    if settings.EXIGIR_DIGITO and not any(c.isdigit() for c in contrasena):
        fallos.append("La contraseña debe contener al menos un dígito")
    if settings.EXIGIR_SIMBOLO and not any(not c.isalnum() for c in contrasena):
        fallos.append("La contraseña debe contener al menos un carácter especial")

    if contrasena.lower() in CONTRASENAS_PROHIBIDAS:
        fallos.append("La contraseña está en la lista de contraseñas comprometidas")

    # No debe contener ninguna parte de la identidad del usuario (A.5.17)
    if email:
        local = contrasena.lower()
        for parte in email.replace("@", " ").replace(".", " ").split():
            if len(parte) >= 4 and parte in local:
                fallos.append("La contraseña no debe contener partes del correo electrónico")
                break

    # Patrones triviales: 4+ caracteres idénticos consecutivos o secuencias
    # de teclado/conteo (aaaa, 1234, qwer, 9876).
    if re.search(r"(.)\1{3,}", contrasena):
        fallos.append("La contraseña no puede contener 4 caracteres idénticos consecutivos")
    lower = contrasena.lower()
    if any(seq in lower for seq in SECUENCIAS_TRIVIALES):
        fallos.append("La contraseña no puede contener secuencias triviales (1234, abcd, qwer)")

    return fallos


def contrasena_es_valida(contrasena: str, email: str | None = None) -> bool:
    return not evaluar_contrasena(contrasena, email)
