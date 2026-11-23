"""
ISO/IEC 27001:2022 — A.8.24 Uso de la criptografía / A.8.26 Seguridad de la
información durante el desarrollo.

Cifrado en reposo de datos sensibles con **AES-256-GCM** (autenticado):

  · La clave se deriva de `CIFRADO_CLAVE` (recomendado en producción) o, en
    su defecto, de `SECRET_KEY` mediante HKDF-SHA256, de modo que dos datos
    idénticos nunca se almacenan idénticos (nonce aleatorio por valor).
  · El ciphertext se guarda con el prefijo `enc:v1:` + base64(nonce || tag).
  · La deserialización es transparente para la aplicación: los modelos devuelven
    el texto plano, pero en la base de datos el valor es ilegible sin la clave.

Uso:
    from ..security.cifrado import TextoCifrado
    diagnostico = Column(TextoCifrado, nullable=False)
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.types import Text, TypeDecorator

from ..config import settings

PREFIJO = "enc:v1:"
LONGITUD_CLAVE = 32          # AES-256
LONGITUD_NONCE = 12          # 96 bits, recomendado para GCM
_LONGITUD_CODIGO = 6         # longitud mínima del texto cifrado en base64


def _derivar_clave() -> bytes:
    """Deriva una clave AES-256 a partir de la clave de configuración (HKDF)."""
    material = (settings.CIFRADO_CLAVE or settings.SECRET_KEY).encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=b"clinica-owasp-cifrado-reposo-v1",
        info=b"aes-256-gcm",
    ).derive(material)


def cifrar(texto: str) -> str:
    """Cifra texto plano con AES-256-GCM y devuelve `enc:v1:<base64>`."""
    if texto is None:
        return None
    nonce = os.urandom(LONGITUD_NONCE)
    ciphertext = AESGCM(_derivar_clave()).encrypt(nonce, texto.encode("utf-8"), None)
    return PREFIJO + base64.b64encode(nonce + ciphertext).decode("ascii")


def descifrar(dato: str) -> str:
    """Descifra un valor almacenado. Un valor sin el prefijo se devuelve tal cual
    para permitir la migración de datos anteriores a la activación del cifrado."""
    if dato is None:
        return None
    if not dato.startswith(PREFIJO):
        return dato
    try:
        bruto = base64.b64decode(dato[len(PREFIJO):])
        nonce, ciphertext = bruto[:LONGITUD_NONCE], bruto[LONGITUD_NONCE:]
        return AESGCM(_derivar_clave()).decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 — dato corrupto o clave distinta
        raise ValueError("No se pudo descifrar el dato almacenado") from exc


class TextoCifrado(TypeDecorator):
    """Columna de texto cifrada en reposo (AES-256-GCM)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or value == "":
            return value
        return cifrar(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return descifrar(value)


def es_cifrado(dato: str) -> bool:
    """Indica si un valor está en formato cifrado (para pruebas y auditoría)."""
    return isinstance(dato, str) and dato.startswith(PREFIJO) and len(dato) > _LONGITUD_CODIGO
