"""
Pruebas unitarias — Seguridad: bcrypt y tokens JWT.
ISO/IEC 29119-2 nivel componente · OWASP A02 / A07 · ISO/IEC 27001 A.8.5, A.8.24

Casos: CP-SEG-001 … CP-SEG-016
"""
from datetime import datetime, timedelta, timezone

import pytest
from jose import JWTError, jwt

from src.auth.models import RolUsuario
from src.auth.security import (
    crear_token,
    decodificar_token,
    hashear_password,
    revocar_tokens,
    verificar_password,
    verificar_password_sin_usuario,
)
from src.config import settings

pytestmark = pytest.mark.unit


class _UsuarioFalso:
    """Doble de prueba: evita depender de la base de datos en pruebas unitarias."""

    def __init__(self, version=0):
        self.email = "medico@test.pe"
        self.rol = RolUsuario.medico
        self.token_version = version


# ── Contraseñas ──────────────────────────────────────────────────────────────
def test_CP_SEG_001_bcrypt_no_guarda_texto_plano():
    hash_ = hashear_password("Huancayo#Root2026")
    assert "Huancayo#Root2026" not in hash_
    assert hash_.startswith("$2")


def test_CP_SEG_002_bcrypt_verifica_correcta_e_incorrecta():
    hash_ = hashear_password("Huancayo#Root2026")
    assert verificar_password("Huancayo#Root2026", hash_) is True
    assert verificar_password("Huancayo#Root2027", hash_) is False


def test_CP_SEG_003_bcrypt_genera_salt_aleatorio():
    hash_a = hashear_password("Huancayo#Root2026")
    hash_b = hashear_password("Huancayo#Root2026")
    assert hash_a != hash_b


def test_CP_SEG_004_hash_malformado_no_rompe_el_sistema():
    """Un hash corrupto en base de datos no debe causar una excepción 500."""
    assert verificar_password("cualquiera", "no-es-un-hash") is False


def test_CP_SEG_005_verificacion_senuelo_no_crea_hash_nuevo():
    verificar_password_sin_usuario("lo-que-sea")
    verificar_password_sin_usuario("lo-que-sea")  # debe ser idempotente en tiempo


# ── Tokens ───────────────────────────────────────────────────────────────────
def test_CP_SEG_006_token_contiene_claims_requeridos():
    payload = decodificar_token(crear_token(_UsuarioFalso()))
    for claim in ("sub", "exp", "iat", "iss", "aud", "jti", "ver"):
        assert claim in payload, claim
    assert payload["sub"] == "medico@test.pe"
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["aud"] == settings.JWT_AUDIENCE
    assert payload["rol"] == "medico"


def test_CP_SEG_007_token_expira_segun_configuracion():
    payload = decodificar_token(crear_token(_UsuarioFalso()))
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    esperado = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    diferencia = exp - datetime.now(timezone.utc)
    assert esperado - timedelta(seconds=5) <= diferencia <= esperado + timedelta(seconds=5)


def test_CP_SEG_008_token_alterado_es_rechazado():
    token = crear_token(_UsuarioFalso())
    cabecera, carga, firma = token.split(".")
    alterada = f"{cabecera}.{carga[:-4]}AAAA.{firma}"
    with pytest.raises(JWTError):
        decodificar_token(alterada)


def test_CP_SEG_009_token_firmado_con_otra_clave_es_rechazado():
    token = jwt.encode(
        {"sub": "medico@test.pe", "ver": 0, "iss": settings.JWT_ISSUER,
         "aud": settings.JWT_AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "clave-del-atacante-suficientemente-larga-0000000000",
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(JWTError):
        decodificar_token(token)


def test_CP_SEG_010_algoritmo_none_es_rechazado():
    """El token sin firma debe rechazarse aunque esté bien estructurado."""
    import base64
    import json

    def b64(datos):
        return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()

    cabecera = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    carga = b64(json.dumps({
        "sub": "medico@test.pe", "ver": 0,
        "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
    }).encode())
    with pytest.raises(JWTError):
        decodificar_token(f"{cabecera}.{carga}.")


def test_CP_SEG_011_token_de_otro_emisor_es_rechazado():
    token = jwt.encode(
        {"sub": "medico@test.pe", "ver": 0, "iss": "otro-sistema",
         "aud": settings.JWT_AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    with pytest.raises(JWTError):
        decodificar_token(token)


def test_CP_SEG_012_token_de_otra_audiencia_es_rechazado():
    token = jwt.encode(
        {"sub": "medico@test.pe", "ver": 0, "iss": settings.JWT_ISSUER,
         "aud": "otra-app", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    with pytest.raises(JWTError):
        decodificar_token(token)


def test_CP_SEG_013_token_expirado_es_rechazado():
    token = jwt.encode(
        {"sub": "medico@test.pe", "ver": 0, "iss": settings.JWT_ISSUER,
         "aud": settings.JWT_AUDIENCE, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    with pytest.raises(JWTError):
        decodificar_token(token)


def test_CP_SEG_014_token_sin_exp_es_rechazado():
    token = jwt.encode(
        {"sub": "medico@test.pe", "ver": 0, "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    with pytest.raises(JWTError):
        decodificar_token(token)


def test_CP_SEG_015_cada_token_tiene_identificador_unico():
    """A.5.25 — `jti` permite trazar y revocar sesiones de forma individual."""
    ids = {decodificar_token(crear_token(_UsuarioFalso()))["jti"] for _ in range(20)}
    assert len(ids) == 20


def test_CP_SEG_016_revocacion_incrementa_la_version():
    usuario = _UsuarioFalso(version=0)
    revocar_tokens(usuario)
    assert usuario.token_version == 1
    revocar_tokens(usuario)
    assert usuario.token_version == 2
