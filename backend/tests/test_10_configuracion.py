"""
Pruebas de configuración y gestión de secretos — ISO/IEC 27001 A.5.17 / A.8.9.

Verifica el principio *fail-fast* (A.8.9): la aplicación se niega a arrancar con
una configuración insegura en lugar de operar con valores por defecto débiles.

Estas pruebas no reutilizan el módulo `src.config` ya importado: construyen
`Settings` en un subproceso con un entorno controlado, de modo que los
validadores se ejecutan realmente y no se ven afectados por la caché de módulos.

Casos: CP-CFG-001 … CP-CFG-015
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

RAIZ_BACKEND = Path(__file__).resolve().parents[1]
SECRETO_VALIDO = "kXq7-9Zm_2Rt_8Wv_4Lp_6Ny_3Hd_5Jf_1Gs_7Bq"

CLAVES_OBSERVABLES = [
    "ENVIRONMENT", "DEBUG", "SECRET_KEY", "ALGORITHM", "JWT_ISSUER", "JWT_AUDIENCE",
    "ACCESS_TOKEN_EXPIRE_MINUTES", "BCRYPT_ROUNDS",
    "PASSWORD_MIN_LENGTH", "PASSWORD_MAX_LENGTH", "EXIGIR_SIMBOLO",
    "EXIGIR_CAMBIO_CONTRASENA_INICIAL", "MAX_INTENTOS_LOGIN", "BLOQUEO_MINUTOS",
    "RATE_LIMIT_ENABLED", "RATE_LIMIT_LOGIN", "RATE_LIMIT_POR_DEFECTO",
    "HABILITAR_DOCS", "AUDIT_RETENTION_DAYS", "ALLOWED_ORIGINS", "TRUSTED_HOSTS",
]

def _entorno_base() -> dict:
    """
    Entorno limpio: se descarta cualquier variable de configuración que el
    sistema o el `.env` local puedan inyectar, para que cada caso pruebe
    exactamente lo que declara.
    """
    entorno = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith((
            "SECRET_", "PASSWORD_", "EXIGIR_", "RATE_LIMIT_", "JWT_",
            "MAX_INTENTOS_", "BLOQUEO_", "DEBUG", "ALLOWED_ORIGINS",
            "TRUSTED_HOSTS", "ENVIRONMENT", "HABILITAR_DOCS", "AUDIT_",
            "ACCESS_TOKEN_", "BCRYPT_ROUNDS", "DATABASE_URL", "ALGORITHM",
            "JWT_ISSUER", "JWT_AUDIENCE",
        ))
    }
    entorno.update({
        "ENVIRONMENT": "testing",
        "DATABASE_URL": "sqlite+pysqlite:///:memory:",
        "BCRYPT_ROUNDS": "4",
        "LOG_LEVEL": "CRITICAL",
    })
    return entorno


def _cargar_config(env_extra: dict) -> tuple[int, str, str]:
    """Ejecuta `Settings()` en un subproceso. Devuelve (código, stdout, stderr)."""
    codigo = textwrap.dedent(
        f"""
        import json, sys
        sys.path.insert(0, {str(RAIZ_BACKEND)!r})
        from src.config import Settings
        # `_env_file=None` aísla la prueba del `.env` local (ISO/IEC 29119 §5.2.2).
        s = Settings(_env_file=None)
        print(json.dumps({{k: str(getattr(s, k)) for k in {CLAVES_OBSERVABLES!r}}}))
        """
    )
    entorno = _entorno_base()
    entorno.update(env_extra)
    proc = subprocess.run(
        [sys.executable, "-c", codigo],
        cwd=str(RAIZ_BACKEND), env=entorno, capture_output=True, text=True, timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _rechazada(env_extra: dict, fragmento: str):
    codigo, salida, error = _cargar_config(env_extra)
    assert codigo != 0, f"Se esperaba el rechazo pero la configuración fue aceptada: {salida}"
    assert fragmento in error, error


def _aceptada(env_extra: dict) -> dict:
    codigo, salida, error = _cargar_config(env_extra)
    assert codigo == 0, f"Se esperaba aceptación pero la validación falló:\n{error}"
    return json.loads(salida.strip().splitlines()[-1])


def _lista(valor: str) -> list:
    """Convierte la representación textual de una lista de configuración."""
    import ast

    return ast.literal_eval(valor)


PRODUCCION_VALIDA = {
    "SECRET_KEY": SECRETO_VALIDO,
    "ENVIRONMENT": "production",
    "ALLOWED_ORIGINS": '["https://clinica.example.pe"]',
    "TRUSTED_HOSTS": '["clinica.example.pe"]',
}


# ── Secreto de firma ─────────────────────────────────────────────────────────
def test_CP_CFG_001_configuracion_valida_se_carga():
    config = _aceptada({"SECRET_KEY": SECRETO_VALIDO})
    assert config["SECRET_KEY"] == SECRETO_VALIDO
    assert config["ENVIRONMENT"] == "testing"


def test_CP_CFG_002_secreto_ausente_se_rechaza():
    """A.8.9 — sin `SECRET_KEY` se usa el valor por defecto, que está prohibido."""
    _rechazada({}, "SECRET_KEY")


def test_CP_CFG_003_secreto_publico_por_defecto_se_rechaza():
    """A.5.17 — la clave del repositorio es pública y no puede seguir en uso."""
    _rechazada({"SECRET_KEY": "clave-secreta-cambiar-en-produccion-2026"}, "valor por defecto público")


@pytest.mark.parametrize("secreto", ["secret", "changeme", "password",
                                     "12345678901234567890123456789012"])
def test_CP_CFG_004_secretos_de_baja_calidad_se_rechazan(secreto):
    """A.5.17 — la lista de valores prohibidos cubre los clásicos predecibles."""
    _rechazada({"SECRET_KEY": secreto}, "valor por defecto público")


def test_CP_CFG_005_secreto_demasiado_corto_se_rechaza():
    """A.8.24 — menos de 32 caracteres no ofrece entropía suficiente."""
    _rechazada({"SECRET_KEY": "Corto9x"}, "al menos 32 caracteres")


def test_CP_CFG_006_secreto_con_poca_variedad_se_rechaza():
    """A.8.24 — una clave con un solo carácter repetido es predecible."""
    _rechazada({"SECRET_KEY": "k" * 48}, "demasiada repetición")


# ── Entorno de producción ────────────────────────────────────────────────────
def test_CP_CFG_007_debug_se_prohibe_en_produccion():
    """A.8.9 — depurar en producción expone trazas e información interna."""
    _rechazada({**PRODUCCION_VALIDA, "DEBUG": "true"}, "DEBUG debe ser False en producción")


def test_CP_CFG_008_comodin_en_origenes_se_rechaza_en_produccion():
    """A.5.23 — `*` permitiría que cualquier sitio invoque la API."""
    _rechazada({**PRODUCCION_VALIDA, "ALLOWED_ORIGINS": '["*"]'}, "ALLOWED_ORIGINS")


def test_CP_CFG_009_localhost_en_origenes_se_rechaza_en_produccion():
    _rechazada({**PRODUCCION_VALIDA, "ALLOWED_ORIGINS": '["http://localhost:3000"]'}, "ALLOWED_ORIGINS")


def test_CP_CFG_010_vida_de_token_excesiva_se_rechaza_en_produccion():
    """A.5.17 — la ventana de exposición del token se acota a una hora."""
    _rechazada({**PRODUCCION_VALIDA, "ACCESS_TOKEN_EXPIRE_MINUTES": "480"}, "ACCESS_TOKEN_EXPIRE_MINUTES")


def test_CP_CFG_011_configuracion_de_produccion_valida_se_acepta():
    config = _aceptada(PRODUCCION_VALIDA)
    assert config["ENVIRONMENT"] == "production"
    assert config["DEBUG"] == "False"
    assert _lista(config["ALLOWED_ORIGINS"]) == ["https://clinica.example.pe"]
    assert _lista(config["TRUSTED_HOSTS"]) == ["clinica.example.pe"]


def test_CP_CFG_012_entorno_no_reconocido_se_rechaza():
    """A.8.9 — se exige identificar explícitamente el entorno."""
    _rechazada({"SECRET_KEY": SECRETO_VALIDO, "ENVIRONMENT": "sistema"}, "ENVIRONMENT")


# ── Coherencia de listas y valores por defecto ───────────────────────────────
def test_CP_CFG_013_los_origenes_se_parsean_como_lista():
    config = _aceptada({
        "SECRET_KEY": SECRETO_VALIDO,
        "ALLOWED_ORIGINS": '["https://a.example.pe", "https://b.example.pe"]',
    })
    assert _lista(config["ALLOWED_ORIGINS"]) == ["https://a.example.pe", "https://b.example.pe"]


def test_CP_CFG_014_los_valores_por_defecto_son_conservadores():
    """A.5.15 — mínimo privilegio por omisión."""
    config = _aceptada({"SECRET_KEY": SECRETO_VALIDO})
    assert config["PASSWORD_MIN_LENGTH"] == "8"
    assert config["PASSWORD_MAX_LENGTH"] == "72"      # límite técnico de bcrypt
    assert config["MAX_INTENTOS_LOGIN"] == "5"
    assert config["BLOQUEO_MINUTOS"] == "15"
    assert config["ACCESS_TOKEN_EXPIRE_MINUTES"] == "30"
    assert config["EXIGIR_CAMBIO_CONTRASENA_INICIAL"] == "True"
    assert config["AUDIT_RETENTION_DAYS"] == "1825"    # 5 años de historia clínica
    assert config["RATE_LIMIT_LOGIN"] == "10/minute"


def test_CP_CFG_015_en_pruebas_se_desactiva_el_limite_de_tasa_pero_no_la_rotacion():
    """
    ISO/IEC 29119 — aislamiento: el entorno de pruebas desactiva el limitador
    para no interferir con las pruebas de bloqueo, pero conserva la exigencia
    de rotar la contraseña inicial.
    """
    config = _aceptada({"SECRET_KEY": SECRETO_VALIDO})
    assert config["RATE_LIMIT_ENABLED"] == "False"
    assert config["EXIGIR_CAMBIO_CONTRASENA_INICIAL"] == "True"


def test_CP_CFG_016_el_archivo_de_ejemplo_no_es_una_configuracion_valida():
    """
    A.5.17 — `backend/.env.example` es una plantilla: sus valores no deben
    permitir arrancar la aplicación por descuido.
    """
    ejemplo = RAIZ_BACKEND / ".env.example"
    if not ejemplo.exists():
        pytest.skip("No existe backend/.env.example")
    codigo, salida, error = _cargar_config({
        "SECRET_KEY": _leer_valor(ejemplo, "SECRET_KEY"),
    })
    assert codigo != 0, f"La plantilla .env.example arranca la aplicación: {salida}"


def _leer_valor(ruta: Path, clave: str) -> str:
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if linea.strip().startswith(f"{clave}="):
            return linea.split("=", 1)[1].strip()
    return ""