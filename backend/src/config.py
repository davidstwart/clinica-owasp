"""
ISO/IEC 27001:2022 — Anexo A
  A.5.17  Información de autenticación
  A.5.23  Seguridad de la información para el uso de servicios en la nube
  A.8.24  Uso de la criptografía
  A.8.9   Configuración de la seguridad

Configuración centralizada y validada. El sistema falla de forma explícita
("fail-closed") cuando la configuración es insegura en producción, en lugar de
arrancar con valores por defecto inseguros.
"""
import json
import secrets
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Valores prohibidos: son públicos (están en el repositorio) y por tanto
# son claves de firma JWT conocidas por cualquiera que lea el código.
SECRETOS_PROHIBIDOS = {
    # Valor por defecto del código y plantillas de ejemplo: son públicos.
    "clave-secreta-cambiar-en-produccion-2026",
    "cambiar-por-clave-generada-aleatoriamente-01",
    "clavesecretaclinica2026",
    "secret",
    "changeme",
    "password",
    "12345678901234567890123456789012",
}


def _separar_lista(valor) -> list[str]:
    """Acepta `a,b,c` o `["a","b"]` desde el entorno y devuelve una lista."""
    if valor is None:
        return []
    if isinstance(valor, str):
        texto = valor.strip()
        if texto.startswith("["):
            try:
                return [str(p).strip() for p in json.loads(texto)]
            except json.JSONDecodeError:
                pass
        return [p.strip() for p in texto.replace("[", "").replace("]", "").split(",") if p.strip()]
    return list(valor)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        """
        pydantic-settings 2.3 decodifica los campos `list[str]` como JSON antes
        de validarlos. Desactivamos esa decodificación solo en las fuentes de
        entorno para que `_separar_lista` acepte también `a,b,c` (A.8.9).
        """
        campos_lista = {"ALLOWED_ORIGINS", "TRUSTED_HOSTS"}
        for fuente in (env_settings, dotenv_settings):
            original = fuente.prepare_field_value

            def preparar(field_name, field, value, value_is_complex, _original=original):
                if field_name in campos_lista:
                    return value
                return _original(field_name, field, value, value_is_complex)

            fuente.prepare_field_value = preparar
        return init_settings, env_settings, dotenv_settings, file_secret_settings

    # ── Entorno ──────────────────────────────────────────────────────────────
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    APP_NAME: str = "Sistema Clínica OWASP Top 10 2021"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    BIND_HOST: str = "127.0.0.1"
    BIND_PORT: int = Field(default=8000, ge=1, le=65535)

    # ── Persistencia ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/clinica_db"

    # ── Autenticación (A.5.17, A.8.24) ──────────────────────────────────────
    SECRET_KEY: str = "clave-secreta-cambiar-en-produccion-2026"
    ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    JWT_ISSUER: str = "clinica-api"
    JWT_AUDIENCE: str = "clinica-frontend"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)
    BCRYPT_ROUNDS: int = Field(default=12, ge=4, le=16)

    # Política de contraseñas (A.5.17)
    PASSWORD_MIN_LENGTH: int = Field(default=8, ge=8, le=128)
    PASSWORD_MAX_LENGTH: int = Field(default=72, ge=16, le=128)  # límite de bcrypt
    EXIGIR_MAYUSCULA: bool = True
    EXIGIR_MINUSCULA: bool = True
    EXIGIR_DIGITO: bool = True
    EXIGIR_SIMBOLO: bool = False
    EXIGIR_CAMBIO_CONTRASENA_INICIAL: bool = True
    MAX_INTENTOS_LOGIN: int = Field(default=5, ge=1, le=20)
    BLOQUEO_MINUTOS: int = Field(default=15, ge=1, le=1440)

    # MFA (A07 / A.5.17) — TOTP obligatorio para cuentas administrativas
    MFA_EXIGIR_ADMIN: bool = True
    MFA_TOKEN_EXPIRE_MINUTES: int = Field(default=5, ge=1, le=15)

    # Cifrado en reposo (A02 / A.8.24) — AES-256-GCM.
    # En producción se recomienda una clave propia de 32 bytes en base64:
    #   python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
    # Si no se define, la clave se deriva de SECRET_KEY con HKDF.
    CIFRADO_CLAVE: str = ""

    # ── Control de acceso web (A.8.20, A.8.21) ──────────────────────────────
    ALLOWED_ORIGINS: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    TRUSTED_HOSTS: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    # Render inyecta automáticamente el hostname público del servicio. Se añade
    # a TRUSTED_HOSTS para no tener que repetirlo en cada Blueprint (A.8.9).
    RENDER_EXTERNAL_HOSTNAME: str = ""
    HABILITAR_DOCS: bool = True
    # A.8.24 — en producción toda petición por HTTP se redirige a HTTPS
    # (cabecera `X-Forwarded-Proto` respetada cuando hay proxy delante).
    FORZAR_TLS: bool = True

    # ── Limitación de tasa (A.8.6, A.8.16) ─────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_POR_DEFECTO: str = "300/minute"

    # ── Registro y monitoreo (A.8.15, A.8.16) ───────────────────────────────
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    AUDIT_RETENTION_DAYS: int = Field(default=1825, ge=30)  # 5 años (historia clínica)

    @field_validator("ALLOWED_ORIGINS", "TRUSTED_HOSTS", mode="before")
    @classmethod
    def _parse_lista(cls, v):
        return _separar_lista(v)

    @field_validator("SECRET_KEY")
    @classmethod
    def _validar_secreto(cls, v: str) -> str:
        v = v.strip()
        if v in SECRETOS_PROHIBIDOS:
            raise ValueError(
                "SECRET_KEY utiliza un valor por defecto público. "
                "Genere una clave única con: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        if len(v) < 32:
            raise ValueError(
                "SECRET_KEY debe tener al menos 32 caracteres. "
                "Genere una clave única con: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        if len(set(v)) <= 8:
            raise ValueError("SECRET_KEY tiene demasiada repetición; genérela con secrets.token_urlsafe(48)")
        return v

    @model_validator(mode="after")
    def _validar_entorno(self):
        if self.RENDER_EXTERNAL_HOSTNAME and self.RENDER_EXTERNAL_HOSTNAME not in self.TRUSTED_HOSTS:
            self.TRUSTED_HOSTS = [*self.TRUSTED_HOSTS, self.RENDER_EXTERNAL_HOSTNAME]
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                raise ValueError("DEBUG debe ser False en producción (A.8.9)")
            if any(o in ("*", "http://localhost:3000") for o in self.ALLOWED_ORIGINS):
                raise ValueError(
                    "ALLOWED_ORIGINS no puede usar comodines ni localhost en producción (A.5.14)"
                )
            if self.ACCESS_TOKEN_EXPIRE_MINUTES > 60:
                raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES máximo 60 min (A.5.17)")
        if self.ENVIRONMENT == "testing":
            # Aislamiento de pruebas (ISO/IEC 29119): sin límite de tasa para
            # que las pruebas de bloqueo (A07) midan el bloqueo de cuenta y no
            # el limitador de peticiones. La rotación de contraseña NO se
            # desactiva: los datos de prueba se crean ya rotados.
            self.RATE_LIMIT_ENABLED = False
        return self

    @property
    def es_produccion(self) -> bool:
        return self.ENVIRONMENT == "production"


def generar_secreto() -> str:
    """Genera una clave de firma JWT criptográficamente segura (A.8.24)."""
    return secrets.token_urlsafe(48)


settings = Settings()
