"""
OWASP A02:2021 — Fallos Criptográficos · ISO/IEC 27001:2022 A.8.24

Forzado de HTTPS en producción: cualquier petición recibida por HTTP (o por
un proxy que la termina en claro y la anuncia con `X-Forwarded-Proto: http`)
se redirige con **308 Permanent Redirect**, conservando método y cuerpo.

La decisión se aísla en `debe_redireccionar` para poder probarla sin levantar
un servidor TLS (ISO/IEC 29119 — casos CP-SEC-*).
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from ..config import settings

PUERTO_HTTPS = 443


def debe_redireccionar(esquema: str, forwarded_proto: str | None, forzar_tls: bool) -> bool:
    """Indica si una petición debe pasarse a HTTPS.

    :param esquema: esquema con el que el servidor recibió la petición.
    :param forwarded_proto: valor de `X-Forwarded-Proto` si hubo proxy delante.
    :param forzar_tls: control de configuración (solo producción).
    """
    if not forzar_tls:
        return False
    if forwarded_proto:
        return forwarded_proto.split(",")[0].strip().lower() != "https"
    return (esquema or "http").lower() != "https"


class TLSRedirectMiddleware(BaseHTTPMiddleware):
    """Redirige a HTTPS cuando la configuración lo exige."""

    async def dispatch(self, request: Request, call_next):
        forzar = settings.FORZAR_TLS and settings.es_produccion
        if debe_redireccionar(
            request.url.scheme,
            request.headers.get("X-Forwarded-Proto"),
            forzar,
        ):
            destino = request.url.replace(scheme="https", port=None)
            return RedirectResponse(str(destino), status_code=308)
        return await call_next(request)
