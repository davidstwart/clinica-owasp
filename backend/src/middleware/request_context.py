"""
ISO/IEC 27001:2022 — A.8.15 Registro / A.8.16 Monitoreo

Cada petición recibe un identificador de correlación (`X-Request-ID`) que:
  1. Se genera en el borde si el cliente no lo aporta (o si aporta un valor
     con formato inválido, para evitar inyección en los registros).
  2. Se propaga en el contexto de la petición para que `registrar_log` lo
     associate a cada entrada de auditoría.
  3. Se devuelve en la respuesta, permitiendo correlacionar la incidencia que
     reporta el usuario con la entrada exacta del registro.

NUNCA se registra el cuerpo de la petición ni cabeceras de autenticación.
"""
import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

logger = logging.getLogger("clinica.acceso")

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        entrante = request.headers.get("X-Request-ID", "")
        request_id = entrante if REQUEST_ID_RE.match(entrante) else uuid.uuid4().hex
        request.state.request_id = request_id

        inicio = time.perf_counter()
        try:
            response = await call_next(request)
            estado = response.status_code
        except Exception:
            duracion_ms = (time.perf_counter() - inicio) * 1000
            logger.exception(
                "ACCESO %s %s ip=%s duracion_ms=%.1f request_id=%s resultado=error",
                request.method, request.url.path,
                request.client.host if request.client else "-", duracion_ms, request_id,
            )
            raise

        duracion_ms = (time.perf_counter() - inicio) * 1000
        response.headers["X-Request-ID"] = request_id

        # A.8.16 — los 5xx y los 4xx de autenticación/autorización se elevan a WARNING
        if estado >= 500:
            nivel = logging.ERROR
        elif estado in (401, 403, 429):
            nivel = logging.WARNING
        else:
            nivel = logging.INFO

        logger.log(
            nivel,
            "ACCESO %s %s status=%s ip=%s usuario=%s duracion_ms=%.1f request_id=%s",
            request.method, request.url.path, estado,
            request.client.host if request.client else "-",
            getattr(request.state, "usuario_email", "-"),
            duracion_ms, request_id,
        )
        return response


def obtener_request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)
