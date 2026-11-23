"""
Punto de entrada de la API — Sistema Clínica OWASP Top 10 2021.

Controles OWASP/ISO aplicados en el borde:
  A01 Broken Access Control         → RBAC en cada router (auth/security.py)
  A02 Cryptographic Failures        → bcrypt + JWT (auth/security.py)
  A03 Injection                     → SQLAlchemy ORM + Pydantic
  A05 Security Misconfiguration     → cabeceras, CORS, hosts, docs, rate limit
  A07 Identification & Auth Failures→ bloqueo de cuenta, rotación, revocación
  A09 Logging & Monitoring          → auditoría + log de acceso con Request-ID

ISO/IEC 27001: A.8.2, A.8.4, A.8.9, A.8.20, A.8.21, A.8.25, A.8.26, A.8.29
"""
import logging
import sys
import uuid

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import settings
from .middleware.request_context import RequestContextMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .middleware.tls_redirect import TLSRedirectMiddleware

# ── Logging estructurado (A.8.15) ────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    stream=sys.stdout,
)
for nombre in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    logging.getLogger(nombre).handlers.clear()
    logging.getLogger(nombre).propagate = True

logger = logging.getLogger("clinica.app")

# ── Limitación de tasa (A.8.6, A.8.16) ───────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_POR_DEFECTO],
    enabled=settings.RATE_LIMIT_ENABLED,
    headers_enabled=True,
)

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Sistema web de gestión clínica con controles OWASP Top 10 2021 "
        "e ISO/IEC 27001:2022, y proceso de desarrollo según "
        "ISO/IEC 9001, ISO/IEC 25000 e ISO/IEC 29119."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.HABILITAR_DOCS else None,
    redoc_url="/redoc" if settings.HABILITAR_DOCS else None,
    openapi_url="/openapi.json" if settings.HABILITAR_DOCS else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Middlewares (el último registrado se ejecuta primero) ─────────────────────
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)
app.add_middleware(SecurityHeadersMiddleware)
# A.8.24 — el forzado de HTTPS protege al resto de la cadena de peticiones.
app.add_middleware(TLSRedirectMiddleware)
app.add_middleware(RequestContextMiddleware)
# A.5.14 — CORS se registra al final para ser el middleware más externo y
# añadir sus cabeceras incluso a las respuestas de error de los demás.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Auth-Error-Code"],
    max_age=600,
)


@app.exception_handler(RequestValidationError)
async def validacion_invalida(request: Request, exc: RequestValidationError):
    """
    A.05 / A.10 — la respuesta de validación no revela la estructura interna
    (traza, modelo, nombre de tabla): solo campos y mensajes de regla.
    """
    campos = []
    for error in exc.errors():
        ubicacion = [str(p) for p in error.get("loc", []) if p not in ("body", "query", "path")]
        campos.append({
            "campo": ".".join(ubicacion) or "cuerpo",
            "mensaje": error.get("msg", "valor inválido"),
        })
    logger.info("VALIDACION request_id=%s campos=%s",
                getattr(request.state, "request_id", "-"), [c["campo"] for c in campos])
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": campos, "request_id": getattr(request.state, "request_id", None)},
    )


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    """Añade `request_id` a todas las respuestas de error (correlación A.8.16)."""
    respuesta = JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        respuesta.headers["X-Request-ID"] = request_id
    if exc.status_code >= 500:
        logger.error("HTTP %s en %s request_id=%s", exc.status_code, request.url.path, request_id)
    return respuesta


@app.exception_handler(Exception)
async def error_inesperado(request: Request, exc: Exception):
    """
    A.05 — nunca se devuelve la traza al cliente; se registra completa en el
    servidor con su `request_id` para que soporte pueda reconstruir el fallo.
    """
    request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex
    logger.exception("ERROR_NO_CONTROLADO request_id=%s ruta=%s", request_id, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Error interno del servidor. Contacte al administrador "
                      f"con el código de seguimiento {request_id}.",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


# ── Modelos y tablas ─────────────────────────────────────────────────────────
from .database import Base, engine, asegurar_esquema  # noqa: E402
from .auth.models import Usuario  # noqa: E402,F401
from .pacientes.models import Paciente  # noqa: E402,F401
from .citas.models import Cita  # noqa: E402,F401
from .atenciones.models import Atencion  # noqa: E402,F401
from .auditoria.models import AuditoriaLog  # noqa: E402,F401

Base.metadata.create_all(bind=engine)
asegurar_esquema()

# ── Routers ──────────────────────────────────────────────────────────────────
from .auth.router import router as auth_router  # noqa: E402
from .pacientes.router import router as pacientes_router  # noqa: E402
from .citas.router import router as citas_router  # noqa: E402
from .atenciones.router import router as atenciones_router  # noqa: E402
from .auditoria.router import router as auditoria_router  # noqa: E402
from .reportes.router import router as reportes_router  # noqa: E402

app.include_router(auth_router)
app.include_router(pacientes_router)
app.include_router(citas_router)
app.include_router(atenciones_router)
app.include_router(auditoria_router)
app.include_router(reportes_router)


@app.get("/", tags=["Sistema"])
def root():
    """A.5.15 — información mínima; no revela versiones de dependencias."""
    return {
        "sistema": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "estado": "operativo",
        "ambiente": settings.ENVIRONMENT,
        "docs": "/docs" if settings.HABILITAR_DOCS else None,
    }


@app.get("/health", tags=["Sistema"])
def health():
    """A.8.16 — sonda de disponibilidad para el monitoreo."""
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host=settings.BIND_HOST,
        port=settings.BIND_PORT,
        reload=not settings.es_produccion,
    )
