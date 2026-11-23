"""
OWASP A05:2021 — Configuración de Seguridad Incorrecta
ISO/IEC 27001:2022 — A.8.20 / A.8.21 / A.8.25 / A.8.26

Cabeceras de seguridad aplicadas a todas las respuestas. Se sigue el proyecto
OWASP Secure Headers Project: se eliminan las cabeceras obsoletas
(`X-XSS-Protection` con `1; mode=block` es contraproducente en navegadores
modernos y se sustituye por una CSP explícita) y se añaden las Recommendations
de OWASP ASVS V14.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..config import settings

# Rutas donde la aplicación sirve su propia interfaz documental (Swagger/ReDoc):
# necesitan permitir estilos y scripts embebidos.
RUTAS_DOCUMENTACION = ("/docs", "/redoc", "/docs/oauth2-redirect")

CSP_ESTRICTA = (
    "default-src 'none'; script-src 'none'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"
)
CSP_DOCUMENTACION = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # A.8.25 — evita que el navegador adivine el tipo de contenido
        response.headers["X-Content-Type-Options"] = "nosniff"

        # A.8.25 — anti-clickjacking (se refuerza con frame-ancestors en la CSP)
        response.headers["X-Frame-Options"] = "DENY"

        # A.8.25 — Content Security Policy
        en_docs = request.url.path.startswith(RUTAS_DOCUMENTACION)
        response.headers["Content-Security-Policy"] = CSP_DOCUMENTACION if en_docs else CSP_ESTRICTA

        # A.8.24 — los datos clínicos no se almacenan en cachés intermedias
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

        # A.5.14 — se revela el origen completo solo al mismo sitio
        response.headers["Referrer-Policy"] = "no-referrer"

        # A.8.25 — aislamiento del documento y permisos mínimos del navegador
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
            "magnetometer=(), interest-cohort=()"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # A.8.25 — HSTS solo en producción: en desarrollo rompería el flujo
        # local al forzar HTTPS contra un servidor sin TLS.
        if settings.es_produccion:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response
