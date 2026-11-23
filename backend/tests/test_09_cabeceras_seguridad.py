"""
Pruebas de seguridad — Cabeceras HTTP (A.5.2, A.8.25).
ISO/IEC 27001:2022 · ISO/IEC 25010 (seguridad)

Verifica que la aplicación emite las cabeceras defensivas que protegen al
navegador frente a、XSS, clickjacking, sniffing de contenido y fuga por caché.
"""
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
def respuesta(cliente, admin):
    return cliente.get("/api/pacientes/", headers=admin)


def test_CP_SEC_001_content_security_policy(respuesta):
    """A.5.2 — política restrictiva: sin fuentes ni scripts externos."""
    csp = respuesta.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'none'" in csp
    assert "object-src 'none'" in csp
    # La API no sirve recursos externos, por lo que no admite 'unsafe-inline'.
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_CP_SEC_002_x_content_type_options(respuesta):
    """A.8.25 — impide que el navegador interprete JSON como otro tipo."""
    assert respuesta.headers["x-content-type-options"] == "nosniff"


def test_CP_SEC_003_x_frame_options(respuesta):
    """A.5.2 — defensa clásica contra clickjacking."""
    assert respuesta.headers["x-frame-options"] == "DENY"


def test_CP_SEC_004_referrer_policy(respuesta):
    """A.5.25 — no se filtra la URL del paciente a terceros."""
    assert respuesta.headers["referrer-policy"] == "no-referrer"


def test_CP_SEC_005_no_cache(respuesta):
    """A.5.33 — los datos de pacientes no se almacenan en cachés intermedias."""
    assert "no-store" in respuesta.headers["cache-control"]
    assert "no-cache" in respuesta.headers["cache-control"]
    assert "must-revalidate" in respuesta.headers["cache-control"]
    assert respuesta.headers["pragma"] == "no-cache"


def test_CP_SEC_006_cross_origin_isolation(respuesta):
    """A.8.25 — aislamiento frente a ventanas cruzadas y recursos externos."""
    assert respuesta.headers["cross-origin-opener-policy"] == "same-origin"
    assert respuesta.headers["cross-origin-resource-policy"] == "same-origin"


def test_CP_SEC_007_permissions_policy(respuesta):
    """A.5.19 — las capacidades del navegador quedan denegadas por defecto."""
    permisos = respuesta.headers["permissions-policy"]
    for capacidad in ("geolocation=()", "camera=()", "microphone=()", "payment=()", "usb=()"):
        assert capacidad in permisos


def test_CP_SEC_008_cross_domain_policies(respuesta):
    """A.8.25 — se desactiva la compatibilidad heredada de Adobe/Flash."""
    assert respuesta.headers["x-permitted-cross-domain-policies"] == "none"


def test_CP_SEC_009_hsts_condicionado_al_entorno(cliente, admin, respuesta):
    """A.5.14 — HSTS solo se emite cuando el despliegue es realmente seguro."""
    from src.config import settings

    hsts = respuesta.headers.get("strict-transport-security")
    if settings.ENVIRONMENT == "production":
        assert hsts is not None
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts
    else:
        assert hsts is None, "HSTS no debe emitirse en entornos no productivos"


def test_CP_SEC_010_request_id_en_toda_respuesta(respuesta):
    """A.8.16 — identificador de correlación por petición."""
    identificador = respuesta.headers["x-request-id"]
    assert len(identificador) >= 16


def test_CP_SEC_011_request_id_se_propaga_al_error(cliente, admin):
    """A.8.16 — los errores también deben ser correlacionables."""
    r = cliente.get("/api/pacientes/999999", headers=admin)
    assert r.status_code == 404
    assert r.headers.get("x-request-id")


def test_CP_SEC_012_se_acepta_un_request_id_del_cliente(cliente, admin):
    """A.8.16 — el identificador se conserva si el cliente lo aporta (trazabilidad extremo a extremo)."""
    propio = "traza-cliente-1234567890"
    r = cliente.get("/api/pacientes/", headers={**admin, "X-Request-ID": propio})
    assert r.headers["x-request-id"] == propio


def test_CP_SEC_013_cabeceras_en_respuestas_de_error(cliente):
    """Las cabeceras defensivas se emiten aunque la petición falle."""
    r = cliente.get("/api/pacientes/")
    assert r.status_code == 401
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers
    assert "no-store" in r.headers["cache-control"]


def test_CP_SEC_014_la_raiz_no_filtra_detalles_internos(cliente):
    """
    A.8.26 — la raíz describe el servicio de forma mínima: no expone la base de
    datos, el servidor web, la ruta de un documento de OpenAPI cuando está
    deshabilitado, ni secretos.
    """
    r = cliente.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")

    cuerpo = r.text.lower()
    for interno in ("sqlite", "postgres", "uvicorn", "secret", "password", "starlette", "fastapi"):
        assert interno not in cuerpo, interno

    # El detalle de la versión del framework no se expone.
    assert "/" not in r.json().get("version", "")


def test_CP_SEC_015_el_frontend_declara_csp_y_sri():
    """
    El cliente React se despliega como origen independiente; su política se
    define en `index.html` (A.5.2 / A.8.9).
    """
    from pathlib import Path

    indice = Path(__file__).resolve().parents[2] / "frontend" / "public" / "index.html"
    assert indice.exists(), "No se encontró frontend/public/index.html"
    html = indice.read_text(encoding="utf-8")

    assert "Content-Security-Policy" in html
    assert "default-src 'self'" in html
    assert "script-src 'self' https://cdn.jsdelivr.net" in html
    assert "object-src 'none'" in html
    assert "frame-ancestors 'none'" in html
    assert "base-uri 'self'" in html

    # `unsafe-eval` no se permite en la directiva `script-src` (A.5.2). El
    # comentario que lo menciona en negativo no cuenta como permiso.
    directiva_script = html.split("script-src", 1)[1].split(";", 1)[0]
    assert "unsafe-eval" not in directiva_script

    # Los recursos de terceros llevan Subresource Integrity.
    assert "integrity=" in html
    assert "crossorigin=\"anonymous\"" in html
    # Google Fonts no ofrece SRI; debe cargar sin Peter's referrer ni dominios abiertos.
    assert "fonts.googleapis.com" in html