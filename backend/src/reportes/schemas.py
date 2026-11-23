"""
Reportes gerenciales — ISO/IEC 27001 A.5.34 (protección de registros) y
A.8.15 (registro de actividades). Emisión y validación firmada de reportes.
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ReporteResumen(BaseModel):
    """Indicadores consolidados para la dirección de la clínica."""

    generado_en: datetime
    pacientes: dict[str, int]
    citas: dict[str, int]
    atenciones: dict[str, int]
    usuarios: dict[str, int]
    auditoria_24h: dict[str, int]


class ValidacionReporteRequest(BaseModel):
    """El reporte emitido se recibe tal cual para sellarlo con SHA-256."""

    reporte: dict[str, Any] = Field(min_length=1)


class ValidacionReporteResponse(BaseModel):
    """A.8.15 — el sello permite demostrar después qué versión del reporte se
    revisó y quién la validó."""

    accion: str = "VALIDAR_REPORTE"
    hash_sha256: str
    registrado_en: datetime
