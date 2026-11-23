"""
Esquemas de atención (historia clínica) — ISO/IEC 29119 (CP-ATE-*).
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class AtencionBase(BaseModel):
    paciente_id: int = Field(ge=1)
    # A.5.26 — la historia clínica se registra siempre sobre una cita: no hay
    # atenciones "huérfanas" fuera de la agenda clínica.
    cita_id: int = Field(ge=1)
    diagnostico: str = Field(min_length=3, max_length=2000)
    tratamiento: str = Field(min_length=3, max_length=2000)
    observaciones: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("diagnostico", "tratamiento")
    @classmethod
    def texto_normalizado(cls, v: str) -> str:
        v = " ".join(v.split())
        if len(v) < 3:
            raise ValueError("El campo debe tener al menos 3 caracteres")
        return v


class AtencionCreate(AtencionBase):
    pass


class AtencionResponse(AtencionBase):
    # Las atenciones históricas anteriores a la regla A.5.26 pueden no tener
    # cita asociada; la lectura las muestra igual en lugar de romper la API.
    cita_id: Optional[int] = Field(default=None, ge=1)
    id: int
    medico_id: int
    created_at: datetime

    class Config:
        from_attributes = True
