"""
Esquemas de cita — ISO/IEC 29119 (CP-CIT-*).
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .models import EstadoCita


class CitaBase(BaseModel):
    paciente_id: int = Field(ge=1)
    medico_id: int = Field(ge=1)
    fecha_hora: datetime
    motivo: str = Field(min_length=5, max_length=255)
    observaciones: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("motivo")
    @classmethod
    def motivo_normalizado(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("El motivo no puede quedar vacío")
        return v

    @model_validator(mode="after")
    def fecha_coherente(self):
        if self.fecha_hora.year < 2000:
            raise ValueError("La fecha de la cita no puede ser anterior al año 2000")
        return self


class CitaCreate(CitaBase):
    pass


class CitaEstadoUpdate(BaseModel):
    """CP-CIT-004 — transición de estado validada (A.4 validación de entrada)."""

    estado: EstadoCita

    @field_validator("estado")
    @classmethod
    def estado_valido(cls, v):
        if v == EstadoCita.pendiente:
            raise ValueError(
                "'pendiente' es el estado inicial; use 'confirmada' para registrar la cita"
            )
        return v


class CitaResponse(CitaBase):
    id: int
    estado: EstadoCita
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
