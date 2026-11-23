"""
Esquemas de paciente — ISO/IEC 29119 (CP-PAC-*).

ISO/IEC 25010 — Idoneidad funcional: los datos del paciente se validan en el
borde (no solo en la base de datos) para devolver mensajes de error útiles.
"""
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class PacienteBase(BaseModel):
    nombres: str = Field(min_length=2, max_length=100)
    apellidos: str = Field(min_length=2, max_length=100)
    dni: str = Field(min_length=8, max_length=8)
    fecha_nacimiento: Optional[date] = None
    telefono: Optional[str] = Field(default=None, max_length=15)
    direccion: Optional[str] = Field(default=None, max_length=255)
    email: Optional[EmailStr] = Field(default=None, max_length=150)

    @field_validator("dni")
    @classmethod
    def dni_valido(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("El DNI debe contener solo dígitos")
        return v

    @field_validator("nombres", "apellidos")
    @classmethod
    def sin_espacios_extremos(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("El campo no puede quedar vacío")
        return v

    @field_validator("telefono")
    @classmethod
    def telefono_valido(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not v.replace(" ", "").isdigit():
            raise ValueError("El teléfono debe contener solo dígitos")
        if not 7 <= len(v.replace(" ", "")) <= 15:
            raise ValueError("El teléfono debe tener entre 7 y 15 dígitos")
        return v

    @field_validator("fecha_nacimiento")
    @classmethod
    def fecha_valida(cls, v: date | None) -> date | None:
        if v is None:
            return None
        hoy = date.today()
        if v > hoy:
            raise ValueError("La fecha de nacimiento no puede ser futura")
        if v.year < 1900:
            raise ValueError("La fecha de nacimiento es anterior a 1900")
        if (hoy - v).days > 365 * 130:
            raise ValueError("La edad del paciente supera los 130 años")
        return v


class PacienteCreate(PacienteBase):
    pass


class PacienteUpdate(PacienteBase):
    """Actualización completa (PUT) con las mismas reglas que el alta."""


class PacienteResponse(PacienteBase):
    id: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
