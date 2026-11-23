"""
OWASP A09:2021 — Fallos de Registro y Monitoreo de Seguridad
ISO/IEC 27001:2022 — A.8.15 Registro / A.8.16 Monitoreo de actividades

El registro de auditoría es **de solo agregado**: la aplicación no expone
ningún endpoint que modifique o elimine entradas (A.8.15 exige proteger el
registro frente a alteración).
"""
import enum

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func

from ..database import Base


class NivelLog(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    SECURITY = "SECURITY"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditoriaLog(Base):
    __tablename__ = "auditoria_logs"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id", ondelete="SET NULL"), nullable=True)
    accion = Column(String(100), nullable=False, index=True)
    nivel = Column(String(20), nullable=False, default=NivelLog.INFO.value, index=True)
    tabla_afectada = Column(String(100), nullable=True, index=True)
    registro_id = Column(Integer, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(200), nullable=True)
    detalle = Column(String(500), nullable=True)
    request_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
