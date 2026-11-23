from sqlalchemy import Column, Integer, DateTime, ForeignKey
from sqlalchemy.sql import func
from ..database import Base
from ..security.cifrado import TextoCifrado

class Atencion(Base):
    """A.8.24 — el contenido clínico (diagnóstico, tratamiento y observaciones)
    se almacena cifrado en reposo con AES-256-GCM."""

    __tablename__ = "atenciones"

    id            = Column(Integer, primary_key=True, index=True)
    paciente_id   = Column(Integer, ForeignKey("pacientes.id"), nullable=False)
    medico_id     = Column(Integer, ForeignKey("usuarios.id"),  nullable=False)
    cita_id       = Column(Integer, ForeignKey("citas.id"),     nullable=False)
    diagnostico   = Column(TextoCifrado, nullable=False)
    tratamiento   = Column(TextoCifrado, nullable=False)
    observaciones = Column(TextoCifrado, nullable=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
