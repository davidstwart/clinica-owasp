from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Columnas añadidas en revisiones posteriores al primer despliegue.
# `create_all` solo crea tablas nuevas, así que una base existente se
# actualiza con ALTER TABLE idempotentes (A.8.32 / A.8.34).
COLUMNAS_NUEVAS = {
    "usuarios": {"mfa_secreto": "TEXT", "mfa_habilitado": "BOOLEAN DEFAULT FALSE"},
}


def asegurar_esquema(motor=None):
    """Asegura que existan las columnas de las últimas revisiones. Idempotente."""
    motor = motor or engine
    for tabla, columnas in COLUMNAS_NUEVAS.items():
        if tabla not in inspect(motor).get_table_names():
            continue
        existentes = {c["name"] for c in inspect(motor).get_columns(tabla)}
        with motor.begin() as conn:
            for columna, tipo in columnas.items():
                if columna not in existentes:
                    conn.execute(text(f"ALTER TABLE {tabla} ADD COLUMN {columna} {tipo}"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
