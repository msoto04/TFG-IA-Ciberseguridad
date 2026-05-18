from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from Src.core.database import Base


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    auditorias = relationship("Auditoria", back_populates="propietario")


class Auditoria(Base):
    __tablename__ = "auditorias"

    id = Column(String, primary_key=True, index=True)
    fecha = Column(DateTime, default=datetime.utcnow)
    nombre_archivo = Column(String)
    puntuacion = Column(Float)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

    propietario = relationship("Usuario", back_populates="auditorias")

    vulnerabilidades = relationship("Vulnerabilidad", back_populates="auditoria", cascade="all, delete-orphan")


class Vulnerabilidad(Base):
    __tablename__ = "vulnerabilidades"

    id = Column(Integer, primary_key=True, index=True)
    auditoria_id = Column(String, ForeignKey("auditorias.id"))
    nombre = Column(String)
    severidad = Column(String)
    archivo_afectado = Column(String)

    linea = Column(Integer, nullable=True)  # Línea exacta del fallo
    codigo_afectado = Column(String, nullable=True)  # Fragmento de código vulnerable
    referencias_legales = Column(String, nullable=True)  # Fuentes normativas (FAISS) usadas por la IA

    consulta_index = Column(String, nullable=True)

    modelo_llm = Column(String, nullable=True)  # Modelo LLM que tomó la decisión
    regla_semgrep = Column(String, nullable=True)  # Regla completa del motor SAST

    analisis_legal = Column(String)
    dominios_ens = Column(String, nullable=True)  # JSON con dominios ENS afectados

    auditoria = relationship("Auditoria", back_populates="vulnerabilidades")
