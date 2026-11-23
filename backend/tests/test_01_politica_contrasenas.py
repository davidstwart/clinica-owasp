"""
Pruebas unitarias — Política de contraseñas.
ISO/IEC 29119-2 nivel componente · ISO/IEC 27001:2022 A.5.17

Casos: CP-POL-001 … CP-POL-012
"""
import pytest

from src.auth.policy import (
    CONTRASENAS_PROHIBIDAS,
    contrasena_es_valida,
    evaluar_contrasena,
)

pytestmark = pytest.mark.unit

CONTRASENA_VALIDA = "Huancayo#Root2026"


# ── Casos positivos ──────────────────────────────────────────────────────────
def test_CP_POL_001_contrasena_conformante_se_acepta():
    assert evaluar_contrasena(CONTRASENA_VALIDA) == []
    assert contrasena_es_valida(CONTRASENA_VALIDA) is True


def test_CP_POL_002_contrasena_valida_es_indiferente_al_correo_no_relacionado():
    assert contrasena_es_valida(CONTRASENA_VALIDA, "medico@clinica.pe") is True


# ── Casos negativos por regla ────────────────────────────────────────────────
def test_CP_POL_003_rechaza_cortas():
    fallos = evaluar_contrasena("Ab1c")
    assert any("al menos 8 caracteres" in f for f in fallos)


def test_CP_POL_004_rechaza_sin_mayuscula():
    fallos = evaluar_contrasena("huancayo#root2026")
    assert any("mayúscula" in f for f in fallos)


def test_CP_POL_005_rechaza_sin_minuscula():
    fallos = evaluar_contrasena("HUANCAYO#ROOT2026")
    assert any("minúscula" in f for f in fallos)


def test_CP_POL_006_rechaza_sin_digito():
    fallos = evaluar_contrasena("HuancayoRoot#")
    assert any("dígito" in f for f in fallos)


def test_CP_POL_007_rechaza_contrasenas_comprometidas():
    for contrasena in ("password", "12345678", "qwerty123"):
        assert not contrasena_es_valida(contrasena), contrasena
    assert any("comprometidas" in f for f in evaluar_contrasena("password"))


def test_CP_POL_008_rechaza_reutilizar_parte_del_correo():
    """A.5.17 — la contraseña no debe derivarse de la identidad del usuario."""
    fallos = evaluar_contrasena("Root2026Admin", "admin@clinica.pe")
    assert any("correo electrónico" in f for f in fallos)


def test_CP_POL_009_no_rechaza_si_no_hay_correo():
    assert evaluar_contrasena("Admin2026Root", None) == []


def test_CP_POL_010_rechaza_caracteres_repetidos():
    fallos = evaluar_contrasena("Aaaaaaaa1")
    assert any("idénticos consecutivos" in f for f in fallos)


def test_CP_POL_010b_rechaza_secuencias_de_teclado():
    assert any("secuencias triviales" in f for f in evaluar_contrasena("Qwerty#2026"))
    assert any("secuencias triviales" in f for f in evaluar_contrasena("Huancayo#9876"))


def test_CP_POL_011_rechaza_vacia():
    assert evaluar_contrasena("") == ["La contraseña no puede estar vacía"]


def test_CP_POL_012_rechaza_supera_limite_bcrypt():
    # bcrypt trunca silenciosamente a 72 bytes: un límite mayor permitiría que
    # dos contraseñas distintas produzcan el mismo hash.
    fallos = evaluar_contrasena("A1a" + "x" * 100)
    assert any("no puede superar" in f for f in fallos)


def test_CP_POL_013_lista_de_comprometidas_no_incluye_contrasenas_conformes():
    assert CONTRASENA_VALIDA.lower() not in CONTRASENAS_PROHIBIDAS
