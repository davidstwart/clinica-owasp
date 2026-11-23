# Sistema de Gestión de Calidad — ISO 9001:2015

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión del documento:** 1.0

---

## 1. Objetivo y alcance (ISO 9001 §4.3)

El objetivo del sistema de gestión de calidad es asegurar que el producto de software cumple los
requisitos especificados de forma consistente y evidenciable. El alcance comprende:

| Aspecto | Definición |
|---|---|
| Producto | API REST (FastAPI) e interfaz web (React) para la gestión de pacientes, citas, atenciones clínicas y usuarios |
| Ubicación | Servidor único del establecimiento de salud |
| Aplicabilidad | Parcial: los requisitos que no aplican están justificados en §7 |
| Partes interesadas | Dirección de la clínica, médicos, recepción, personal de sistemas, pacientes |
| Marco legal aplicable | Ley N.º 29733 (Protección de Datos Personales, Perú) y Ley N.º 26842 (Ley del DATASUS) |

## 2. Contexto de la organización (ISO 9001 §4.1)

El proyecto parte de un sistema preexistente en el que se identificaron brechas frente a
OWASP Top 10 y ausencia de procesos de verificación formal. La necesidad detectada es de carácter
**preventivo**: reducir la exposición de datos clínicos sensibles antes de que el sistema se ponga en producción.

## 3. Leadership (ISO 9001 §5)

- **Responsabilidad:** la persona responsable del proyecto planifica, asigna recursos y rinde
  cuentas sobre el estado de las acciones correctivas.
- **Orientación al paciente:** la trazabilidad de la historia clínica y la prohibición de eliminar
  pacientes con historial atendido responden al interés del paciente por la integridad de su
  expediente (control A.5.33).
- **Estructura organizacional:** los procesos, sus entradas, salidas, responsables e indicadores se
  definen en `9001-mapa-procesos.md`.

## 4. Planificación (ISO 9001 §6.1)

### 4.1 Acciones frente a riesgos y oportunidades

| Riesgo u oportunidad | Acción definida | Evidencia |
|---|---|---|
| Exposición de datos clínicos | Implementar controles de seguridad verificables | `27001-evaluacion-riesgos.md`, `tests/test_08_owasp_a01_a10.py` |
| Regresiones de autorización | Matriz de permisos automatizada, de caja negra y blanca | `tests/test_05_rbac.py` |
| Pérdida de historia clínica | Borrado lógico y bloqueo de eliminación con historial | `tests/test_06_negocio.py` |
| Incidentes no detectables | Registro de auditoría con correlación por petición | `tests/test_07_auditoria.py` |
| Configuración insegura en producción | Arranque *fail-closed* de la configuración | `tests/test_10_configuracion.py` |
| Entregas sin evidencia | Informe de pruebas con cobertura medida | `29119-informe-pruebas.md` |

### 4.2 Objetivos de calidad y su medición

| Objetivo | Indicador | Meta | Resultado medido | Evidencia |
|---|---|---|---|---|
| Reducir la superficie expuesta | Endpoints con control de acceso verificado | 100 % | 100 % | CP-RBAC-011 |
| Cobertura de reglas de negocio | Casos de negocio automatizados | ≥ 25 | 34 | `test_06_negocio.py` |
| Fiabilidad del producto | Casos de prueba aprobados | 100 % | 246/246 | Informe de pruebas |
| Mantenibilidad | Cobertura de líneas | ≥ 90 % | 93,59 % | Informe de cobertura |
| Verificación de la interfaz | Compilación sin errores de ESLint | Correcta | Correcta | Registro de compilación |
| Detección de incidentes | Casos de seguridad aprobados | 100 % | 104/104 | Marcador `security` |

## 5. Soporte (ISO 9001 §7)

### 5.1 Recursos

- **Tecnológicos:** Python 3.14.7, FastAPI, SQLAlchemy 2.0, PostgreSQL en producción, SQLite en
  pruebas, React 19.
- **Entorno de pruebas:** `backend/venv`, con dependencias fijadas en `requirements-dev.txt`.
- **Repositorio:** control de versiones que conserva el historial auditable de cada cambio.

### 5.2 Competencias del personal

Las competencias requeridas (desarrollo seguro, modelado de datos clínicos, diseño de pruebas
basadas en riesgo) se acreditan mediante la suite de pruebas automatizadas, que constituye
evidencia objetiva de capacidad técnica.

### 5.3 Comunicación

- Resultados de verificación e informe de pruebas en `docs/iso/`.
- Registro de auditoría de la aplicación para el seguimiento operativo (A.8.15).

### 5.4 Información documentada

Este conjunto de documentos constituye la información documentada requerida por la norma,
organizada por estándar en el índice de `docs/iso/README.md`.

## 6. Operación (ISO 9001 §8)

### 6.1 Requisitos del producto

- **Funcionales:** autenticación y gestión de sesiones, pacientes, agenda de citas, historia
  clínica, gestión de usuarios, auditoría.
- **No funcionales:** seguridad (ver `25000-calidad-producto.md`), rendimiento (paginación
  obrigatória y límites por consulta), usabilidad (validación en el borde con mensajes útiles),
  mantenibilidad (arquitectura por capas y configuración centralizada validada).
- **Trazabilidad:** cada requisito funcional se vincula a casos de prueba en
  `29119-casos-de-prueba.md`.

### 6.2 Diseño y desarrollo

- **Arquitectura por capas:** *routers* (transporte), *schemas* (validación de entrada),
  *services* (lógica de negocio), *models* (persistencia), *middleware* (controles transversales).
- **Seguridad por diseño:** los controles se derivan de OWASP ASVS y se incorporan antes de la
  implementación, no como parche posterior.
- **Revisión:** cada cambio funcional incorpora sus casos de prueba en la misma entrega.

### 6.3 Verificación

Verificación automatizada con `pytest`. Criterios de aceptación y resultados:

| Criterio | Umbral | Resultado |
|---|---|---|
| Casos aprobados | 100 % | **246 de 246** |
| Cobertura de líneas | ≥ 90 % | **93,59 %** |
| Casos de seguridad | 100 % | **104 de 104** |
| Compilación del frontend | Sin errores | Correcta |

Detalle en `29119-informe-pruebas.md`.

### 6.4 No conformidades y acción correctiva

Durante el desarrollo se detectaron cuatro no conformidades que se corrigieron y quedaron
protegidas por pruebas de regresión:

| Id. | Descripción | Severidad | Corrección | Prueba de regresión |
|---|---|---|---|---|
| NC-01 | La respuesta de login distinguía entre correo inexistente y contraseña incorrecta, permitiendo enumerar cuentas | Media | Hash señuelo y mensaje genérico | `CP-AUT-005`, `CP-OWASP-A07-002` |
| NC-02 | Dependencias de autorización sin anotación de tipo (`_=todos`) no se registraban en FastAPI, dejando endpoints sin autenticar | **Crítica** | Se anotan como `Depends(...)` y se añade verificación estructural de todas las rutas | `CP-RBAC-011`, `CP-RBAC-012` |
| NC-03 | El `SECRET_KEY` de ejemplo de `.env.example` era aceptado por la validación, permitiendo arrancar con un secreto conocido | Alta | Se añadió a la lista de secretos prohibidos | `CP-CFG-016` |
| NC-04 | La CSP de la API no declaraba `script-src` ni `object-src` de forma explícita | Baja | Directivas explícitas de bloqueo | `CP-SEC-001` |

Detalle de cada una en `29119-informe-pruebas.md` §6.

### 6.5 Control de los cambios

- **Configuración:** `src/config.py` rechaza valores inseguros en producción, lo que impide
  desplegar con ajustes por omisión débiles (`tests/test_10_configuracion.py`).
- **Esquema de datos:** no se emplea Alembic; las alteraciones de esquema requieren recrear la base
  de datos. Registrado como riesgo `R-12` en `27001-evaluacion-riesgos.md`.

## 7. Requisitos no aplicables y aplicado por equivalencia (ISO 9001 §7.1.3)

### 7.1 Requisitos no aplicables

| Requisito | Justificación |
|---|---|
| §8.4.1.2 Control de procesos subcontratados | No hay procesos subcontratados: el desarrollo, la operación y el mantenimiento son internos al proyecto. |
| §8.7.1.2 Control de las entradas de proveedores | No se consumen productos ni servicios de proveedores externos en el proceso de realización. |
| §9.1.2 Satisfacción del cliente | No existe un mecanismo de medición de la satisfacción del paciente; no se aplica al alcance actual. |

### 7.2 Requisitos aplicados por equivalencia

Estos requisitos sí son exigibles, pero se satisfacen mediante prácticas propias del proyecto en
lugar del procedimiento prescrito por la norma.

| Requisito | Equivalencia aplicada | Evidencia |
|---|---|---|
| §8.2.3.2 Determinación de los requisitos de entrada | Los requisitos funcionales, no funcionales y regulatorios se detallan en `9001-trazabilidad.md` y se validan antes de implementar | `9001-trazabilidad.md` |
| §8.5.2 Identificación y trazabilidad | Trazabilidad requisito → control → caso de prueba, y registro de auditoría de las operaciones | `9001-trazabilidad.md`, `test_07_auditoria.py` |
| §8.6 Releases de los productos y servicios | Cada incremento de código se acompaña de su suite de pruebas y su informe | `29119-informe-pruebas.md` |

## 8. Documentos relacionados

- `9001-politica-calidad.md` — política y objetivos
- `9001-mapa-procesos.md` — procesos, responsables e indicadores
- `9001-trazabilidad.md` — matriz requisito → control → prueba
- `25000-calidad-producto.md` — modelo de calidad de producto (ISO/IEC 25010)
- `27001-politica-seguridad.md` — política y arquitectura de seguridad
- `27001-evaluacion-riesgos.md` — análisis de riesgos (ISO/IEC 27005)
- `27001-declaracion-aplicabilidad.md` — declaración de aplicabilidad (SoA)
- `27001-matriz-owasp-iso.md` — matriz OWASP ↔ controles ↔ pruebas
- `29119-plan-de-pruebas.md` — estrategia y condiciones de prueba
- `29119-casos-de-prueba.md` — especificación de casos
- `29119-informe-pruebas.md` — resultados, cobertura y no conformidades