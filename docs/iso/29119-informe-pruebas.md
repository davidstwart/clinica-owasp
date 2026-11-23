# Informe de Pruebas — ISO/IEC 29119-2:2021 §6.3

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión del producto:** 1.0
**Fecha de ejecución:** 2026-10-01 05:35 UTC
**Ejecutado por:** responsable del proyecto
**Plan de pruebas:** `29119-plan-de-pruebas.md`

---

## 1. Resumen ejecutivo

La suite completa se ejecutó y **los 246 casos fueron aprobados**. No se registraron fallos, errores
ni casos omitidos. La cobertura de líneas del código de aplicación (`src/`) alcanza el **93,59 %**,
por encima del umbral de aceptación del 90 %.

| Métrica | Valor |
|---|---|
| Casos ejecutados | **246** |
| Casos aprobados | **246** |
| Casos fallidos | 0 |
| Casos con error | 0 |
| Casos omitidos | 0 |
| Tasa de éxito | **100 %** |
| Tiempo de ejecución | 19,52 s |
| Cobertura de líneas de `src/` | **93,59 %** (967 sentencias, 62 sin cubrir) |
| Warnings | 1 (dependencia transitiva ajena al proyecto) |

**Conclusión:** el producto cumple los criterios de aceptación definidos en el plan de pruebas y
está en condiciones de superar la revisión de calidad del ciclo de desarrollo actual. Los riesgos
residuales que impiden la puesta en producción están documentados en
`27001-evaluacion-riesgos.md` y en el §6 de este informe.

## 2. Alcance ejecutado

| # | Componente | Casos | Estado |
|---|---|---|---|
| 1 | Política de contraseñas | 14 | Correcto |
| 2 | Utilidades de seguridad (bcrypt, JWT) | 16 | Correcto |
| 3 | Validación de esquemas de entrada | 25 | Correcto |
| 4 | API de autenticación y sesiones | 20 | Correcto |
| 5 | Control de acceso por rol | 39 | Correcto |
| 6 | Reglas de negocio (pacientes, citas, atenciones) | 34 | Correcto |
| 7 | Registro de auditoría | 16 | Correcto |
| 8 | OWASP Top 10 2021 (A01–A10) | 34 | Correcto |
| 9 | Cabeceras de seguridad HTTP | 15 | Correcto |
| 10 | Configuración y gestión de secretos | 19 | Correcto |
| 11 | Gestión de cuentas de usuario | 14 | Correcto |
| | **Total** | **246** | **Correcto** |

## 3. Resultados por categoría de prueba

| Marcador | Casos | Aprobados | Fallidos | Tasa |
|---|---|---|---|---|
| `unit` | 74 | 74 | 0 | 100 % |
| `integration` | 172 | 172 | 0 | 100 % |
| `security` | 104 | 104 | 0 | 100 % |

## 4. Resultados por estándar de referencia

| Estándar | Aspecto verificado | Casos asociados | Estado |
|---|---|---|---|
| OWASP A01 | Control de acceso roto | 39 (RBAC) + 5 (A01) | Mitigado |
| OWASP A02 | Fallos criptográficos | 16 (SEG) + 3 (A02) | Mitigado |
| OWASP A03 | Inyección | 6 | Mitigado |
| OWASP A04 | Diseño inseguro | 3 + 2 (validación) | Mitigado |
| OWASP A05 | Misconfiguración | 19 (CFG) + 2 (A05) | Mitigado |
| OWASP A06 | Componentes vulnerables | 3 | Parcial (riesgo R-14) |
| OWASP A07 | Fallos de autenticación | 20 (AUT) + 5 (A07) | Mitigado |
| OWASP A08 | Fallos de integridad | 3 (A08) + 7 (NEG) + 2 (AUD) | Mitigado |
| OWASP A09 | Registro insuficiente | 16 (AUD) + 3 (A09) | Mitigado |
| OWASP A10 | SSRF | 1 | No aplica |
| ISO/IEC 29119 | Casos de negocio y validación | 59 | Correcto |
| ISO/IEC 27001 | Configuración y cabeceras | 34 | Correcto |

## 5. Cobertura de código

Cobertura global de `src/`: **93,59 %** (905 de 967 sentencias, 62 sin ejecutar). Los 20 módulos con
cobertura inferior al 100 % son los siguientes:

| Módulo | Cobertura | Líneas cubiertas |
|---|---|---|
| `auth/security.py` | 97,3 % | 73/75 |
| `auth/policy.py` | 97,2 % | 35/36 |
| `citas/schemas.py` | 97,1 % | 33/34 |
| `pacientes/schemas.py` | 96,3 % | 52/54 |
| `auth/router.py` | 96,0 % | 120/125 |
| `middleware/security_headers.py` | 95,7 % | 22/23 |
| `pacientes/router.py` | 95,2 % | 60/63 |
| `auth/schemas.py` | 95,1 % | 58/61 |
| `auditoria/router.py` | 94,3 % | 33/35 |
| `atenciones/router.py` | 93,8 % | 45/48 |
| `main.py` | 92,2 % | 71/77 |
| `citas/router.py` | 91,4 % | 74/81 |
| `middleware/request_context.py` | 84,8 % | 28/33 |
| `config.py` | 83,8 % | 62/74 |
| `database.py` | 66,7 % | 8/12 |
| `common/time_utils.py` | 44,4 % | 4/9 |

Los 20 módulos restantes —modelos, esquemas de pacientes, citas, atenciones, auditoría y
`service.py`— alcanzan el 100 % de cobertura de líneas.

### 5.1 Análisis de las brechas de cobertura

Ninguna brecha oculta lógica de negocio sin verificar. Las líneas sin cubrir corresponden a:

| Ubicación | Motivo |
|---|---|
| `common/time_utils.py` (44,4 %) | Funciones de conversión de zona horaria no invocadas por la suite; el flujo operativo usa UTC de forma uniforme |
| `database.py` (66,7 %) | Code de arranque del servidor y conexión real a PostgreSQL, no ejercitado por el SQLite en memoria |
| `config.py` (83,8 %) | Los validadores se ejecutan en un subproceso, por lo que no se contabilizan en el informe del proceso principal |
| `middleware/request_context.py` (84,8 %) | Ramas de fallo del generador de `request_id` |
| `main.py` (92,2 %) | Bloque de ejecución directa `uvicorn` y algún manejador de excepción poco frecuente |
| Routers (91–96 %) | Mensajes de error de casos ya validados en los esquemas |

La cobertura real de `config.py` es superior a la reportada: los 19 casos de
`test_10_configuracion.py` validan sus validadores mediante un subproceso aislado, técnica
necesaria para que la configuración se construya realmente desde un entorno controlado.

## 6. No conformidades detectadas y su estado

Durante el desarrollo se detectaron cuatro no conformidades. Las cuatro están cerradas y cubiertas
por pruebas de regresión.

| Id. | Descripción | Severidad | Estado | Regresión |
|---|---|---|---|---|
| NC-01 | El mensaje de login distinguía entre correo inexistente y contraseña incorrecta, permitiendo enumerar cuentas | Media | **Cerrada** | `CP-AUT-005`, `CP-OWASP-A07-002` |
| NC-02 | Las dependencias de autorización declaradas como `_=todos` sin anotación de tipo no se registraban en FastAPI; varios endpoints quedaban accesibles sin sesión | **Crítica** | **Cerrada** | `CP-RBAC-011`, `CP-RBAC-012` |
| NC-03 | El valor de ejemplo de `SECRET_KEY` en `.env.example` era aceptado por la validación, permitiendo arrancar con un secreto conocido | Alta | **Cerrada** | `CP-CFG-016` |
| NC-04 | La CSP de la API no declaraba `script-src` ni `object-src` de forma explícita | Baja | **Cerrada** | `CP-SEC-001` |

### 6.1 Detalle de NC-02 (crítica)

**Descripción.** En cinco módulos se declararon las dependencias de autorización con la forma
`_=todos` o `_=solo_admin`, sin anotación de tipo. FastAPI interpreta un parámetro sin anotación como
un parámetro de consulta, por lo que **la dependencia nunca se registraba** y el endpoint quedaba sin
control de autenticación.

**Detección.** El caso `CP-AUT-017` (cuenta pendiente de rotación) esperaba 403 y obtuvo 200. La
inspección del grafo de dependencias de la ruta reveló que el único `dependant` registrado era
`get_db`.

**Alcance afectado.** `pacientes/router.py`, `citas/router.py`, `atenciones/router.py`,
`auditoria/router.py` y `auth/router.py`.

**Acción correctiva.** Se annotaron las dependencias como `_usuario=Depends(...)`.

**Prevención de recaída.** Se añadieron dos casos de caja blanca:

- `CP-RBAC-011` recorre el `dependant` de todas las rutas de la API y falla si alguna no declara
  una cadena de dependencias de seguridad.
- `CP-RBAC-012` verifica que la cadena `usuario_operativo` → `obtener_usuario_actual` quede
  registrada como subdependencia de la autorización.

## 7. Verificación del cliente React

| Aspecto | Resultado |
|---|---|
| Compilación de producción | Correcta |
| Errores de ESLint | Ninguno |
| Advertencias | Ninguna |
| Tamaño del paquete JavaScript (gzip) | 103,85 kB |
| Tamaño de la hoja de estilos (gzip) | 2,81 kB |

La compilación se ejecutó con `node node_modules/react-scripts/bin/react-scripts.js build`. El
cliente incorpora CSP declarativa y Subresource Integrity, verificados por `CP-SEC-015` y
`CP-OWASP-A06-002`.

## 8. Evaluación frente a los objetivos de calidad

| Objetivo | Meta | Resultado | Estado |
|---|---|---|---|
| O1 Endpoints con control de acceso verificado | 100 % | 100 % | **Cumplido** |
| O2 Casos de prueba de integridad de datos clínicos | ≥ 10 | 10 | **Cumplido** |
| O3 Casos aprobados | 100 % | 246/246 | **Cumplido** |
| O4 Cobertura de líneas | ≥ 90 % | 93,59 % | **Cumplido** |
| O5 Casos de seguridad aprobados | 100 % | 104/104 | **Cumplido** |
| O6 Casos de fallo de configuración detectados | ≥ 8 | 10 | **Cumplido** |
| O7 Compilación del cliente | Correcta | Correcta | **Cumplido** |

## 9. Limitaciones y trabajo pendiente

La aprobación de esta ejecución se refiere a los criterios definidos en el plan de pruebas. Los
siguientes elementos **no están cubiertos** y deben resolverse antes de la puesta en producción:

| # | Elemento | Riesgo | Prioridad |
|---|---|---|---|
| 1 | Migraciones de esquema (Alembic): `create_all` no altera tablas existentes | R-12 | Alta |
| 2 | Copia de seguridad automatizada y definición de RTO/RPO | R-10 | Alta |
| 3 | Migración de la sesión a cookie `HttpOnly` con protección CSRF | R-03, R-08 | Media |
| 4 | `pip-audit` y `npm audit` en integración continua | R-14 | Media |
| 5 | Pruebas de carga y de estrés | R-11 | Media |
| 6 | Auditoría de accesibilidad WCAG 2.1 AA | R-13 | Baja |
| 7 | Pruebas del cliente React (proyecto sin suite de pruebas) | — | Media |
| 8 | Verificación de la suite contra PostgreSQL real | R-12 | Media |
| 9 | Cadena de hash del registro de auditoría (descartada por riesgo de concurrencia) | R-09 | Baja |

## 10. Conclusión de la verificación

Con base en la evidencia obtenida:

1. Los 246 casos de prueba definidos se ejecutaron y aprobaron, sin fallos ni casos omitidos.
2. La cobertura del código de aplicación alcanza el 93,59 %, superó el umbral del 90 %.
3. Las diez categorías de OWASP Top 10 2021 cuentan con control implementado y prueba de
   verificación.
4. Las cuatro no conformidades detectadas durante el desarrollo están cerradas, con prueba de
   regresión asociada.
5. Persisten nueve elementos de trabajo pendiente, cuantificados como riesgos residuales.

El producto **supera los criterios de aceptación del ciclo actual**. La puesta en producción
requiere cerrar, como mínimo, los elementos 1 y 2 del §9, dado que afectan a la integridad de los
datos y a la disponibilidad del servicio.

---

**Reproducibilidad**

```bash
cd backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt -r requirements-dev.txt
./venv/bin/python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

**Evidencia generada:** `backend/docs_cobertura.json`