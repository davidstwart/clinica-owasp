# Plan de Pruebas — ISO/IEC 29119-2:2021

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Objetivos de la prueba

1. Verificar que el sistema cumple los requisitos funcionales de gestión de una clínica.
2. Verificar que los controles de seguridad derivados de OWASP Top 10 e ISO/IEC 27001 operan
   correctamente.
3. Verificar que la configuración del sistema se niega a arrancar en condiciones inseguras.
4. Obtener evidencia objetiva y reproducible de la consecución de los objetivos de calidad.
5. Detectar regresiones antes de cada entrega.

## 2. Alcance

### 2.1 Dentro del alcance

| Componente | Verificado por |
|---|---|
| Política de contraseñas | `test_01_politica_contrasenas.py` |
| Utilidades de seguridad (bcrypt, JWT, tiempo) | `test_02_seguridad_utilerias.py` |
| Validación de esquemas (Pydantic) | `test_03_validacion_esquemas.py` |
| API de autenticación y sesiones | `test_04_auth_api.py` |
| Control de acceso por rol | `test_05_rbac.py` |
| Reglas de negocio (pacientes, citas, atenciones) | `test_06_negocio.py` |
| Registro de auditoría | `test_07_auditoria.py` |
| Categorías OWASP Top 10 2021 | `test_08_owasp_a01_a10.py` |
| Cabeceras de seguridad HTTP | `test_09_cabeceras_seguridad.py` |
| Validación de configuración y secretos | `test_10_configuracion.py` |
| Gestión de cuentas de usuario | `test_11_usuarios.py` |
| Compilación del cliente React | Registro de compilación manual |

### 2.2 Fuera del alcance

| Elemento | Motivo |
|---|---|
| Pruebas de carga y de estrés | No se ha definido el volumen objetivo de usuarios (riesgo R-11) |
| Pruebas de usabilidad con usuarios | No se ha definido el perfil de usuario (riesgo R-13) |
| Auditoría de accesibilidad WCAG | Requiere evaluación externa (riesgo R-13) |
| Penetración externa | Requiere un despliegue real en producción |
| Pruebas sobre PostgreSQL | El entorno de pruebas usa SQLite en memoria por determinismo |
| Pruebas del cliente React | El proyecto usa `react-scripts` sin suite de pruebas configurada |

## 3. Estrategia de prueba (ISO/IEC 29119-2 §5)

### 3.1 Niveles

| Nivel | Objetivo | Archivos | Casos |
|---|---|---|---|
| Componente | Verificar funciones y módulos aislados | `test_01`, `test_02`, `test_03`, `test_10` | 74 |
| Integración | Verificar la interacción entre módulos, la API y la base de datos | `test_04`, `test_05`, `test_06`, `test_07`, `test_08`, `test_09`, `test_11` | 172 |
| Sistema | Verificación de extremo a extremo del flujo de negocio | Transversal a `test_06` | Incluido en 34 casos |
| Aceptación | Criterios de aceptación del usuario | Ver §6 | — |

### 3.2 Técnicas

| Técnica | Aplicación | Justificación |
|---|---|---|
| Equivalencia de clases | Validación de DNI, teléfono, fecha de nacimiento, estados de cita | Los datos de entrada se agrupan por comportamiento equivalente |
| Valores límite | Longitud de contraseña, paginación, longitud de búsqueda, DNI de 8 dígitos | Los errores se concentran en los límites |
| Tabla de decisión | Transiciones de estado de cita por rol | Combina rol × estado anterior × estado nuevo |
| Casos de uso | Flujo clínico completo: alta de paciente → cita → atención → historial | Verifica la integración de los módulos |
| Caja negra | Casos de OWASP Top 10, cabeceras, auditoría | Se observa el comportamiento externo |
| Caja blanca | `CP-RBAC-011`, `CP-RBAC-012` | Se verifica la estructura interna de las dependencias |
| Pruebas de configuración | `test_10_configuracion.py` en subproceso aislado | Se valida el comportamiento de arranque real |

### 3.3 Criterios de entrada y salida

**Entrada:** el código compila, el entorno de pruebas es reproducible y la versión está identificada.

**Salida:** todos los casos aprobados, cobertura ≥ 90 % y ninguna no conformidad abierta.

## 4. Entorno de pruebas (ISO/IEC 29119-2 §5.2.2)

| Elemento | Configuración |
|---|---|
| Base de datos | SQLite en memoria con `StaticPool`: aislamiento completo por caso y determinismo |
| Coste de bcrypt | 4 rondas (el valor de producción es 12; se reduce solo por tiempo de ejecución) |
| Límite de tasa | Desactivado en `testing` para que las pruebas de bloqueo midan el bloqueo de cuenta y no el limitador |
| Rotación de contraseña | **No se desactiva**: los datos de prueba se crean con la contraseña ya rotada |
| Secretos | Clave de pruebas declarada antes de importar la aplicación, mediante variable de entorno |
| Reloj | UTC uniforme mediante `common/time_utils.py` |
| Aislamiento | Una base de datos nueva por caso; `dependency_overrides` se limpia al finalizar |

### 4.1 Los datos de prueba

| Tipo | Suministro | Consideraciones |
|---|---|---|
| Credenciales | Contraseñas ficticias (`AdminDemo#2026`, etc.) | Nunca son reutilizables en producción |
| Pacientes | Nombres, DNI y teléfonos ficticios | No se utilizan datos reales de pacientes |
| Usuarios | Un usuario por rol | Cubre la matriz de permisos completa |

## 5. Cobertura

La cobertura de código se mide con `pytest-cov` y se almacena en `backend/docs_cobertura.json`.

| Módulo | Cobertura de líneas | Observación |
|---|---|---|
| `auth/security.py` | 97 % | Núcleo de autenticación y autorización |
| `auth/policy.py` | 97 % | Política de contraseñas |
| `auth/router.py` | 96 % | Ciclo de vida de cuentas |
| `auth/schemas.py` | 95 % | Contratos de entrada y salida |
| `auditoria/router.py` | 94 % | Consulta y resumen |
| `atenciones/router.py` | 94 % | Historia clínica |
| `pacientes/router.py` | 95 % | Pacientes |
| `citas/router.py` | 91 % | Agenda y transiciones |
| `citas/schemas.py` | 97 % | Validación de citas |
| `pacientes/schemas.py` | 96 % | Validación de pacientes |
| `middleware/security_headers.py` | 96 % | Cabeceras de seguridad |
| `middleware/request_context.py` | 85 % | Correlación de peticiones |
| `main.py` | 92 % | Aplicación y manejadores de error |
| `config.py` | 84 % | Validación de configuración |
| **Total de `src/`** | **93,59 %** | — |

Los módulos con cobertura inferior al 95 % corresponden a líneas de arranque (`if __name__ ==
"__main__"`), al formateo de listas y a ramas de error poco frecuentes, no a lógica de negocio sin
verificar. La cobertura de `config.py` aparece como 84 % porque sus validadores se ejercitan en un
subproceso aislado (`test_10_configuracion.py`), técnica necesaria para reconstruir la configuración
desde un entorno real controlado.

## 6. Criterios de aceptación

| # | Criterio | Meta | Resultado |
|---|---|---|---|
| AC-01 | Casos aprobados | 100 % | **246 de 246** |
| AC-02 | Cobertura de líneas de `src/` | ≥ 90 % | **93,59 %** |
| AC-03 | Casos de seguridad aprobados | 100 % | **104 de 104** |
| AC-04 | Casos de configuración que detectan arranque inseguro | ≥ 8 | **10** |
| AC-05 | Verificación de control de acceso en todas las rutas | 100 % | **100 %** |
| AC-06 | Compilación del cliente React | Sin errores | Correcta |

## 7. Procedimiento de ejecución

```bash
cd backend

# Suite completa con cobertura
./venv/bin/python -m pytest tests/ -v --cov=src --cov-report=term-missing

# Solo un nivel
./venv/bin/python -m pytest tests/ -m unit
./venv/bin/python -m pytest tests/ -m integration
./venv/bin/python -m pytest tests/ -m security

# Un módulo o un caso concreto
./venv/bin/python -m pytest tests/test_05_rbac.py
./venv/bin/python -m pytest tests/test_08_owasp_a01_a10.py -k "A01"
```

### 7.1 Marcadores

| Marcador | Significado |
|---|---|
| `unit` | Pruebas de componente sobre módulos aislados |
| `integration` | Pruebas que implican la API y la base de datos |
| `security` | Pruebas derivadas de OWASP Top 10 o de controles de ISO/IEC 27001 |

## 8. Suspension y reanudación

La ejecución se suspende y se escala si ocurre cualquiera de estas condiciones:

- Un fallo de conexión o de la base de datos impide obtener un resultado fiable.
- El fallo del código bajo prueba invalida las conclusiones de la prueba (por ejemplo, si no arranca
  la aplicación).
- Un fallo en la infraestructura de pruebas, no en el producto.

No se suspende ante un fallo del producto: se registra como defecto y se escala al responsable.

## 9. Entregables

| Entregable | Ubicación |
|---|---|
| Casos de prueba especificados | `docs/iso/29119-casos-de-prueba.md` |
| Informe de ejecución | `docs/iso/29119-informe-pruebas.md` |
| Informe de cobertura | `backend/docs_cobertura.json` |