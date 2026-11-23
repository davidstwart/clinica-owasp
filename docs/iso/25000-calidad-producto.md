# Calidad del Producto de Software — ISO/IEC 25000 (ISO/IEC 25010:2023)

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Encuadre

ISO/IEC 25000 es la serie de requisitos y evaluación de la calidad del producto de software. Su
parte central, **ISO/IEC 25010:2023**, define nueve características de calidad que este documento
descompone en subcaracterísticas aplicables al sistema.

El objetivo no es declarar los nueve niveles como "cumplidos", sino declarar con precisión qué
está medido, cómo y con qué evidencia, y señalar con honestidad las brechas conocidas.

## 2. Modelo de calidad aplicado

### 2.1 Adecuación funcional

| Subcaracterística | Aplicación en el sistema | Evidencia |
|---|---|---|
| Compleción funcional | Los módulos de pacientes, citas, atenciones, usuarios, auditoría y autenticación están implementados con sus operaciones de alta, consulta, edición y baja donde corresponde | 12 requisitos funcionales trazados en `9001-trazabilidad.md` |
| Corrección funcional | Las reglas de negocio se validan en el servidor: existencia de referencias, no solapamiento de agenda, límite de 16 citas diarias, máquina de estados, integridad paciente–cita | 34 casos en `test_06_negocio.py`, todos aprobados |
| Adecuación al propósito | El sistema cubre el flujo real de una clínica: registro del paciente, agenda, consulta y cierre con historia clínica | Casos de negocio de extremo a extremo (CP-NEG-001 a CP-NEG-034) |

### 2.2 Eficiencia de rendimiento

| Subcaracterística | Medida | Resultado |
|---|---|---|
| Comportamiento temporal en el tiempo | Toda colección está paginada con límite superior (`le=200`), lo que acota el trabajo por petición | Verificado en CP-NEG-007 y CP-OWASP-A04-003 |
| Utilización de recursos | Índices en columnas de clave primaria y de búsqueda; consultas parametrizadas por el ORM | Sin consultas N+1 en los listados; el historial se ordena por índice |
| Capacidad | El límite de agenda por médico y día protege la disponibilidad del profesional | `CP-NEG-019` (máximo 16 citas) |
| Tiempo de respuesta *(indicativo)* | Suite completa de 246 casos en ~19 s en SQLite en memoria; 1 caso ≈ 77 ms de media | Medición del entorno de pruebas, no de producción |

> **Brecha declarada:** no se han realizado pruebas de carga ni de estrés con usuarios
> concurrentes. La scalability con PostgreSQL y el comportamiento bajo carga simultánea quedan
> pendientes de medición (riesgo `R-11`).

### 2.3 Compatibilidad

| Subcaracterística | Medida |
|---|---|
| Compatibilidad entre productos | El cliente React se despliega como origen independiente; la API declara `ALLOWED_ORIGINS` como lista blanca |
| Compatibilidad entre versiones | El token JWT incorpora `iss` y `aud`, lo que impide reutilizarlo en otro despliegue; la versión del esquema viaja en la cabecera del token |
| Fin de vida | `react-scripts 5.0.1` está en mantenimiento limitado; su retirada se planificará hacia Vite + React Router |

### 2.4 Usabilidad

| Subcaracterística | Aplicación |
|---|---|
| Comprensibilidad | Mensajes de error en español y orientados a la acción ("Ya existe un paciente con ese DNI", "Debe actualizar su contraseña antes de continuar") |
| Aprendibilidad | Pantalla de cambio de contraseña obligatoria tras el primer inicio de sesión, que explica el motivo del bloqueo |
| Operabilidad | Código de error en cabecera (`X-Auth-Error-Code`) para que la interfaz actúe sin interpretar el texto |
| Protección frente a errores | Validación en el borde, mensajes específicos por campo y bloqueo de operaciones inválidas en el servidor |
| Accesibilidad | Formularios semánticos y contraste adecuado en la interfaz |

> **Brecha declarada:** no se ha realizado una evaluación de accesibilidad conforme a WCAG 2.1
> con usuarios reales ni pruebas de usabilidad. Riesgo `R-13`.

### 2.5 Fiabilidad

| Subcaracterística | Medida |
|---|---|
| Madurez | **246 de 246 casos aprobados (100 %)**; cobertura de líneas del 93,59 % |
| Tolerancia a fallos | La escritura del registro de auditoría es tolerante a fallos: un fallo de auditoría no impide la operación clínica, pero se registra el incidente |
| Recuperabilidad | El bloqueo de cuenta es temporal (15 minutos) y se libera automáticamente; el administrador puede restablecer la contraseña, lo que revoca las sesiones activas |
| Analizabilidad | Cada respuesta lleva `X-Request-ID`; el log de auditoría correlaciona evento, recurso, IP y agente |

### 2.6 Seguridad

Es la característica con mayor densidad de evidencia. Detalle completo en
`27001-matriz-owasp-iso.md`.

| Subcaracterística | Controles implementados | Casos |
|---|---|---|
| Autenticidad | bcrypt, bloqueo por intentos, anti-enumeración, rotación obligatoria, revocación por `jti` y `token_version` | 20 + 5 |
| Integridad | Allow-list de campos en toda entrada; reglas de negocio en el servidor; integridad referencial verificada | 20 |
| No repudio | Registro de auditoría *append-only* con autor, fecha, recurso, IP y nivel | 16 |
| Confidencialidad | Controles de acceso por rol, rotación de secretos, cabeceras de seguridad, sin datos clínicos en respuestas de listado | 39 + 15 |
| Determinación | Configuración *fail-closed*: el arranque se rechaza con valores inseguros | 16 |

### 2.7 Mantenibilidad

| Subcaracterística | Medida |
|---|---|
| Modularidad | Arquitectura por capas; un módulo deConcern sin dependencia funcional de otro |
| Reutilización | Política de contraseñas, `obtener_usuario_actual`, `registrar_log` y `obtener_request_id` centralizados y reutilizados |
| Analizabilidad | Código en español con referencias al control normativo (A.5.15, A.8.15) en la documentación de cada módulo |
| Modificabilidad | Configuración por variables de entorno; ninguna constante de entorno embebida en la lógica |
| Pruebabilidad | **93,59 %** de cobertura; aislamiento por prueba mediante base en memoria |

### 2.8 Portabilidad

| Subcaracterística | Estado |
|---|---|
| Adaptabilidad | Configuración por entorno; `DATABASE_URL` permite PostgreSQL en producción y SQLite en pruebas |
| Instalabilidad | Dependencias fijadas en `requirements.txt`; el cliente se compila con `react-scripts` |
| Sustituibilidad | ORM (SQLAlchemy) desacopla del motor de base de datos |

> **Brecha declarada:** no se ha verificado la instalación en un sistema operativo distinto al de
> desarrollo ni el arranque en contenedores.

### 2.9 Seguridad de la información *(característica añadida por la edición 2023)*

Coincide con §2.6 en su orientación a confidencialidad, integridad y disponibilidad. La
disponibilidad no se ha medido: no existen objetivos de tiempo de recuperación ni de punto de
recuperación definidos. Riesgo `R-10`.

## 3. Resumen de la evaluación

| Característica | Estado | Brechas declaradas |
|---|---|---|
| Adecuación funcional | Verificada | — |
| Eficiencia de rendimiento | Parcial | Sin pruebas de carga (R-11) |
| Compatibilidad | Verificada | Mantenimiento limitado de `react-scripts` |
| Usabilidad | Parcial | Sin evaluación de accesibilidad ni pruebas con usuarios (R-13) |
| Fiabilidad | Verificada | — |
| Seguridad | Verificada | Sesión en `sessionStorage` (R-08) |
| Mantenibilidad | Verificada | — |
| Portabilidad | Parcial | Sin verificación multiplataforma ni en contenedores |
| Disponibilidad | No medida | Sin objetivos RTO/RPO (R-10) |

**Declaración de honestidad:** el sistema cumple y demuestra cinco características completas,
tres de forma parcial y una no medida. Este documento no afirma certificación; describe el estado
real medido en la versión 1.0.