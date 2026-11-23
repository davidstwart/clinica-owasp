# Evaluación de Riesgos — ISO/IEC 27005:2022

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Metodología

Se aplica el enfoque de riesgo de ISO/IEC 27005 con el método de probabilización e impacto de la
tabla siguiente. La escala es de 1 a 5 en ambos ejes.

**Probabilidad (P):** 1 Remota · 2 Improbable · 3 Posible · 4 Probable · 5 Casi seguro.
**Impacto (I):** 1 Insignificante · 2 Menor · 3 Moderado · 4 Mayor · 5 Crítico
(afecta a datos clínicos sensibles o impide la operación).

**Nivel de riesgo = P × I**

| Nivel | Rango | Tratamiento |
|---|---|---|
| Bajo | 1–6 | Aceptar con monitoreo |
| Medio | 8–12 | Mitigar con control definido |
| Alto | 15–20 | Mitigar con prioridad alta |
| Crítico | 25 | Mitigar obligatoriamente antes de producción |

## 2. Análisis de riesgos

### R-01 Exposición de datos clínicos por acceso sin autenticar

| | |
|---|---|
| **Amenaza** | Uso de un endpoint sin control de acceso |
| **Actantes** | Usuario no autenticado, atacante externo |
| **Vulnerabilidad** | Dependencias de autorización mal declaradas (noconformidad NC-02 detectada) |
| **P / I** | 4 × 5 = **20 (Alto)** |
| **Controles** | Cadena de dependencias `obtener_usuario_actual` → `usuario_operativo` → `requerir_rol`; prueba estructural `CP-RBAC-011`; matriz de permisos `CP-RBAC-003` |
| **Riesgo residual** | 1 × 5 = **5 (Bajo)** |
| **Evidencia** | `tests/test_05_rbac.py` |

### R-02 Robo de credenciales por fuerza bruta

| | |
|---|---|
| **Amenaza** | Ataque automatizado de credenciales por defecto o adivinadas |
| **P / I** | 5 × 4 = **20 (Alto)** |
| **Controles** | Bloqueo temporal tras 5 intentos (15 min); límite de tasa `10/minute` en `/auth/login`; respuesta genérica; hash señuelo que iguala el tiempo de respuesta |
| **Riesgo residual** | 2 × 4 = **8 (Medio)** |
| **Evidencia** | CP-AUT-012, CP-OWASP-A07-001, CP-OWASP-A07-002 |

### R-03 Interceptación de la sesión (token)

| | |
|---|---|
| **Amenaza** | Secuestro del token JWT en el navegador |
| **P / I** | 3 × 4 = **12 (Medio)** |
| **Controles** | Expiración de 30 minutos; verificación de `iss`, `aud`, `alg`; `jti` y `token_version` permiten revocación inmediata; HSTS en producción |
| **Brecha** | El token se almacena en `sessionStorage`, accesible a JavaScript del mismo origen |
| **Riesgo residual** | 2 × 4 = **8 (Medio)** |
| **Evidencia** | CP-OWASP-A02-003, CP-OWASP-A07-003, CP-OWASP-A07-004 |

### R-04 Reutilización de una clave conocida

| | |
|---|---|
| **Amenaza** | Despliegue con el secreto de firma publicado en el repositorio |
| **P / I** | 3 × 5 = **15 (Alto)** |
| **Controles** | Lista de secretos prohibidos; longitud mínima de 32; variedad mínima de caracteres; rechazo de repeticiones; validación en arranque |
| **Riesgo residual** | 1 × 5 = **5 (Bajo)** |
| **Evidencia** | `tests/test_10_configuracion.py` (CP-CFG-002 a CP-CFG-006, CP-CFG-016) |

### R-05 Inyección SQL

| | |
|---|---|
| **Amenaza** | Manipulación de consultas mediante los parámetros de búsqueda |
| **P / I** | 3 × 4 = **12 (Medio)** |
| **Controles** | SQLAlchemy con parámetros vinculados en todas las consultas; no se interpolan valores; ordenación no parametrizable por el cliente |
| **Riesgo residual** | 1 × 4 = **4 (Bajo)** |
| **Evidencia** | CP-OWASP-A03-001 (4 cargas maliciosas), CP-OWASP-A03-003 |

### R-06 Manipulación de datos clínicos

| | |
|---|---|
| **Amenaza** | Alteración o borrado de información por campos no previstos en el modelo |
| **P / I** | 3 × 5 = **15 (Alto)** |
| **Controles** | Allow-list estricta mediante esquemas Pydantic; los campos de sistema enviados se descartan; reglas de negocio verificadas en el servidor |
| **Riesgo residual** | 1 × 5 = **5 (Bajo)** |
| **Evidencia** | CP-NEG-011, CP-OWASP-A04-001, CP-OWASP-A08-002 |

### R-07 Pérdida o corrupción de la historia clínica

| | |
|---|---|
| **Amenaza** | Eliminación inadvertida de atenciones o DNI |
| **P / I** | 3 × 5 = **15 (Alto)** |
| **Controles** | Eliminación física únicamente cuando no existe historial clínico; bloqueo de eliminación de pacientes con atenciones, de citas con atenciones y de usuarios con historial; ventana de retención de auditoría configurada en 5 años |
| **Riesgo residual** | 1 × 5 = **5 (Bajo)** |
| **Evidencia** | CP-NEG-004, CP-NEG-024, CP-USR-011, CP-OWASP-A08-001 |

### R-08 Acceso al token desde JavaScript del mismo origen

| | |
|---|---|
| **Amenaza** | Robo del token mediante XSS |
| **P / I** | 2 × 4 = **8 (Medio)** |
| **Controles** | CSP restrictiva sin `unsafe-inline` en scripts ni `unsafe-eval`; SRI en recursos de terceros; React escapa por defecto |
| **Brecha** | `sessionStorage` en lugar de cookie `HttpOnly` |
| **Riesgo residual** | 2 × 4 = **8 (Medio)** |
| **Plan** | Migrar a cookie `HttpOnly` `Secure` `SameSite=Strict` con protección CSRF (fuera del alcance de la v1.0) |

### R-09 Ausencia de trazabilidad de las operaciones

| | |
|---|---|
| **Amenaza** | Imposibilidad de reconstruir quién accedió a qué dato |
| **P / I** | 2 × 4 = **8 (Medio)** |
| **Controles** | Registro de auditoría *append-only* con autor, acción, recurso, IP, agente y nivel; `X-Request-ID` por petición; indicadores de 24 h |
| **Riesgo residual** | 1 × 4 = **4 (Bajo)** |
| **Evidencia** | CP-AUD-001 a CP-AUD-016 |

### R-10 Indisponibilidad del servicio

| | |
|---|---|
| **Amenaza** | Caída del sistema sin capacidad de recuperación definida |
| **P / I** | 3 × 4 = **12 (Medio)** |
| **Controles** | Sonda `/health` para el monitoreo; despliegue en servidor único |
| **Brecha** | No existen objetivos de tiempo de recuperación (RTO) ni de punto de recuperación (RPO); no hay copia de seguridad automatizada |
| **Riesgo residual** | 3 × 4 = **12 (Medio)** |
| **Plan** | Definir RTO/RPO, configurar copia de seguridad de PostgreSQL y probar la restauración |

### R-11 Rendimiento insuficiente bajo carga

| | |
|---|---|
| **Amenaza** | Degradación o caída por volumen de usuarios o de historia clínica |
| **P / I** | 3 × 3 = **9 (Medio)** |
| **Controles** | Paginación obligatoria con límite superior; índices en claves de búsqueda y de ordenación; consultas parametrizadas |
| **Brecha** | No se han ejecutado pruebas de carga ni de estrés |
| **Riesgo residual** | 3 × 3 = **9 (Medio)** |
| **Plan** | Ensayo con `k6` o `Locust` sobre los escenarios de alta y de consulta de historial |

### R-12 Desalineación entre el código y el esquema de la base de datos

| | |
|---|---|
| **Amenaza** | Ausencia de migraciones: `create_all` no altera tablas existentes |
| **P / I** | 4 × 4 = **16 (Alto)** |
| **Controles** | Detección temprana en desarrollo; la base local se regenera desde `seed.py` |
| **Brecha** | No existe control automático de versión de esquema |
| **Riesgo residual** | 3 × 4 = **12 (Medio)** |
| **Plan** | Incorporar Alembic con migraciones versionadas antes de producción |

### R-13 Inaccesibilidad de la interfaz

| | |
|---|---|
| **Amenaza** | Usuarios con discapacidad impedidos de operar el sistema |
| **P / I** | 3 × 2 = **6 (Bajo)** |
| **Controles** | HTML semántico, etiquetas asociadas a los campos y contraste visual |
| **Brecha** | No se ha realizado auditoría WCAG 2.1 AA |
| **Riesgo residual** | 3 × 2 = **6 (Bajo)** |
| **Plan** | Auditoría de accesibilidad y prueba con teclado y lector de pantalla |

### R-14 Dependencias con vulnerabilidades conocidas

| | |
|---|---|
| **Amenaza** | Explotación de una vulnerabilidad en una biblioteca de terceros |
| **P / I** | 3 × 4 = **12 (Medio)** |
| **Controles** | Versiones fijadas en `requirements.txt`; verificación automática de que toda dependencia declara restricción (`CP-OWASP-A06_001`); SRI en recursos del cliente |
| **Brecha** | No se ejecuta `pip-audit` ni `npm audit` de forma programada |
| **Riesgo residual** | 2 × 4 = **8 (Medio)** |
| **Plan** | Incorporar análisis de dependencias al flujo de integración continua |

### R-15 Divulgación de información en las respuestas de error

| | |
|---|---|
| **Amenaza** | Exposición de trazas, versiones o estructura interna al usuario |
| **P / I** | 2 × 3 = **6 (Bajo)** |
| **Controles** | Manejadores globales que devuelven mensajes genéricos; `DEBUG` prohibido en producción; raíz con información mínima; sin opciones de `traceback` |
| **Riesgo residual** | 1 × 3 = **3 (Bajo)** |
| **Evidencia** | CP-OWASP-A09-003, CP-OWASP-A02-002, CP-SEC-014 |

### R-16 Manipulación de la identidad profesional

| | |
|---|---|
| **Amenaza** | Registro de una atención clínica en nombre de otro médico |
| **P / I** | 2 × 5 = **10 (Medio)** |
| **Controles** | El `medico_id` se toma del token y del cuerpo solo se acepta un subconjunto explícito de campos; la atención se vincula a la cita del mismo paciente |
| **Riesgo residual** | 1 × 5 = **5 (Bajo)** |
| **Evidencia** | CP-NEG-025, CP-NEG-029, CP-OWASP-A08-003 |

## 3. Resumen del tratamiento de riesgos

| Id. | Riesgo | Nivel inicial | Nivel residual | Tratamiento |
|---|---|---|---|---|
| R-01 | Acceso sin autenticar | 20 | 5 | Mitigado |
| R-02 | Fuerza bruta | 20 | 8 | Mitigado |
| R-03 | Secuestro de sesión | 12 | 8 | Mitigado parcialmente |
| R-04 | Clave conocida | 15 | 5 | Mitigado |
| R-05 | Inyección SQL | 12 | 4 | Mitigado |
| R-06 | Manipulación de datos | 15 | 5 | Mitigado |
| R-07 | Pérdida de historia clínica | 15 | 5 | Mitigado |
| R-08 | Token accesible a JavaScript | 8 | 8 | Aceptado con plan |
| R-09 | Falta de trazabilidad | 8 | 4 | Mitigado |
| R-10 | Indisponibilidad | 12 | 12 | Aceptado con plan |
| R-11 | Rendimiento bajo carga | 9 | 9 | Aceptado con plan |
| R-12 | Esquema sin migraciones | 16 | 12 | Aceptado con plan |
| R-13 | Inaccesibilidad | 6 | 6 | Aceptado con plan |
| R-14 | Dependencias vulnerables | 12 | 8 | Mitigado parcialmente |
| R-15 | Fuga en errores | 6 | 3 | Mitigado |
| R-16 | Suplantación de profesional | 10 | 5 | Mitigado |

**Ningún riesgo permanece en nivel Crítico.** Los riesgos altos (R-01, R-02, R-04, R-06, R-07) están
mitigados con controles verificados por pruebas. Los riesgos aceptados con plan (R-08, R-10, R-11,
R-12, R-13, R-14) están documentados como trabajo pendiente con su riesgo residual cuantificado.

## 4. Criterios de aceptación del riesgo

El riesgo se acepta cuando:

1. El nivel residual es inferior a 12 (medio).
2. No afecta a la confidencialidad, integridad ni disponibilidad de datos clínicos.
3. Existe un plan de mitigación con responsable y plazo.

Si alguna de estas condiciones no se cumple, el riesgo se eleva a la agenda de la dirección antes
de la puesta en producción.