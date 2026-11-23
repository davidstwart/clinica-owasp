# Matriz OWASP ↔ ISO/IEC 27001 ↔ Pruebas

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

Esta matriz establece la trazabilidad en los tres ejes: categoría de riesgo (OWASP Top 10 2021),
control de la norma (ISO/IEC 27001:2022 Anexo A) y evidencia de verificación (caso de prueba).
Permite demostrar que ninguna categoría de riesgo queda sin control ni sin prueba.

---

## 1. Resumen por categoría

| OWASP 2021 | Riesgo dominante | Control ISO principal | Casos | Estado |
|---|---|---|---|---|
| A01 Control de acceso roto | Lectura o modificación de datos sin autorización | A.5.15, A.5.16, A.8.2, A.8.3 | 39 + 14 | Mitigado |
| A02 Fallos criptográficos | Exposición de credenciales o sesiones | A.8.24, A.8.4, A.5.17 | 16 + 4 | Mitigado |
| A03 Inyección | Ejecución de código o manipulación de datos vía entrada | A.8.25, A.8.28, A.8.26 | 6 | Mitigado |
| A04 Diseño inseguro | Ausencia de controles en el diseño | A.8.25, A.8.26, A.5.1 | 5 | Mitigado |
| A05 Misconfiguración | Configuración por omisión insegura, superficie expuesta | A.8.9, A.8.25, A.5.10 | 17 | Mitigado |
| A06 Componentes vulnerables | Bibliotecas de terceros con vulnerabilidades | A.8.8, A.8.19 | 3 | Parcial |
| A07 Fallos de autenticación | Secuestro de sesión, fuerza bruta | A.5.17, A.8.5, A.8.6 | 20 + 5 | Mitigado |
| A08 Fallos de integridad | Datos alterados o perdidos | A.8.26, A.5.33, A.5.34 | 3 | Mitigado |
| A09 Registro insuficiente | Incidentes indetectables | A.8.15, A.8.16 | 4 | Mitigado |
| A10 SSRF | Peticiones salientes controladas por el atacante | A.8.25 | 1 | No aplica |

## 2. Matriz detallada

### A01:2021 — Control de acceso roto

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Acceder a endpoints sin sesión | A.5.15 | Cadena `obtener_usuario_actual` → `usuario_operativo` → `requerir_rol` | CP-RBAC-001 (21 rutas), CP-RBAC-012 |
| Ruta declarada sin dependencia de seguridad | A.8.26 | Verificación estructural de todas las rutas de la API | CP-RBAC-011 |
| Escalada horizontal entre pacientes | A.8.3 | Verificación de la relación recurso–paciente en la capa de negocio | CP-NEG-029, CP-OWASP-A08-003 |
| Escalada vertical por rol falsificado | A.5.15 | El rol se valida contra la base de datos, no contra el token | CP-RBAC-006 |
| Recepcionista accediendo a atenciones | A.8.2 | RBAC con lista explícita de roles por endpoint | CP-RBAC-003, CP-RBAC-005 |
| Recepcionista confirmando o atendiendo citas | A.5.18 | Máquina de estados sensible al rol | CP-NEG-021, CP-RBAC-004 |
| Usuario inactivo operando | A.5.17 | Verificación de `activo` en cada petición | CP-OWASP-A01-004 |
| Modificación de cuentas por no administrador | A.5.18 | Solo el administrador gestiona cuentas | CP-RBAC-003, CP-RBAC-005 |
| Referencia de rol inexistente | A.5.15 | Lista blanca de roles en el esquema | CP-USR-006 |

### A02:2021 — Fallos criptográficos

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Contraseñas en claro o reversibles | A.8.24 | bcrypt con coste configurable | CP-OWASP-A02-001, `test_01` |
| Hash expuesto en la respuesta | A.8.11 | El esquema de salida no incluye `password_hash` | CP-USR-002 |
| Detalles criptográficos en el error | A.8.11 | Mensaje genérico | CP-OWASP-A02-002 |
| Token sin caducidad ni identificador | A.5.25 | JWT con `exp`, `iat`, `nbf`, `jti`, `iss`, `aud`, `ver` | CP-OWASP-A02-003 |
| Secreto débil o predecible | A.8.24 | Validación de longitud, variedad y lista de valores prohibidos | CP-CFG-002…006, CP-CFG-016 |
| Reutilización de un token ajeno al despliegue | A.8.24 | Verificación de `iss` y `aud` | CP-OWASP-A01_005 |

### A03:2021 — Inyección

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Inyección SQL por búsqueda | A.8.25 | Consultas parametrizadas del ORM | CP-OWASP-A03-001 (4 cargas) |
| Inyección de ordenación | A.8.26 | La ordenación no es parametrizable por el cliente | CP-OWASP-A03-003 |
| XSS reflejado en los datos | A.8.28 | Respuesta JSON; React escapa por defecto | CP-OWASP-A03-002 |

### A04:2021 — Diseño inseguro

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Aceptar campos no declarados | A.8.26 | Allow-list estricta con esquemas Pydantic | CP-OWASP-A04-001, CP-NEG-011 |
| Reglas de negocio solo en el cliente | A.8.26 | Validación en el servidor | CP-OWASP-A04_002 |
| Ausencia de límites de recursos | A.8.26 | Límite superior de paginación en toda colección | CP-OWASP-A04_003 |
| Superficie de la API no controlada | A.8.9 | Verificación de que solo las rutas públicas lo están | CP-RBAC-002 |

### A05:2021 — Misconfiguración de seguridad

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Arranque con configuración insegura | A.8.9 | Validación *fail-closed* | CP-CFG-001…016 |
| `DEBUG` activo en producción | A.8.9 | Prohibición explícita | CP-CFG-007 |
| CORS con comodín | A.8.21 | Lista blanca obligatoria | CP-CFG-008, CP-CFG-009 |
| Vida de sesión excesiva | A.5.17 | Máximo 60 minutos en producción | CP-CFG-010 |
| Falta de cabeceras de seguridad | A.8.25 | Middleware con 11 cabeceras | CP-SEC-001…015 |
| CSP permisiva | A.5.2 | `default-src 'none'`, sin `unsafe-inline` ni `unsafe-eval` | CP-SEC-001 |
| Datos clínicos en caché | A.8.12 | `no-store, no-cache, must-revalidate` | CP-SEC-005 |
| HSTS fuera de producción | A.5.14 | Condicionado al entorno | CP-SEC-009 |
| Documentación de la API expuesta | A.8.9 | Desactivable; obligatoria desactivación en producción | CP-OWASP-A05_001, CP-OWASP-A06_003 |
| Raíz que filtra detalles internos | A.8.26 | Respuesta mínima | CP-SEC-014 |

### A06:2022 — Componentes vulnerables y anticuados

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Dependencia sin versión fijada | A.8.8 | Versiones fijadas en `requirements.txt` | CP-OWASP-A06_001 |
| Recurso de terceros sin integridad | A.8.19 | Subresource Integrity SHA-384 | CP-OWASP-A06_002, CP-SEC-015 |
| Versión del framework revelada | A.8.9 | Respuesta de documentación controlada | CP-OWASP-A06_003 |

**Brecha declarada:** no se ejecuta `pip-audit` ni `npm audit` de forma automatizada (riesgo R-14).

### A07:2021 — Fallos de autenticación

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Fuerza bruta | A.8.6 | Bloqueo temporal y límite de tasa | CP-AUT-012, CP-OWASP-A07-001 |
| Enumeración de usuarios | A.5.17 | Hash señuelo y mensaje genérico | CP-AUT-016, CP-OWASP-A07-002 |
| Sesión no revocable | A.5.25 | `token_version` y `jti` | CP-OWASP-A07_003, CP-OWASP-A07-004 |
| Contraseña inicial reutilizada | A.5.17 | Rotación obligatoria en la capa de dependencias | CP-AUT-017, CP-OWASP-A07-005, CP-USR-014 |
| Token manipulado o de otro esquema | A.8.5 | Verificación de firma y `WWW-Authenticate` | CP-OWASP-A01_002, CP-OWASP-A01_003 |
| Restablecimiento que no revoca sesiones | A.5.17 | El restablecimiento incrementa `token_version` | CP-USR-009 |

### A08:2021 — Fallos de integridad de software y datos

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Pérdida de historia clínica | A.5.33 | Eliminación física solo sin historial; bloqueo por historial | CP-OWASP-A08_001, CP-NEG-004 |
| Sobrescritura de campos de sistema | A.8.26 | Allow-list de campos | CP-OWASP-A08_002, CP-NEG-011 |
| Recurso validado contra otra entidad | A.8.26 | Verificación paciente–cita en la capa de negocio | CP-OWASP-A08_003, CP-NEG-029 |
| Desinstalación de datos con referencias | A.5.33 | Bloqueo de eliminación de usuarios y citas con historial | CP-USR-011, CP-NEG-024 |

### A09:2021 — Registro y monitoreo deficientes

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Petición sin correlación | A.8.16 | `X-Request-ID` en cada respuesta | CP-OWASP-A09-001, CP-SEC-010…012 |
| Eventos de seguridad no registrados | A.8.15 | Registro de auditoría con niveles de severidad | CP-OWASP-A09_002, CP-AUD-002 |
| Errores que revelan el internals | A.8.26 | Manejadores genéricos sin trazas | CP-OWASP-A09-003 |
| Registro mutable | A.8.15 | Sin endpoints de escritura en auditoría | CP-AUD-014 |

### A10:2021 — Server-Side Request Forgery

| Riesgo | Control ISO | Medida implementada | Prueba |
|---|---|---|---|
| Petición saliente a destino controlado por el atacante | A.8.25 | El backend no realiza peticiones HTTP salientes | CP-OWASP-A10_001 |

**Justificación:** no existe superficie de SSRF porque no hay cliente HTTP saliente ni integración
con servicios externos. El control se limita a la verificación de que no se introduzcan.

## 3. Cobertura

| Dimensión | Total | Cubiertos | Porcentaje |
|---|---|---|---|
| Categorías OWASP Top 10 | 10 | 10 | 100 % |
| Riesgos identificados en la categoría | 62 | 62 | 100 % |
| Controles ISO/IEC 27001 derivados | 33 | 33 | 100 % |
| Casos de prueba de seguridad | 104 | 104 | 100 % |

**Una categoría (A06) tiene un riesgo con control parcial** (`pip-audit`/`npm audit`), declarado
como riesgo residual R-14 con plan de cierre. Ninguna categoría carece de prueba.

## 4. Conclusión

La aplicación implementa y verifica controles frente a las diez categorías de OWASP Top 10 2021.
Cada categoría está respaldada por al menos un caso de prueba automatizado, y cada control se
traza a la norma ISO/IEC 27001. Las brechas identificadas (A06 parcial; A05 sin auditoría
automatizada) están documentadas con su riesgo cuantificado y no se ocultan.