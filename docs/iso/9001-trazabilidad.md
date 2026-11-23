# Matriz de Trazabilidad — ISO 9001:2015 §8.1, §8.5.2

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

La trazabilidad se establece en ambos sentidos: cada requisito se enlaza con su control y su
evidencia, y cada control se enlaza con los casos de prueba que lo verifican.

---

## 1. Requisitos funcionales → implementación → pruebas

| RF | Requisito | Implementación | Casos de prueba | Resultado |
|---|---|---|---|---|
| RF-01 | El usuario se autentica con correo y contraseña | `auth/router.py` `login` | `test_04_auth_api.py` CP-AUT-001…006 | Correcto |
| RF-02 | El acceso se bloquea tras intentos fallidos | `auth/router.py` bloqueo temporal | CP-AUT-012, CP-OWASP-A07-001 | Correcto |
| RF-03 | El login no revela si el correo existe | `auth/router.py` hash señuelo | CP-AUT-016, CP-OWASP-A07-002 | Correcto |
| RF-04 | El usuario cierra sesión y el token se revoca | `auth/security.py` `revocar_tokens` | CP-AUT-013, CP-OWASP-A07-003 | Correcto |
| RF-05 | Toda cuenta debe rotar su contraseña inicial | `security.py` `usuario_operativo` | CP-AUT-017, CP-OWASP-A07-005, CP-USR-014 | Correcto |
| RF-06 | El administrador crea, edita y da de baja usuarios | `auth/router.py` | `test_11_usuarios.py` CP-USR-001…014 | Correcto |
| RF-07 | Se registran pacientes con validación estricta | `pacientes/router.py` | CP-NEG-001…012, CP-VAL-001…009 | Correcto |
| RF-08 | Se agenda una cita validando paciente, médico y disponibilidad | `citas/router.py` | CP-NEG-013…019 | Correcto |
| RF-09 | Las transiciones de estado de cita son controladas por rol | `citas/router.py` `cambiar_estado` | CP-NEG-020…023, CP-RBAC-004 | Correcto |
| RF-10 | Se registra la atención clínica con médico autenticado | `atenciones/router.py` | CP-NEG-025…032 | Correcto |
| RF-11 | El historial del paciente se consulta por profesional | `atenciones/router.py` `por_paciente` | CP-NEG-026, CP-NEG-031 | Correcto |
| RF-12 | El administrador consulta el registro de auditoría | `auditoria/router.py` | `test_07_auditoria.py` CP-AUD-001…016 | Correcto |

## 2. Requisitos no funcionales → evidencia

| RNF | Requisito | Implementación | Evidencia | Resultado |
|---|---|---|---|---|
| RNF-01 | Cifrado de contraseñas en reposo | bcrypt con coste configurable | `test_01_politica_contrasenas.py`, CP-OWASP-A02-001 | Correcto |
| RNF-02 | Sesiones firmadas y con caducidad | JWT HS256 con `iss`, `aud`, `jti`, `exp`, `ver` | CP-OWASP-A01-005, CP-OWASP-A02-003 | Correcto |
| RNF-03 | Cabeceras de seguridad completas | `middleware/security_headers.py` | `test_09_cabeceras_seguridad.py` (15 casos) | Correcto |
| RNF-04 | Límite de tasa en autenticación | `RateLimiter` en `/auth/login` | CP-OWASP-A07-001 | Correcto |
| RNF-05 | Paginación acotada en toda colección | `Query(ge=1, le=…)` en los listados | CP-NEG-007, CP-OWASP-A04-003 | Correcto |
| RNF-06 | Protección frente a inyección SQL | ORM con parámetros vinculados | CP-OWASP-A03-001 | Correcto |
| RNF-07 | Sin pérdida de datos clínicos | Eliminación física solo sin historial; bloqueo por historial | CP-NEG-004, CP-NEG-024, CP-USR-011 | Correcto |
| RNF-08 | Registro de auditoría verificable | `auditoria/service.py` | CP-AUD-001…016 | Correcto |
| RNF-09 | Correlación de peticiones | `middleware/request_context.py` | CP-OWASP-A09-001, CP-SEC-010…012 | Correcto |
| RNF-10 | Arranque seguro por configuración | `config.py` *fail-closed* | `test_10_configuracion.py` (19 casos) | Correcto |
| RNF-11 | Integridad de recursos externos | Subresource Integrity en `index.html` | CP-SEC-015 | Correcto |
| RNF-12 | Aislamiento de pruebas | SQLite en memoria con `StaticPool` | `tests/conftest.py`, CP-CFG-015 | Correcto |

## 3. Requisitos de las normas → documentos

| Norma | Requisito | Evidencia documental |
|---|---|---|
| ISO 9001 §4.3 | Alcance del SGC | `9001-sistema-gestion-calidad.md` §1 |
| ISO 9001 §5.2 | Política de calidad | `9001-politica-calidad.md` §1 |
| ISO 9001 §6.2 | Objetivos medibles | `9001-politica-calidad.md` §2 |
| ISO 9001 §7.1.3 | No aplicabilidad | `9001-sistema-gestion-calidad.md` §7 |
| ISO 9001 §4.4 | Mapa de procesos | `9001-mapa-procesos.md` |
| ISO/IEC 25010 | Características de calidad | `25000-calidad-producto.md` |
| ISO/IEC 27001 A.5.15 | Control de acceso | `27001-matriz-owasp-iso.md`, `test_05_rbac.py` |
| ISO/IEC 27001 A.5.17 | Autenticación | `test_01`, `test_04`, `test_11` |
| ISO/IEC 27001 A.5.25 | Evaluación de riesgos | `27001-evaluacion-riesgos.md` |
| ISO/IEC 27001 A.8.15 | Registro de auditoría | `test_07_auditoria.py` |
| ISO/IEC 27001 A.8.9 | Configuración segura | `test_10_configuracion.py` |
| ISO/IEC 27001 A.8.20–8.21 | Redes y seguridad de servicios | `27001-politica-seguridad.md` |
| ISO/IEC 27001 A.8.24–8.26 | Criptografía y prevención de fugas | `test_09_cabeceras_seguridad.py` |
| ISO/IEC 29119-2 | Estrategia de prueba | `29119-plan-de-pruebas.md` |
| ISO/IEC 29119-2 §5.2 | Especificación de casos | `29119-casos-de-prueba.md` |
| ISO/IEC 29119-2 §6.3 | Informe de ejecución | `29119-informe-pruebas.md` |

## 4. No conformidades → acción correctiva → regresión

| Id. | Hallazgo | Control implicado | Acción | Prueba de regresión |
|---|---|---|---|---|
| NC-01 | El mensaje de login distinguía entre correo inexistente y contraseña incorrecta | A.5.17, OWASP A07 | Hash señuelo y mensaje genérico | CP-AUT-016, CP-OWASP-A07-002 |
| NC-02 | Las dependencias de autorización escritas como `_=todos` sin anotación no se registraban en FastAPI; los endpoints quedaban sin autenticar | A.5.15, OWASP A01 | Anotación explícita con `Depends` | CP-RBAC-011, CP-RBAC-012 |
| NC-03 | El `.env.example` contenía un valor de secreto que la aplicación aceptaba como válido | A.8.9 | Valor añadido a `SECRETOS_PROHIBIDOS` | CP-CFG-016 |
| NC-04 | La CSP de la API no declaraba `script-src` ni `object-src` explícitos | A.5.2 | Directivas explícitas añadidas | CP-SEC-001 |

## 5. Cobertura de la matriz

| Dimensión | Total | Cubiertos | Porcentaje |
|---|---|---|---|
| Requisitos funcionales | 12 | 12 | 100 % |
| Requisitos no funcionales | 12 | 12 | 100 % |
| Categorías OWASP Top 10 | 10 | 10 | 100 % |
| Cabeceras de seguridad | 15 | 15 | 100 % |
| Controles de configuración | 16 | 16 | 100 % |
| No conformidades detectadas | 4 | 4 cerradas | 100 % |