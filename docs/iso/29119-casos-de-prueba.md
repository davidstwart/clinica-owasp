# Especificación de Casos de Prueba — ISO/IEC 29119-2:2021 §5.2

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión del documento:** 1.0

Este documento especifica los casos de prueba del sistema. Cada caso declara su identificador, su
objetivo y el control de ISO/IEC 27001 al que responde. El resultado esperado está codificado en las
aserciones del propio caso; la ejecución se registra en `29119-informe-pruebas.md`.

## Convenciones

| Elemento | Convención |
|---|---|
| Identificador | `CP-<BLOQUE>-<n>`, donde el bloque indica el ámbito: POL, SEG, VAL, AUT, RBAC, NEG, AUD, OWASP, SEC, CFG, USR |
| Nivel | Componente, integración o sistema, según ISO/IEC 29119-2 §5 |
| Marcadores | `unit`, `integration`, `security`; permiten ejecutar por categoría |
| Casos parametrizados | El sufijo `-2`, `-3`… indica la iteración sobre un dato de entrada |

## Resumen por archivo

| Archivo | Ámbito | Nivel | Marcadores | Casos |
|---|---|---|---|---|
| `test_01_politica_contrasenas.py` | Política de contraseñas | Componente | unit | 14 |
| `test_02_seguridad_utilerias.py` | Utilidades de seguridad: bcrypt y JWT | Componente | unit | 16 |
| `test_03_validacion_esquemas.py` | Validación de esquemas de entrada | Componente | unit | 20 |
| `test_04_auth_api.py` | API de autenticación y sesiones | Integración | integration | 19 |
| `test_05_rbac.py` | Control de acceso por rol | Integración y caja blanca | integration, security | 8 |
| `test_06_negocio.py` | Reglas de negocio: pacientes, citas y atenciones | Sistema | integration | 34 |
| `test_07_auditoria.py` | Registro de auditoría | Integración | integration, security | 16 |
| `test_08_owasp_a01_a10.py` | OWASP Top 10 2021 | Integración | integration, security | 31 |
| `test_09_cabeceras_seguridad.py` | Cabeceras de seguridad HTTP | Integración | integration, security | 15 |
| `test_10_configuracion.py` | Configuración y gestión de secretos | Componente en subproceso | unit | 16 |
| `test_11_usuarios.py` | Gestión de cuentas de usuario | Integración | integration | 14 |
| **Total** | | | | **203** |

Los casos parametrizados —cargas maliciosas de inyección, matriz de permisos por rol, rutas
protegidas— se ejecutan una vez por cada dato de entrada, de modo que el número de casos ejecutados
supera al número de funciones definidas.

---

## Política de contraseñas

`test_01_politica_contrasenas.py` · **Nivel:** Componente · **Marcadores:** `unit`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-POL-001` | Contraseña conformante se acepta. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-002` | Contraseña válida es indiferente al correo no relacionado. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-003` | Rechaza cortas. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-004` | Rechaza sin mayúscula. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-005` | Rechaza sin minúscula. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-006` | Rechaza sin dígito. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-007` | Rechaza contraseñas comprometidas. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-008` | Rechaza reutilizar parte del correo. | A.5.17 |
| `CP-POL-009` | No rechaza si no hay correo. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-010` | Rechaza caracteres repetidos. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-010b` | Rechaza secuencias de teclado. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-011` | Rechaza vacía. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-012` | Rechaza supera límite bcrypt. | A.5.17, A.8.5, A.8.24 |
| `CP-POL-013` | Lista de comprometidas no incluye contraseñas conformes. | A.5.17, A.8.5, A.8.24 |

## Utilidades de seguridad: bcrypt y JWT

`test_02_seguridad_utilerias.py` · **Nivel:** Componente · **Marcadores:** `unit`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-SEG-001` | bcrypt no guarda el texto plano. | A.8.24, A.8.11 |
| `CP-SEG-002` | bcrypt verifica la contraseña correcta y la incorrecta. | A.8.24, A.8.11 |
| `CP-SEG-003` | bcrypt genera una sal aleatoria. | A.8.24, A.8.11 |
| `CP-SEG-004` | Hash malformado no rompe el sistema. | A.8.24, A.8.11 |
| `CP-SEG-005` | La verificación señuelo no crea un hash nuevo. | A.8.24, A.8.11 |
| `CP-SEG-006` | El token contiene los *claims* requeridos. | A.8.24, A.8.11 |
| `CP-SEG-007` | El token expira según la configuración. | A.8.24, A.8.11 |
| `CP-SEG-008` | Token alterado es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-009` | Token firmado con otra clave es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-010` | El algoritmo `none` es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-011` | Token de otro emisor es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-012` | Token de otra audiencia es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-013` | Token expirado es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-014` | Token sin exp es rechazado. | A.8.24, A.8.11 |
| `CP-SEG-015` | Cada token tiene identificador único. | A.5.25 |
| `CP-SEG-016` | La revocación incrementa la versión del token. | A.8.24, A.8.11 |

## Validación de esquemas de entrada

`test_03_validacion_esquemas.py` · **Nivel:** Componente · **Marcadores:** `unit`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-VAL-001` | Paciente válido se acepta. | A.8.25, A.8.26 |
| `CP-VAL-002` | Dni inválido es rechazado. | A.8.25, A.8.26 |
| `CP-VAL-003` | Telefono no numérico es rechazado. | A.8.25, A.8.26 |
| `CP-VAL-004` | Telefono demasiado corto es rechazado. | A.8.25, A.8.26 |
| `CP-VAL-005` | Fecha futura es rechazada. | A.8.25, A.8.26 |
| `CP-VAL-006` | Edad inexistente es rechazada. | A.8.25, A.8.26 |
| `CP-VAL-007` | Email inválido es rechazado. | A.8.25, A.8.26 |
| `CP-VAL-008` | Campos obligatorios faltantes son rechazados. | A.8.25, A.8.26 |
| `CP-VAL-009` | Espacios en texto se normalizan. | A.8.25, A.8.26 |
| `CP-VAL-010` | Cita válida se acepta. | A.8.25, A.8.26 |
| `CP-VAL-011` | Motivo muy corto es rechazado. | A.8.25, A.8.26 |
| `CP-VAL-012` | Identificadores no positivos son rechazados. | A.8.25, A.8.26 |
| `CP-VAL-013` | Fecha anterior a 2000 es rechazada. | A.8.25, A.8.26 |
| `CP-VAL-014` | Estado pendiente no se acepta como transición. | A.8.25, A.8.26 |
| `CP-VAL-015` | Estado válido se acepta. | A.8.25, A.8.26 |
| `CP-VAL-016` | Atención válida se acepta. | A.8.25, A.8.26 |
| `CP-VAL-017` | Los campos clínicos vacíos son rechazados. | A.8.25, A.8.26 |
| `CP-VAL-018` | Usuario válido se acepta. | A.8.25, A.8.26 |
| `CP-VAL-019` | Contraseña débil en alta es rechazada. | A.8.25, A.8.26 |
| `CP-VAL-020` | Un cambio de contraseña válido se acepta. | A.8.25, A.8.26 |

## API de autenticación y sesiones

`test_04_auth_api.py` · **Nivel:** Integración · **Marcadores:** `integration`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-AUT-001` | Login válido devuelve token. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-002` | El login no distingue mayúsculas en el correo. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-003` | Login registra el evento. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-004` | Contraseña incorrecta es 401. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-005` | Correo inexistente da el mismo mensaje. | A.5.17 |
| `CP-AUT-006` | Bloqueo tras cinco intentos. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-007` | El bloqueo registra la IP y el nivel de seguridad. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-008` | El usuario inactivo recibe 403. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-009` | Campos inválidos son 422. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-010` | El endpoint `me` devuelve el usuario autenticado. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-011` | El cierre de sesión invalida el token. | A.5.25 |
| `CP-AUT-012` | Token ausente o inválido es 401. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-013` | Cambio de contraseña requiere la actual. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-014` | Cambio de contraseña revoca sesiones. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-016` | Cambio de contraseña rechaza la misma. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-017` | Cuenta pendiente de rotación no accede a operaciones. | A.5.17 |
| `CP-AUT-018` | Token conserva rol pero el servidor lo verifica. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-019` | Deshabilitar un usuario invalida sus sesiones activas. | A.5.17, A.5.25, A.8.5 |
| `CP-AUT-020` | Último acceso se actualiza. | A.5.17, A.5.25, A.8.5 |

## Control de acceso por rol

`test_05_rbac.py` · **Nivel:** Integración y caja blanca · **Marcadores:** `integration, security`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-RBAC-001` | Sin token toda ruta responde 401. | A.5.15, A.5.16, A.8.2 |
| `CP-RBAC-002` | Rutas públicas no exigen sesión. | A.5.15, A.5.16, A.8.2 |
| `CP-RBAC-003` | Matriz de permisos por rol. | A.5.15, A.5.16, A.8.2 |
| `CP-RBAC-004` | Recepcionista no confirma ni atiende. | A.5.15 |
| `CP-RBAC-005` | Médico no gestiona usuarios ni auditoría. | A.5.15, A.5.16, A.8.2 |
| `CP-RBAC-006` | Rol dentro del token no otorga privilegios. | A.5.15 |
| `CP-RBAC-011` | Toda ruta protegida declara una dependencia de seguridad. | A.5.15, A.5.16, A.8.2 |
| `CP-RBAC-012` | La dependencia de autorización está registrada como subdependencia. | A.5.15, A.5.16, A.8.2 |

## Reglas de negocio: pacientes, citas y atenciones

`test_06_negocio.py` · **Nivel:** Sistema · **Marcadores:** `integration`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-NEG-001` | Crear paciente devuelve 201. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-002` | Dni duplicado devuelve 409. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-003` | Eliminar paciente sin historial lo borra. | A.5.33 |
| `CP-NEG-004` | Paciente con historial clínico no se elimina. | A.5.33 |
| `CP-NEG-005` | Al eliminar paciente se retiran sus citas. | A.5.33 |
| `CP-NEG-006` | Lista paginada respeta límites. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-007` | Lista rechaza paginación excesiva. | A.8.26 |
| `CP-NEG-008` | Búsqueda por nombre apellido o dni. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-009` | Búsqueda sin coincidencias devuelve lista vacía. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-010` | Paciente inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-011` | Actualizar no acepta campos injectados. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-012` | Actualizar a un dni ya usado devuelve 409. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-013` | Crear cita devuelve 201 en estado pendiente. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-014` | Cita con paciente inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-015` | Cita con médico inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-016` | No se asigna un no médico como médico. | A.5.15 |
| `CP-NEG-017` | Cita en el pasado devuelve 400. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-018` | Solapamiento de cita devuelve 409. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-019` | Agenda diaria limitada a 16 citas. | A.8.26 |
| `CP-NEG-020` | Transición válida a confirmada por el médico. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-021` | Recepcionista no confirma ni atiende. | A.5.15 |
| `CP-NEG-022` | Una cita atendida solo puede cancelarse. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-023` | Una cita cancelada libera el hueco. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-024` | Cita con atención no se elimina. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-025` | El médico de la atención se toma del token. | A.5.15 |
| `CP-NEG-026` | Atención válida y historial por paciente. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-027` | Atención para paciente inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-028` | Atención con datos incompletos devuelve 422. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-029` | Atención no puede usar una cita de otro paciente. | A.5.26 |
| `CP-NEG-030` | Atención no puede usar una cita cancelada. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-031` | Historial de paciente inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-032` | Atención inexistente devuelve 404. | A.5.33, A.8.26, A.8.15 |
| `CP-NEG-033` | Health check no expone información sensible. | A.8.16 |
| `CP-NEG-034` | La atención creada queda auditada. | A.8.15 |

## Registro de auditoría

`test_07_auditoria.py` · **Nivel:** Integración · **Marcadores:** `integration, security`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-AUD-001` | Login exitoso queda registrado. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-002` | El login fallido registra la IP y el usuario. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-003` | La creación de un paciente queda auditada con su recurso. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-004` | La edición y el borrado quedan auditados. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-005` | Cambio de estado de cita registra transición. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-006` | Cambio de contraseña auditado. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-007` | El cierre de sesión queda auditado. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-008` | Filtro por usuario. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-009` | Filtro por nivel. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-010` | Nivel inválido devuelve 422. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-011` | Paginación consistente con el total. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-012` | Orden por fecha descendente. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-013` | Resumen de 24 horas consistente. | A.8.15, A.8.16, A.5.28 |
| `CP-AUD-014` | El registro de auditoría no es modificable por la API. | A.8.15 |
| `CP-AUD-015` | El detalle no almacena credenciales. | A.5.17 |
| `CP-AUD-016` | El detalle registra el identificador de petición. | A.8.16 |

## OWASP Top 10 2021

`test_08_owasp_a01_a10.py` · **Nivel:** Integración · **Marcadores:** `integration, security`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-OWASP-A01-001` | Endpoints exigen autenticación. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A01-002` | Token ausente inválido o manipulado. | A.5.17 |
| `CP-OWASP-A01-003` | Esquema no autorizado se rechaza. | A.5.17 |
| `CP-OWASP-A01-004` | Usuario inactivo no puede autenticarse. | A.5.15 |
| `CP-OWASP-A01-005` | Token de otro entorno se rechaza. | A.8.24 |
| `CP-OWASP-A02-001` | Las contraseñas se guardan cifradas. | A.5.17 |
| `CP-OWASP-A02-002` | La respuesta de error no revela algoritmos. | A.8.26 |
| `CP-OWASP-A02-003` | El token lleva identificador y expiración. | A.5.25 |
| `CP-OWASP-A03-001` | La búsqueda no es inyectable. | A.5.25 |
| `CP-OWASP-A03-002` | Script en datos no se refleja sin escapar. | A.5.3 |
| `CP-OWASP-A03-003` | Orden de consulta no acepta SQL. | A.5.25 |
| `CP-OWASP-A04-001` | No se aceptan campos no declarados. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A04-002` | Las reglas de negocio se validan en el servidor. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A04-003` | Los paginadores están acotados. | A.8.26 |
| `CP-OWASP-A05-001` | La documentación no se expone en producción. | A.8.9 |
| `CP-OWASP-A05-002` | No se expone el esquema de la base de datos. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A07-001` | Cuenta bloqueada tras intentos fallidos. | A.5.17 |
| `CP-OWASP-A07-002` | La respuesta no revela si el correo existe. | A.5.17 |
| `CP-OWASP-A07-003` | El cierre de sesión invalida el token. | A.5.25 |
| `CP-OWASP-A07-004` | Cambio de contraseña invalida las sesiones previas. | A.5.17 |
| `CP-OWASP-A07-005` | Contraseña pendiente bloquea la operativa. | A.5.17 |
| `CP-OWASP-A06-001` | No se declaran dependencias sin verificar. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A06-002` | El cliente declara integridad de los subrecursos (Subresource Integrity). | A.8.19 |
| `CP-OWASP-A06-003` | La documentación no revela versiones de dependencias. | A.8.9 |
| `CP-OWASP-A08-001` | Los datos clínicos no se pierden. | A.8.24 |
| `CP-OWASP-A08-002` | No se admite sobrescritura de campos de sistema. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A08-003` | El recurso se verifica contra la petición. | A.8.25, A.8.26, A.8.9 |
| `CP-OWASP-A09-001` | Cada petición tiene identificador de correlación. | A.8.16 |
| `CP-OWASP-A09-002` | Se se registran los intentos fallidos. | A.8.15 |
| `CP-OWASP-A09-003` | Los errores no revelan pistas internas. | A.8.26 |
| `CP-OWASP-A10-001` | La aplicación no realiza peticiones salientes. | A.8.25, A.8.26, A.8.9 |

## Cabeceras de seguridad HTTP

`test_09_cabeceras_seguridad.py` · **Nivel:** Integración · **Marcadores:** `integration, security`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-SEC-001` | La cabecera Content-Security-Policy se emite. | A.5.2 |
| `CP-SEC-002` | La cabecera X-Content-Type-Options se emite. | A.8.25 |
| `CP-SEC-003` | La cabecera X-Frame-Options se emite. | A.5.2 |
| `CP-SEC-004` | La cabecera Referrer-Policy se emite. | A.5.25 |
| `CP-SEC-005` | Las respuestas llevan cabeceras de no caché. | A.5.33 |
| `CP-SEC-006` | La cabecera Cross-Origin-Opener-Policy se emite. | A.8.25 |
| `CP-SEC-007` | La cabecera Permissions-Policy se emite. | A.5.19 |
| `CP-SEC-008` | La cabecera Cross-Domain-Policy se emite. | A.8.25 |
| `CP-SEC-009` | HSTS se emite únicamente en producción. | A.5.14 |
| `CP-SEC-010` | Toda respuesta incluye el identificador de petición. | A.8.16 |
| `CP-SEC-011` | El identificador de petición se propaga a la respuesta de error. | A.8.16 |
| `CP-SEC-012` | Se respeta el identificador de petición enviado por el cliente. | A.8.16 |
| `CP-SEC-013` | Cabeceras en respuestas de error. | A.5.2, A.8.25, A.5.14 |
| `CP-SEC-014` | La raíz de la API no filtra detalles internos. | A.5.2, A.8.25, A.5.14 |
| `CP-SEC-015` | El cliente declara CSP y Subresource Integrity. | A.5.2, A.8.25, A.5.14 |

## Configuración y gestión de secretos

`test_10_configuracion.py` · **Nivel:** Componente en subproceso · **Marcadores:** `unit`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-CFG-001` | Configuración válida se carga. | A.8.9, A.8.24 |
| `CP-CFG-002` | Secreto ausente se rechaza. | A.8.9 |
| `CP-CFG-003` | Secreto público por defecto se rechaza. | A.5.17 |
| `CP-CFG-004` | Secretos de baja calidad se rechazan. | A.5.17 |
| `CP-CFG-005` | Secreto demasiado corto se rechaza. | A.8.24 |
| `CP-CFG-006` | Secreto con poca variedad se rechaza. | A.8.24 |
| `CP-CFG-007` | Debug se prohíbe en producción. | A.8.9 |
| `CP-CFG-008` | Comodin en orígenes se rechaza en producción. | A.5.23 |
| `CP-CFG-009` | Localhost en orígenes se rechaza en producción. | A.8.9, A.8.24 |
| `CP-CFG-010` | Vida de token excesiva se rechaza en producción. | A.5.17 |
| `CP-CFG-011` | Configuración de producción válida se acepta. | A.8.9, A.8.24 |
| `CP-CFG-012` | Entorno no reconocido se rechaza. | A.8.9 |
| `CP-CFG-013` | Los orígenes se se analizan como lista. | A.8.9, A.8.24 |
| `CP-CFG-014` | Los valores por defecto son conservadores. | A.5.15 |
| `CP-CFG-015` | En pruebas se desactiva el límite de tasa pero no la rotación. | A.8.9, A.8.24 |
| `CP-CFG-016` | El archivo de ejemplo no es una configuración válida. | A.8.9, A.8.24 |

## Gestión de cuentas de usuario

`test_11_usuarios.py` · **Nivel:** Integración · **Marcadores:** `integration`

| Caso | Objetivo verificado | Control ISO/IEC 27001 |
|---|---|---|
| `CP-USR-001` | Alta de usuario devuelve 201 y exige rotación. | A.5.17 |
| `CP-USR-002` | La respuesta nunca expone el hash. | A.5.17 |
| `CP-USR-003` | Correo duplicado se rechaza. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-004` | Correo no válido se rechaza. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-005` | Contraseña débil se rechaza. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-006` | Rol desconocido se rechaza. | A.5.15 |
| `CP-USR-007` | Editar un usuario inexistente devuelve 404. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-008` | El administrador no puede otorgar un rol inexistente. | A.5.15 |
| `CP-USR-009` | Restablecer la contraseña no exige rotación y revoca las sesiones. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-010` | No se puede eliminar la propia cuenta. | A.5.15 |
| `CP-USR-011` | No se puede eliminar un usuario con historial clínico. | A.5.33 |
| `CP-USR-012` | Usuario sin historial se puede eliminar. | A.5.15, A.5.17, A.5.33 |
| `CP-USR-013` | Usuario eliminado no puede autenticarse. | A.5.15 |
| `CP-USR-014` | Las cuentas nuevas no pueden operar sin rotar la contraseña. | A.5.17 |

