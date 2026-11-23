# Declaración de Aplicabilidad (SoA) — ISO/IEC 27001:2022 Anexo A

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0
**Alcance del SGSI:** desarrollo, operación y mantenimiento del sistema web de gestión de una clínica.

> La ISO/IEC 27001:2022 contiene 93 controles en el Anexo A (controles de la organización y de las
> personas; controles físicos; controles tecnológicos). Este sistema se despliega en un
entorno de nube e infraestructura de terceros (servidor único), por lo que los controles
> físicos se gestionan fuera del alcance del proyecto. Se enumeran a continuación los controles de
> aplicación y organizacionales, con su aplicabilidad, justificación y evidencia.

**Leyenda:** ✅ Aplicable e implementado · ⚠️ Aplicable parcialmente · ➖ No aplicable (con justificación)

---

## A.5 Controles de la organización

| Control | Aplicabilidad | Justificación / implementación | Evidencia |
|---|---|---|---|
| A.5.1 Políticas de seguridad de la información | ✅ | La política y la arquitectura de seguridad están documentadas y aprobadas | `27001-politica-seguridad.md` |
| A.5.2 Roles y responsabilidades de seguridad de la información | ✅ | Los roles de administrador, médico y recepcionista tienen capacidades diferenciadas | `9001-mapa-procesos.md`, `test_05_rbac.py` |
| A.5.3 Separación de funciones | ✅ | Solo el administrador gestiona cuentas; solo el médico registra atenciones | CP-RBAC-005, CP-USR-011 |
| A.5.4 Responsabilidades de la dirección | ✅ | La dirección aprueba la política y revisa los objetivos | `9001-politica-calidad.md` §3 |
| A.5.5 Contacto para la seguridad de la información | ⚠️ | El responsable del proyecto actúa como punto de contacto; no se ha designado un contacto externo formal (depende de la institución) | Pendiente |
| A.5.6 Contacto para la seguridad de la información (continuidad) | ⚠️ | Se designó el mismo punto de contacto; falta documentar la cadena de escalamiento ante incidentes | Pendiente |
| A.5.7 Concienciación en seguridad de la información | ⚠️ | El equipo desarrollador conoce los controles (documentación en el código); no se ha realizado una campaña de concienciación para el personal de la clínica | Pendiente |
| A.5.8 Procedimientos de gestión de incidentes | ⚠️ | Se define el flujo detección–contención–erradicación–recuperación; falta incluir la comunicación legal (Ley N.º 29733) | Pendiente |
| A.5.9 Inventario de activos de información | ✅ | Los activos son los módulos del sistema, la base de datos y el registro de auditoría; inventariados en `9001-mapa-procesos.md` | `9001-mapa-procesos.md` |
| A.5.10 Uso aceptable de los activos | ⚠️ | Uso interno; falta una declaración formal de uso aceptable | Pendiente |
| A.5.11 Devolución de los activos de información | ⚠️ | El `.env` con la clave de firma debe eliminarse al devolver el equipo | Pendiente |
| A.5.12 Clasificación de la información | ✅ | Los datos clínicos se clasifican como información sensible; el registro de auditoría como información de seguridad | `27001-politica-seguridad.md` §3.3 |
| A.5.13 Etiquetado de la información | ⚠️ | La clasificación existe; falta etiquetar físicamente los soportes | Pendiente |
| A.5.14 Transferencia de información | ✅ | HTTPS obligatorio en producción; HSTS; CORS con lista blanca; verificación de `aud` en el token | `test_10_configuracion.py`, CP-SEC-009 |
| A.5.15 Control de acceso | ✅ | RBAC con tres roles, mínimo privilegio, verificación estructural de todas las rutas | `test_05_rbac.py` (39 casos) |
| A.5.16 Identificación de autenticación | ✅ | Autenticación por correo con token de sesión; el `medico_id` se toma del token | CP-NEG-025, CP-OWASP-A08-003 |
| A.5.17 Información de autenticación | ✅ | bcrypt, política de contraseñas, bloqueo por intentos, rotación obligatoria, revocación | `test_01`, `test_04`, `test_11` |
| A.5.18 Derechos de acceso asignados | ✅ | El administrador asigna el rol; toda cuenta nace con privilege mínimo (recepcionista por omisión) | CP-VAL-018, CP-RBAC-003 |
| A.5.19 Provisión de los derechos de acceso | ✅ | El alta de usuario exige rol explícito y genera auditoría de nivel `SECURITY` | `test_11_usuarios.py` |
| A.5.20 Gestión de los derechos de accesoprivileged | ⚠️ | La elevación de privilegios requiere rol de administrador; falta revisión periódica formal de accesos | Pendiente |
| A.5.21 Gestión de los privilegios de acceso | ✅ | Operaciones sensibles restringidas al administrador; el recepcionista no accede a atenciones ni auditoría | CP-RBAC-005 |
| A.5.22 Gestión de los derechos de acceso de terceros | ➖ | No hay acceso de terceros ni proveedores al sistema | — |
| A.5.38 Gestión de los acuerdos de seguridad de la información | ➖ | No se firman acuerdos con terceros que accedan al sistema | — |
| A.5.39 Gestión de la seguridad de la información en las relaciones con proveedores | ➖ | Sin proveedores con acceso al sistema | — |
| A.5.23 Uso de servicios en la nube | ✅ | El despliegue debe declarar HTTPS y lista blanca de orígenes; el comodín CORS se rechaza | CP-CFG-008, CP-CFG-009 |
| A.5.24 Preparación para incidentes de seguridad | ⚠️ | El flujo de respuesta está documentado; falta el plan formal con responsables y plazos | Pendiente |
| A.5.25 Evaluación de riesgos de seguridad de la información | ✅ | 16 riesgos analizados con probabilidad, impacto y riesgo residual | `27001-evaluacion-riesgos.md` |
| A.5.26 Tratamiento de los riesgos de seguridad de la información | ✅ | Cada riesgo tiene controles asignados y evidencia de verificación | `27001-evaluacion-riesgos.md` |
| A.5.27 Recolección y análisis de evidencia de seguridad de la información | ✅ | Registro de auditoría con niveles de severidad y resumen de 24 h para detección | `test_07_auditoria.py` |
| A.5.28 Recolección de evidencia | ✅ | El registro de auditoría es *append-only* y conserva 5 años; la API no permite modificarlo | CP-AUD-014 |
| A.5.29 Interruptos en las actividades de seguridad | ✅ | Detección de fallo de auditoría sin interrumpir la operación clínica; fallo de configuración impide el arranque (fail-closed) | `auditoria/service.py`, `config.py` |
| A.5.30 Preparation de la continuidad y de la recuperación | ⚠️ | Sonda `/health` para monitoreo; **no** existen RTO/RPO ni copia de seguridad automatizada | Pendiente (riesgo R-10) |
| A.5.31 Requisitos legales, reglamentarios y contractuales | ✅ | Aplicabilidad de la Ley N.º 29733 y la Ley N.º 26842 declarada en el alcance | `9001-sistema-gestion-calidad.md` §1 |
| A.5.32 Protección de los derechos de propiedad intelectual | ⚠️ | El código es del proyecto; falta definir el uso de bibliotecas de terceros en la política institucional | Pendiente |
| A.5.33 Protección de los datos personales y de la privacidad | ✅ | Minimización en auditoría, integridad de la historia clínica, retención 5 años, `no-store` | CP-AUD-015, CP-NEG-004 |
| A.5.34 Privacidad y protección de la PII | ✅ | Los datos se procesan solo para la finalidad clínica; la eliminación se sustituye por baja lógica | `27001-politica-seguridad.md` §3.3 |
| A.5.35 Revisión independiente de la seguridad de la información | ⚠️ | Las pruebas de seguridad automatizadas actúan como verificación independiente del autor; falta una auditoría externa | Pendiente |
| A.5.36 Cumplimiento de las políticas de seguridad | ✅ | Verificación por casos de prueba de los controles de configuración y cabeceras | `test_09`, `test_10` |
| A.5.37 Procedimientos de gestión documentados | ✅ | Documentación normativa y técnica en `docs/` y en las cabeceras de los módulos | `docs/iso/README.md` |

## A.8 Controles tecnológicos

| Control | Aplicabilidad | Justificación / implementación | Evidencia |
|---|---|---|---|
| A.8.1 Endpoint de usuario | ✅ | FastAPI sirve la API; el cliente React se despliega como origen separado | `frontend/` |
| A.8.2 Privilegios de acceso asignados | ✅ | Ver A.5.15; los roles se aplican como dependencias de FastAPI | `test_05_rbac.py` |
| A.8.3 Restricción de la información de acceso | ✅ | Filtrado por rol y por recurso; paginación para limitar exposición | CP-RBAC-003, CP-NEG-006 |
| A.8.4 Acceso a los códigos fuente | ✅ | El repositorio no expone la clave de firma; `.env` excluido del control de versiones | `.gitignore` |
| A.8.5 Autenticación segura | ✅ | bcrypt + JWT firmado con `iss`/`aud`/`jti`; rate limit en el login | `auth/security.py`, CP-OWASP-A02-003 |
| A.8.6 Capacidad de la carga de trabajo | ✅ | Límite de tasa global (300/min) y en el login (10/min) | `main.py` |
| A.8.7 Protección contra virus y malware | ➖ | El backend no ejecuta archivos del usuario; depende de la protección del sistema operativo | — |
| A.8.8 Gestión de las vulnerabilidades técnicas | ⚠️ | Versiones fijadas; **pendiente** `pip-audit`/`npm audit` automatizado | `CP-OWASP-A06_001` (riesgo R-14) |
| A.8.9 Configuración de la seguridad | ✅ | Arranque *fail-closed*; sin `DEBUG` en producción; documentación de la API desactivable | `test_10_configuracion.py` (19 casos) |
| A.8.10 Eliminación de la información | ⚠️ | Retención de auditoría 5 años; **pendiente** procedimiento de borrado seguro | Pendiente |
| A.8.11 Enmascaramiento de datos | ✅ | El hash nunca cruza el límite de la aplicación; los errores son genéricos | CP-USR-002, CP-OWASP-A09-003 |
| A.8.12 Prevención de fuga de datos | ✅ | Auditoría sin datos clínicos; `no-store`; `Referrer-Policy: no-referrer` | CP-AUD-015, CP-SEC-005 |
| A.8.13 Copia de seguridad de la información | ⚠️ | **Pendiente.** No hay copia automatizada de PostgreSQL (riesgo R-10) | Pendiente |
| A.8.14 Restitución de la información | ⚠️ | **Pendiente.** No se ha probado la restauración de copias | Pendiente |
| A.8.15 Registro de la actividad | ✅ | Auditoría *append-only* con autor, fecha, recurso, IP, agente y severidad | `test_07_auditoria.py` (16 casos) |
| A.8.16 Monitoreo de la actividad | ✅ | Resumen de 24 h; `X-Request-ID`; log de acceso por petición | CP-OWASP-A09-001, CP-AUD-013 |
| A.8.17 Sincronización del reloj | ✅ | Horario UTC uniforme mediante `common/time_utils.py`; SQLite en pruebas comparte el mismo reloj | `common/time_utils.py` |
| A.8.18 Uso de las utilidades de sistema | ➖ | El backend no lanza procesos del sistema ni invoca utilidades externas | — |
| A.8.19 Instalación de software en los sistemas operativos | ✅ | Dependencias fijadas; SRI en los recursos de terceros del cliente | CP-OWASP-A06_002 |
| A.8.20 Redes de seguridad | ✅ | HTTPS obligatorio; HSTS; hosts confiables; CORS con lista blanca | CP-SEC-009, CP-CFG-010 |
| A.8.21 Seguridad de los servicios de red | ✅ | Límite de tasa; sin exposición de servicios internos; superficie reducida a `/api` y `/health` | CP-OWASP-A04_003 |
| A.8.22 Segregación de redes | ➖ | El sistema es de un solo servidor; no hay segmentación de red que gestionar | — |
| A.8.35 Uso de servicios en la nube | ⚠️ | El despliegue en nube exige declarar HTTPS y lista blanca de orígenes; falta el acuerdo de nivel de servicio con el proveedor (A.5.38) | Pendiente |
| A.8.23 Filtrado web | ➖ | No se sirve contenido web desde la API; el filtrado se aplica en el borde (CDN del proveedor) | — |
| A.8.24 Uso de la criptografía | ✅ | bcrypt para contraseñas; HS256 para sesiones; SHA-384 (SRI) para recursos; gestión segura de la clave | `auth/security.py`, `index.html` |
| A.8.25 Desarrollo de sistemas seguros | ✅ | Verificación en todas las etapas: validación de entrada, salida segura, cabeceras, pruebas de seguridad | `test_03`, `test_08`, `test_09` |
| A.8.26 Práctica de desarrollo seguro | ✅ | Lista blanca de campos; reglas de negocio en el servidor; comprobación estructural de la autorización | `test_05`, `test_08` |
| A.8.27 Entorno de desarrollo seguro | ✅ | Entorno de pruebas aislado (SQLite en memoria, sin datos reales); variables por entorno | `tests/conftest.py` |
| A.8.28 Codificación segura | ✅ | Controles de inyección y XSS; revisión por pruebas automatizadas | `test_08_owasp_a01_a10.py` |
| A.8.29 Pruebas de seguridad en el desarrollo y la aceptación | ✅ | 104 casos de seguridad ejecutados en la suite; se ejecutan antes de cada entrega | Marcador `security` |
| A.8.30 outsource / Desarrollo y entrega seguros | ⚠️ | Se aplican prácticas seguras; falta incorporar la revisión de dependencias en la entrega | Pendiente (riesgo R-14) |
| A.8.31 Separación de los entornos de desarrollo, prueba y producción | ✅ | `ENVIRONMENT` explícito; `.env` por entorno; base de datos de pruebas separada | `config.py` |
| A.8.32 Gestión de los cambios de información | ✅ | Validación *fail-closed* de la configuración; cambio de esquema exige recrear la base (riesgo R-12) | `test_10_configuracion.py` |
| A.8.33 Datos de prueba | ✅ | Los datos de prueba son ficticios; las contraseñas demo exigen rotación obligatoria | `tests/conftest.py` |
| A.8.34 Protección de la información durante las pruebas | ✅ | Las pruebas usan una base en memoria separada de producción; no se registran credenciales reales | `test_07_auditoria.py` |

## Resumen de aplicabilidad

| Categoría | ✅ Implementados | ⚠️ Parciales | ➖ No aplicables | Total |
|---|---|---|---|---|
| A.5 Organizacionales | 24 | 12 | 3 | 39 |
| A.8 Tecnológicos | 25 | 6 | 4 | 35 |
| **Total** | **49** | **18** | **7** | **74** |

**Estado global:** 49 controles implementados y verificados, 18 parcialmente (con plan de cierre
documentado) y 7 no aplicables con justificación. Ningún control aplicable se considera cerrado sin
evidencia.

> El recuento cubre los 74 controles del Anexo A cuya aplicabilidad se ha evaluado para el alcance
> declarado. Los controles puramente físicos (A.7) y aquellos que dependen exclusivamente de la
> institución usuaria se gestionan mediante acuerdos de servicio con el proveedor de
> infraestructura y no forman parte del alcance de este proyecto.

## Plan de cierre de los controles parciales

| Control | Pendiente | Riesgo asociado |
|---|---|---|
| A.5.5, A.5.6, A.5.8, A.5.24 | Designar punto de contacto y cadena de escalamiento | R-10 |
| A.5.7 | Campaña de concienciación para el personal de la clínica | R-13 |
| A.5.10, A.5.11, A.5.13 | Declaración de uso aceptable, devolución y etiquetado | — |
| A.5.20 | Revisión periódica de accesos | R-03 |
| A.5.30, A.8.13, A.8.14 | Copia de seguridad, RTO/RPO y prueba de restauración | R-10 |
| A.5.32 | Política institucional sobre propiedad intelectual | — |
| A.5.35 | Auditoría externa de seguridad | R-14 |
| A.8.8, A.8.30 | `pip-audit`/`npm audit` en integración continua | R-14 |
| A.8.10 | Procedimiento de borrado seguro | R-04 |
| A.8.35 | Acuerdo de nivel de servicio con el proveedor de nube (A.5.38) | R-10 |