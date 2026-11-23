# Política y Arquitectura de Seguridad — ISO/IEC 27001:2022

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Compromiso de la dirección

La dirección del proyecto se compromete a proteger la información que procesa el sistema —datos
personales de pacientes, credenciales de acceso y registros de auditoría— frente a pérdida,
alteración, divulgación o falta de disponibilidad.

Marco aplicable:

- **ISO/IEC 27001:2022** — sistema de gestión de la seguridad de la información.
- **ISO/IEC 27005:2022** — gestión de riesgos.
- **OWASP Top 10 (2021)** — referencia técnica para el diseño de controles.
- **OWASP ASVS 4.0.3** — criterios de verificación de seguridad de aplicación.
- **Ley N.º 29733** (Perú, Protección de Datos Personales) — obligatoriedad de medidas de seguridad.

> **Nota de alcance:** este proyecto implementa y verifica los controles. **No constituye una
> certificación** ISO/IEC 27001, que requiere auditoría externa acreditada por un organismo
> certificador. El documento describe el estado real medido.

## 2. Arquitectura de seguridad

```
┌───────────────────────────── Navegador ─────────────────────────────┐
│  React 19 · CSP declarativa · SRI · tokens en sessionStorage         │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTPS (obligatorio en producción)
┌───────────────────────────────▼──────────────────────────────────────┐
│  Middleware: cabeceras de seguridad · request-id y logging            │
│  TrustedHost · Limitación de tasa · CORS (lista blanca)              │
├──────────────────────────────────────────────────────────────────────┤
│  /api/auth        /api/pacientes   /api/citas   /api/atenciones      │
│        │                │              │              │               │
│        └────────────────┴──────┬───────┴──────────────┘               │
│                                ▼                                      │
│     obtener_usuario_actual → usuario_operativo → requerir_rol         │
├──────────────────────────────────────────────────────────────────────┤
│  Esquemas Pydantic (allow-list) → Servicios → Modelos SQLAlchemy      │
├──────────────────────────────────────────────────────────────────────┤
│  PostgreSQL · bcrypt · registro de auditoría *append-only*            │
└──────────────────────────────────────────────────────────────────────┘
```

## 3. Dominios de protección y controles

### 3.1 Autenticación (A.5.17, A.8.5)

| Control | Implementación | Verificación |
|---|---|---|
| Almacenamiento de credenciales | bcrypt con coste configurable (12 rondas por omisión) | `test_01`, CP-OWASP-A02-001 |
| Política de contraseñas | Mínimo 8 caracteres, mayúscula, minúscula y dígito; rechazo de secuencias triviales; máximo 72 (límite de bcrypt) | `test_01` (14 casos) |
| Resistencia a fuerza bruta | Bloqueo 15 minutos tras 5 intentos; límite `10/minute` en el login | CP-AUT-012, CP-OWASP-A07-001 |
| Anti-enumeración | Mensaje genérico y hash señuelo que iguala el tiempo de respuesta | CP-AUT-016, CP-OWASP-A07-002 |
| Emisión de sesión | JWT HS256 con `iss`, `aud`, `jti`, `iat`, `nbf`, `exp`, `ver` | CP-OWASP-A02-003 |
| Revocación | `token_version` invalida todas las sesiones al cerrar sesión o cambiar la contraseña | CP-OWASP-A07-003, CP-OWASP-A07-004 |
| Rotación obligatoria | Toda cuenta nace con `debe_cambiar_contrasena=True`; el bloqueo se aplica en la capa de dependencias | CP-AUT-017, CP-OWASP-A07-005, CP-USR-014 |

### 3.2 Control de acceso (A.5.15, A.5.18)

| Rol | Alcance |
|---|---|
| Administrador | Control total, incluida la gestión de usuarios y la consulta de auditoría |
| Médico | Pacientes, citas, atenciones; confirma y atiende sus citas |
| Recepcionista | Pacientes y agenda; solo cancela citas; no confirma ni atiende; sin acceso a atenciones ni auditoría |

Reglas transversales:

- El rol se valida **contra la base de datos**, no contra la claim del token (`CP-RBAC-006`).
- La validación de sesión y de rotación antecede a toda autorización (`usuario_operativo`).
- Toda ruta de la API declara su cadena de dependencias de seguridad, verificado de forma
  estructural en `CP-RBAC-011` y `CP-RBAC-012`.
- Toda colección de datos está paginada para evitar extracción masiva (`A.8.26`).

### 3.3 Protección de datos personales (A.5.33, A.5.34)

| Control | Implementación |
|---|---|
| Minimización | Los datos clínicos no se incluyen en los registros de auditoría (solo identificadores) |
| Integridad | La historia clínica bloquea el borrado del paciente, de la cita y del profesional |
| Conservación | Retención de auditoría de 1825 días (5 años), alineada con la normativa sanitaria peruana |
| Confidencialidad | Cabeceras `no-store` en toda respuesta con datos |
| Derechos del titular | Los datos se consultan y actualizan por profesional autorizado; la eliminación se sustituye por baja lógica para preservar la trazabilidad |

### 3.4 Criptografía (A.8.24)

| Uso | Algoritmo | Parámetro |
|---|---|---|
| Contraseñas | bcrypt | 12 rondas (4 en pruebas) |
| Firma de sesión | HMAC-SHA256 | Secreto de 64 caracteres generado con `secrets.token_urlsafe` |
| Integridad de recursos | SHA-384 (Subresource Integrity) | 2 recursos de terceros |

La gestión de claves sigue la regla: **la clave nunca se versiona**. `backend/.env` está excluido del
control de versiones y `SECRETOS_PROHIBIDOS` impide arrancar con valores conocidos.

### 3.5 Seguridad de las comunicaciones (A.8.20, A.8.21, A.8.24)

- HTTPS obligatorio en producción: la configuración rechaza el arranque si no se declara.
- HSTS con `max-age=31536000; includeSubDomains; preload`, emitido solo en producción para no
  romper el desarrollo local.
- CORS con lista blanca de orígenes; se rechaza el comodín cuando hay credenciales.
- `TrustedHostMiddleware` limita los encabezados `Host` admitidos.
- Limitación de tasa por IP en el login (10/minuto) y global (300/minuto).

### 3.6 Registro y monitoreo (A.8.15, A.8.16)

| Atributo | Registro |
|---|---|
| Qué | Acción, tabla afectada, identificador del registro |
| Quién | `usuario_id` |
| Cuándo | Marca temporal UTC |
| Dónde | Dirección IP y agente de usuario |
| Correlación | `request_id` enlazado a `X-Request-ID` |
| Severidad | Nivel `INFO`, `WARNING` o `SECURITY` |

El registro es **append-only**: la API expone únicamente consultas filtrables y paginadas. No hay
endpoint de modificación ni de eliminación (`CP-AUD-014`).

## 4. Cabeceras de seguridad (A.5.2, A.8.25)

| Cabecera | Valor | Propósito |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox` | La API no sirve contenido activo |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | HTTPS obligatorio (solo producción) |
| `X-Content-Type-Options` | `nosniff` | Evita la adivinanza de tipo |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `no-referrer` | No filtra la URL del paciente |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` | Datos clínicos fuera de caché |
| `Cross-Origin-Opener-Policy` | `same-origin` | Aislamiento de ventanas |
| `Cross-Origin-Resource-Policy` | `same-origin` | Bloqueo de recursos cruzados |
| `Permissions-Policy` | Deniega geolocalización, cámara, micrófono, pago, USB y others | Mínimo privilegio del navegador |
| `X-Permitted-Cross-Domain-Policies` | `none` | Desactiva compatibilidad heredada |
| `X-Request-ID` | Identificador por petición | Correlación de eventos |

En el cliente React la CSP se declara en `index.html` y limita los orígenes a `self` y al CDN
autorizado, con SRI en los recursos de terceros y sin `unsafe-eval`.

## 5. Gestión de incidentes (A.5.24, A.5.26)

| Etapa | Actuación |
|---|---|
| Detección | Resumen de seguridad de 24 h: eventos, logins exitosos y fallidos, cuentas bloqueadas, cambios de contraseña |
| Contención | Bloqueo temporal automático; el administrador puede restablecer la contraseña, lo que revoca las sesiones |
| Erradicación | Corrección de la causa raíz con prueba de regresión |
| Recuperación | Verificación de la suite completa antes de la redeploy |
| Aprendizaje | Registro de la no conformidad en `9001-trazabilidad.md` |

## 6. Gestión de vulnerabilidades y dependencias (A.8.8, A.8.19)

- Toda dependencia declara restricción de versión; verificado por `CP-OWASP-A06_001`.
- Los recursos de terceros del cliente llevan SRI (`CP-OWASP-A06_002`).
- La documentación de la API se desactiva en producción.
- **Pendiente:** integrar `pip-audit` y `npm audit` en el flujo de integración continua (riesgo
  R-14).

## 7. Continuidad, responsabilidades y desecho

| Control | Estado |
|---|---|
| Copia de seguridad | **Pendiente.** No hay copia automatizada de PostgreSQL (riesgo R-10) |
| RTO / RPO | **Pendiente de definir** (riesgo R-10) |
| Plan de respuesta ante ransomware | **Pendiente** (riesgo R-10) |
| Descarte seguro de soportes | **Pendiente.** El `.env` local contiene la clave de firma; al devolver la máquina debe revocarse la clave y eliminarse el fichero de forma segura |

## 8. Documentos relacionados

- `27001-declaracion-aplicabilidad.md` — SoA con los controles del Anexo A
- `27001-evaluacion-riesgos.md` — 16 riesgos analizados
- `27001-matriz-owasp-iso.md` — trazabilidad OWASP ↔ ISO ↔ pruebas
- `9001-politica-calidad.md` — objetivos de calidad derivados de estos controles