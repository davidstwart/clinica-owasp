# Mapa de Procesos e Indicadores — ISO 9001:2015 §4.4

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Enfoque basado en procesos

El sistema se modela como una cadena de seis macroprocesos. Cada uno declara entradas, salidas,
responsable, recursos y al menos un indicador verificable.

```
   [P1 Gestión de configuración de seguridad]
                     |
                     v
   [P2 Autenticación y control de acceso] <--- [P3 Gestión de cuentas]
                     |
                     v
   [P4 Registro clínico] --- [P5 Agenda de citas]
                     |
                     v
   [P6 Auditoría y monitoreo]  -->  retroalimenta P1, P2, P3
```

## 2. Inventario de procesos

### P1 — Gestión de configuración de seguridad

| | |
|---|---|
| **Objetivo** | Garantizar que la aplicación solo operará con parámetros de seguridad validados. |
| **Entradas** | Variables de entorno, `.env`, despliegue |
| **Salidas** | Proceso operativo o fallo de arranque explícito |
| **Responsable** | Administración del sistema |
| **Controles** | Validación *fail-closed* de secretos y entorno (`config.py`) |
| **Indicador** | Casos de configuración validados: **16** (`test_10_configuracion.py`) |
| **Registro** | `.env.example` documenta los parámetros sin exponer secretos reales |

### P2 — Autenticación y control de acceso

| | |
|---|---|
| **Objetivo** | Autenticar al usuario, emitir y revocar su sesión, y autorizar cada operación según su rol. |
| **Entradas** | Credenciales, token Bearer, rol del usuario |
| **Salidas** | Token JWT, identidad del usuario, decisión de acceso |
| **Responsable** | Todos los usuarios del sistema |
| **Controles** | bcrypt, bloqueo por intentos fallidos, anti-enumeración, JWT con `iss`/`aud`/`jti`/`exp`/`ver`, rotación obligatoria de contraseña, RBAC |
| **Indicador** | Casos de seguridad de sesión aprobados: **20** (`test_04_auth_api.py`) + **39** (`test_05_rbac.py`) |
| **Trazabilidad** | A.5.15, A.5.17, A.5.25, A.8.24 |

### P3 — Gestión de cuentas

| | |
|---|---|
| **Objetivo** | Crear, editar y dar de baja cuentas con mínimo privilegio y registro de cada acción. |
| **Entradas** | Datos del usuario, rol, credencial inicial |
| **Salidas** | Cuenta creada, editada o desactivada; auditoría asociada |
| **Responsable** | Administrador del sistema |
| **Controles** | Solo el administrador opera sobre cuentas; toda cuenta nace con rotación obligatoria; no se elimina un usuario con historial clínico ni la propia cuenta |
| **Indicador** | Casos de gestión de cuentas: **14** (`test_11_usuarios.py`) |

### P4 — Registro clínico (pacientes y atenciones)

| | |
|---|---|
| **Objetivo** | Mantener la información del paciente y su historia clínica íntegra, trazable e inalterable en lo esencial. |
| **Entradas** | Datos del paciente, diagnóstico, tratamiento |
| **Salidas** | Expediente, historial por paciente, auditoría de la operación |
| **Responsable** | Personal médico y administrativo |
| **Controles** | Validación estricta en el borde; eliminación física cuando no hay historial y bloqueo cuando sí lo hay; paginación obligatoria; el `medico_id` se toma del token; auditoría de cada alta, edición y baja |
| **Indicador** | Casos de negocio: **34** (`test_06_negocio.py`) |
| **Trazabilidad** | A.5.33, A.8.15, A.8.26 |

### P5 — Agenda de citas

| | |
|---|---|
| **Objetivo** | Registrar y administrar citas sin solapamientos y con transiciones de estado válidas. |
| **Entradas** | Paciente, médico, fecha y hora, motivo |
| **Salidas** | Cita creada o transicionada; agenda consultable |
| **Responsable** | Recepción (agenda) y médico (cierre de consulta) |
| **Controles** | Verificación de existencia de paciente y médico; rechazo de solapamientos; máximo 16 citas diarias por médico; máquina de estados; el recepcionista solo cancela; el médico asignado confirma y atiende; el administrador puede confirmar y atender |
| **Indicador** | Casos de agenda: **24** (`test_06_negocio.py`, CP-NEG-013 a CP-NEG-024) |

### P6 — Auditoría y monitoreo

| | |
|---|---|
| **Objetivo** | Poder reconstruir quién hizo qué, cuándo y desde dónde. |
| **Entradas** | Eventos de autenticación, cambios sobre datos, peticiones HTTP |
| **Salidas** | Registro de auditoría consultable, indicadores de 24 h, `X-Request-ID` por petición |
| **Responsable** | Administrador del sistema |
| **Controles** | Registro *append-only* (la API no expone alta, edición ni borrado); retención configurada a 5 años; correlación por petición; niveles de severidad |
| **Indicador** | Casos de auditoría: **16** (`test_07_auditoria.py`) |
| **Trazabilidad** | A.8.15, A.8.16 |

## 3. Matriz de interrelación

| Proceso | Entrada desde | Salida hacia |
|---|---|---|
| P1 | — | P2, P3, P4, P5, P6 |
| P2 | P1 | P3, P4, P5, P6 |
| P3 | P2 | P4, P5 |
| P4 | P2, P3 | P5, P6 |
| P5 | P2, P3, P4 | P4, P6 |
| P6 | Todos | P1, P2, P3 (retroalimentación) |

## 4. Indicadores consolidados

| Proceso | Indicador | Meta | Resultado |
|---|---|---|---|
| P1 | Casos de configuración | ≥ 8 | 16 |
| P2 | Casos de sesión y RBAC | ≥ 30 | 59 |
| P3 | Casos de cuentas | ≥ 10 | 14 |
| P4 | Casos de registro clínico | ≥ 15 | 18 |
| P5 | Casos de agenda | ≥ 15 | 16 |
| P6 | Casos de auditoría | ≥ 10 | 16 |
| Transversal | Casos de cabeceras de seguridad | ≥ 10 | 15 |
| Transversal | Casos OWASP Top 10 | ≥ 20 | 25 |

**Total: 246 casos, todos aprobados.**

## 5. EFI seis pasos del enfoque basado en procesos

1. **Determinar** los procesos y sus responsables (este documento).
2. **Establecer** entradas, salidas e interrelaciones (§3).
3. **Definir** recursos y criterios de aceptación (objetivos de calidad).
4. **Asignar** responsabilidades por proceso (tablas anteriores).
5. **Evaluar** el desempeño con los indicadores (§4).
6. **Mejorar** mediante acciones correctivas registradas en el informe de pruebas.