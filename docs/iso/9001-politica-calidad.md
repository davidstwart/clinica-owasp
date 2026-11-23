# Política y Objetivos de Calidad — ISO 9001:2015 §5.2, §6.2

**Proyecto:** Sistema Clínica OWASP Top 10 2021
**Versión:** 1.0

---

## 1. Política de calidad

La dirección del proyecto se compromete a entregar un sistema de gestión clínica que sea
**correcto, seguro y verificable**. La calidad no se declara: se demuestra con evidencia objetiva
reproducible.

La política se sostiene en cuatro compromisos:

1. **Seguridad de la información como requisito de primer nivel.** Los datos que se procesan son
   datos personales sensibles de salud. El acceso se restringe por rol, se registra y se audita.
2. **Verificación automatizada e independiente del autor.** Cada cambio funcional incorpora sus
   casos de prueba. La suite completa debe aprobarse al 100 % antes de cualquier entrega.
3. **Trazabilidad bidireccional.** Todo requisito normativo y todo control de seguridad está
   vinculado al menos a un caso de prueba; todo caso de prueba está vinculado a un requisito.
4. **No conformidad como hallazgo, no como blame.** Los defectos detectados durante la verificación
   se registran, se corrigen y quedan cubiertos por una prueba de regresión que impide la recaída.

## 2. Objetivos de calidad

Los objetivos se derivan de los riesgos detectados en `27001-evaluacion-riesgos.md` y se
desglosan en metas medibles con evidencia.

| # | Objetivo | Indicador | Meta 2026 | Resultado verificado | Evidencia |
|---|---|---|---|---|---|
| O1 | Eliminar accesos no controlados | Rutas de API con dependencia de seguridad verificada | 100 % | **100 %** (21 rutas) | `CP-RBAC-011` |
| O2 | Proteger la historia clínica | Casos de prueba de integridad de datos clínicos | ≥ 10 | **11** | `test_06_negocio.py` |
| O3 | Fiabilidad del producto | Casos aprobados sobre casos ejecutados | 100 % | **246/246** | Informe de pruebas |
| O4 | Mantenibilidad | Cobertura de líneas de `src/` | ≥ 90 % | **93,59 %** | Informe de cobertura |
| O5 | Detección de incidentes | Casos de seguridad aprobados | 100 % | **104/104** | Marcador `security` |
| O6 | Configuración segura por diseño | Casos de fallo de configuración detectados | ≥ 8 | **10** | `test_10_configuracion.py` |
| O7 | Verificabilidad de la interfaz | Compilación sin errores ni advertencias de ESLint | Correcta | **Correcta** | Registro de compilación |

## 3. Despliegue de los objetivos

### O1 — Eliminar accesos no controlados

Se implementó una prueba de caja blanca (`CP-RBAC-011`) que recorre el objeto `Dependant` de cada
ruta de la aplicación y exige que exista una cadena de dependencias de seguridad. Esta prueba
detectó la no conformidad **NC-02**: los parámetros de autorización escritos sin anotación de tipo
(`_=todos`) no se registran como dependencia en FastAPI, por lo que el endpoint quedaba accesible
sin sesión. La corrección.annotó las dependencias y la prueba de estructura
(`CP-RBAC-012`) verifica que `usuario_operativo` y `obtener_usuario_actual` queden encadenadas.

### O2 — Proteger la historia clínica

Las atenciones clínicas y los DNI son irremplazables. Las reglas implementadas y verificadas:

- Un paciente con historial clínico no puede eliminarse (`CP-NEG-004`).
- Un paciente no puede darse de baja si tiene historial; se desvincula lógicamente.
- Un usuario con atenciones registradas no puede eliminarse (`CP-USR-011`).
- El `medico_id` de una atención se toma del token, nunca del cuerpo de la petición
  (`CP-NEG-025`).
- Una atención no puede vincularse a una cita de otro paciente (`CP-NEG-029`) ni a una cita
  cancelada (`CP-NEG-030`).

### O3 y O4 — Fiabilidad y mantenibilidad

La suite se ejecuta con `pytest` e informe de cobertura. Los umbrales de aceptación están
definidos en `29119-informe-pruebas.md`. La cobertura por módulo se revisa para que ningún
componente de seguridad quede por debajo del 84 %.

### O6 — Configuración segura por diseño

`src/config.py` implementa validación con *fail-closed*: el proceso no arranca si el secreto de
firma es público, demasiado corto, con poca variedad o con un entorno de producción inseguro. Los
diez casos de `test_10_configuracion.py` ejecutan los validadores en un subproceso aislado para
verificar el comportamiento real de arranque.

## 4. Medición y revisión

| Elemento | Evidencia de medición |
|---|---|
| Integridad del producto | Suite de pruebas + informe de cobertura |
| Eficacia de los controles | Marcadores `security` y `unit` de pytest |
| Eficacia de la respuesta a incidentes | Registro de auditoría y resumen de 24 h |
| Cumplimiento normativo | Matriz de trazabilidad `9001-trazabilidad.md` |

**Frecuencia de revisión:** en cada cierre de sprint y antes de cada entrega.

## 5. Acción correctiva

El procedimiento ante una no conformidad es: registrar, corregir la causa raíz, añadir la prueba de
regresión, volver a ejecutar la suite completa y documentar el hallazgo en el informe de pruebas.
Los dos casos atendidos durante este proyecto (NC-01 y NC-02) se detallan en
`9001-sistema-gestion-calidad.md` §8.4.