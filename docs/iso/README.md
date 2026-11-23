# Documentación Normativa ISO — Sistema Clínica OWASP

Este directorio reúne la documentación de calidad, seguridad de la información y pruebas del
proyecto, elaborada siguiendo las normas ISO/IEC e ISO que se indican en cada documento.

> **Alcance de esta documentación.** Los documentos describen la aplicación de los requisitos
> derivados de las normas dentro del proyecto. **No constituyen una certificación** ni sustituyen
> una auditoría externa realizada por un organismo acreditado. Las afirmaciones se apoyan
> exclusivamente en evidencia verificable del repositorio.

## Índice de documentos

### ISO 9001 — Sistemas de gestión de la calidad

| Documento | Contenido |
|---|---|
| [Sistema de gestión de calidad](9001-sistema-gestion-calidad.md) | Alcance, contexto, partes interesadas y ciclo PDCA |
| [Política de calidad](9001-politica-calidad.md) | Compromisos de la dirección y objetivos medibles |
| [Mapa de procesos](9001-mapa-procesos.md) | Procesos, responsables, entradas y salidas |
| [Matriz de trazabilidad](9001-trazabilidad.md) | Requisitos → controles → implementación → evidencia de prueba |

### ISO/IEC 25000 — Calidad del producto de software

| Documento | Contenido |
|---|---|
| [Calidad del producto](25000-calidad-producto.md) | Modelo de calidad aplicado, métricas y resultados |

### ISO/IEC 27001 — Seguridad de la información

| Documento | Contenido |
|---|---|
| [Política de seguridad](27001-politica-seguridad.md) | Principios, contorno de seguridad y responsabilidades |
| [Evaluación de riesgos](27001-evaluacion-riesgos.md) | Inventario de activos, amenazas, vulnerabilidades y tratamiento según ISO/IEC 27005 |
| [Declaración de aplicabilidad](27001-declaracion-aplicabilidad.md) | Controles del Anexo A, estado y justificación |
| [Matriz OWASP → ISO/IEC 27001](27001-matriz-owasp-iso.md) | Correspondencia entre OWASP Top 10 2021 y los controles implementados |

### ISO/IEC 29119 — Pruebas de software

| Documento | Contenido |
|---|---|
| [Plan de pruebas](29119-plan-de-pruebas.md) | Objetivos, estrategia, entorno, datos, criterios de entrada y salida |
| [Especificación de casos de prueba](29119-casos-de-prueba.md) | Los 203 casos definidos, con identificador, objetivo y control asociado |
| [Informe de pruebas](29119-informe-pruebas.md) | Resultados de la ejecución, cobertura, no conformidades y conclusión |

## Resumen de la última verificación

| Métrica | Valor |
|---|---|
| Casos de prueba ejecutados | 246 |
| Casos aprobados | 246 (100 %) |
| Cobertura de líneas de `src/` | 93,59 % |
| No conformidades detectadas | 4, todas cerradas |
| Elementos de trabajo pendientes | 9, documentados como riesgos residuales |

Detalle completo en [Informe de pruebas](29119-informe-pruebas.md).

## Verificación de la documentación

```bash
# Suite completa con cobertura
cd backend
./venv/bin/python -m pytest tests/ -v --cov=src --cov-report=term-missing

# Ejecución por categoría
./venv/bin/python -m pytest tests/ -m unit
./venv/bin/python -m pytest tests/ -m integration
./venv/bin/python -m pytest tests/ -m security

# Compilación del cliente
cd frontend && node node_modules/react-scripts/bin/react-scripts.js build
```

El informe de cobertura en formato legible por máquina se genera en `backend/docs_cobertura.json`.

## Cómo se mantiene esta documentación

| Documento | Se actualiza cuando |
|---|---|
| Política y sistema de calidad | Cambian el alcance, el contexto o los objetivos del proyecto |
| Mapa de procesos y trazabilidad | Se añade, modifica o elimina un proceso o un requisito |
| Calidad del producto | Cambian las métricas o el resultado de una medición |
| Política, riesgos y SoA | Cambia un control, un activo o la valoración de un riesgo |
| Matriz OWASP | Se implementa o retira una mitigación |
| Plan, casos e informe | Se modifica la suite o se ejecuta una nueva campaña |