# 🏥 Sistema Web Clínica — OWASP Top 10 2021

> **Tesis:** "Sistema web con controles de seguridad basados en OWASP Top 10 2021 y su influencia en la seguridad de la información en clínicas privadas de la región Junín, 2026"
> **Autor:** Ñaupari Camarena, Julio Armando
> **Universidad Continental — Ing. de Sistemas e Informática**
> **Herramienta IA utilizada:** Claude (Anthropic) — Claude Code

---

## 🛡️ Controles OWASP Top 10 2021 Implementados

| Control | Riesgo | Implementación | Verificado por |
|---|---|---|---|
| A01 | Control de acceso roto | RBAC con tres roles, dependencias de autorización registradas y verificación estructural de todas las rutas | `CP-RBAC-*`, `CP-OWASP-A01-*` |
| A02 | Fallos criptográficos | bcrypt, JWT HS256 con `iss`/`aud`/`exp`/`jti`, versión de token para revocación inmediata | `CP-SEG-*`, `CP-OWASP-A02-*` |
| A03 | Inyección | SQLAlchemy ORM, validación Pydantic y escapes en la interfaz | `CP-OWASP-A03-*` |
| A04 | Diseño inseguro | Esquemas que rechazan campos no declarados, reglas de negocio en el servidor, paginación acotada | `CP-OWASP-A04-*` |
| A05 | Configuración incorrecta | Arranque *fail-closed*, cabeceras defensivas, CORS con lista blanca, hosts confiables, documentación desactivable | `CP-CFG-*`, `CP-OWASP-A05-*` |
| A06 | Componentes vulnerables | Versiones fijadas, Subresource Integrity en el cliente, sin exposición de versiones | `CP-OWASP-A06-*` |
| A07 | Fallas de autenticación | Bloqueo tras 5 intentos, mensaje anti-enumeración, revocación, rotación obligatoria de contraseña | `CP-AUT-*`, `CP-OWASP-A07-*` |
| A08 | Fallos de integridad y datos | Sin sobrescritura de campos de sistema, recurso verificado contra la petición, borrado bloqueado con historial | `CP-OWASP-A08-*` |
| A09 | Fallas de registro y monitoreo | Auditoría append-only con correlación por `request_id` en cada petición | `CP-AUD-*`, `CP-OWASP-A09-*` |
| A10 | SSRF | La aplicación no realiza peticiones salientes | `CP-OWASP-A10-001` |

---

## 🗂️ Estado del Arte

### Pregunta de investigación
¿En qué medida la implementación de un sistema web con controles de seguridad basados en el estándar OWASP Top 10 2021 influye en la seguridad de la información en clínicas privadas de Huancayo, Junín, 2026?

### Estrategia de búsqueda
- **Bases de datos:** IEEE Xplore, Scopus, Dialnet, Redalyc, SciELO
- **Período:** 2018–2025
- **Idiomas:** Español e inglés
- **Total identificados:** 811 artículos
- **Total seleccionados:** 16 artículos

### Artículos seleccionados

| Código | Autores | Año | Título | Fuente |
|---|---|---|---|---|
| ART_1 | Álava, K.; Basurto, W. & Tóala, R. | 2022 | Vulnerabilidades en los sistemas informáticos OWASP Top 10: revisión bibliográfica | Dialnet |
| ART_2 | Carrión, E. & Proaño, J. | 2024 | Metodología OWASP: prevención de vulnerabilidades en aplicaciones web | Dialnet |
| ART_3 | Vega-Oyola, C.; Tapia, E. & Gallardo, F. | 2022 | Análisis de factores de seguridad informática mediante la metodología OWASP v4.2: caso ISTJOL | SciELO |
| ART_4 | González Brito, A. & Montesino, R. | 2018 | Capacidades de las metodologías de pruebas de penetración para vulnerabilidades web | SciELO Cuba |
| ART_5 | González Brito, A.; Montesino, R. & Gainza, G. | 2021 | Riesgos de seguridad en las pruebas de penetración de aplicaciones web | Redalyc |
| ART_6 | Niño Benítez, Y. & Silega Martínez, N. | 2018 | Requisitos de seguridad para aplicaciones web | SciELO Cuba |
| ART_7 | Ramírez Patajalo, G. A. | 2023 | Seguridad en desarrollo web: mejores prácticas para proteger aplicaciones y datos | Dialnet |
| ART_8 | Choiriyah, A. & Qomariasih, N. | 2023 | Security Analysis on Websites belonging to the Health Service Districts based on OWASP Top 10 2021 | IEEE |
| ART_9 | Gomero-Cuadra, R. & Sánchez-Calle, D. | 2024 | Ciberseguridad en servicios de apoyo al médico ocupacional de la ciudad de Lima | SciELO Perú |
| ART_10 | Cervera García, A. & Goussens, A. | 2024 | Ciberseguridad y uso de las TIC en el Sector Salud | ScienceDirect |
| ART_11 | Salazar-Lazo, C. & Avila-Correa, B. | 2024 | Estándares de ciberseguridad aplicables a los sistemas informáticos sanitarios | Dialnet |
| ART_12 | Coronel Suárez, S. & Quirumbay, D. | 2022 | Seguridad informática, metodologías, estándares y aplicaciones web | Redalyc |
| ART_13 | Pillajo-García, P. & Avila-Pesantez, D. | 2023 | Ciberseguridad en plataformas digitales: revisión sistemática | Dialnet |
| ART_14 | Morales-Paredes, C. & Medina-Chicaiza, R. | 2021 | Análisis de ciberseguridad en clínicas: vulnerabilidades en plataformas web de salud | Dialnet |
| ART_15 | Solís, B. et al. | 2023 | Seguridad de los sistemas informáticos: retos pendientes en organizaciones del sector salud | REICIT |
| ART_16 | Pillajo Pila, K. et al. | 2025 | Ciberseguridad y su integración en los sistemas de organizaciones de salud de Latinoamérica | Dialnet |

### Hallazgos principales
- OWASP supera al 76% de metodologías alternativas en cobertura de vulnerabilidades (ART_4)
- El 83% de organizaciones de salud experimentó brechas en 2022 con costo promedio de $4.35M por incidente (ART_9)
- Sistemas web de salud sin controles OWASP presentan hasta 11 vulnerabilidades activamente explotables (ART_8)
- El sector salud en Latinoamérica registra 388 incidentes de ciberseguridad por día (ART_16)

---

## 🚀 Instalación rápida

### Backend
```bash
cd backend
python3 -m venv venv
./venv/bin/pip install -r requirements-dev.txt      # Linux/macOS
# venv\Scripts\pip install -r requirements-dev.txt   # Windows
cp .env.example .env                                # y edita DATABASE_URL y SECRET_KEY
./venv/bin/python seed.py
./venv/bin/python -m uvicorn src.main:app --reload --port 8000
```

La aplicación se niega a arrancar si la configuración es insegura: `SECRET_KEY` ausente, con el valor
de ejemplo, demasiado corto o con poca variedad, `DEBUG=True`, orígenes con comodín o `localhost`,
o una vida de token excesiva en producción. Los valores por omisión son seguros para desarrollo.

### Frontend
```bash
cd frontend
npm install
npm start
```

---

## 🌐 Despliegue

Instrucciones y archivos de configuración para subir el sistema a Render y/o Vercel:
[DEPLOYMENT.md](DEPLOYMENT.md) (`render.yaml` y `vercel.json`).

---

## 🧪 Verificación

```bash
cd backend
./venv/bin/python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

| Métrica | Resultado de la última ejecución |
|---|---|
| Casos de prueba | **246**, todos aprobados |
| Unitarias / integración / seguridad | 74 / 172 / 104 |
| Cobertura de líneas de `src/` | **93,59 %** |
| Compilación del cliente React | Correcta, sin errores de ESLint |

Detalle en [`docs/iso/29119-informe-pruebas.md`](docs/iso/29119-informe-pruebas.md).

---

## 📁 Estructura del proyecto
```
clinica-owasp/
├── backend/
│   ├── src/
│   │   ├── auth/         → A01 + A02 + A07: autenticación, JWT, RBAC, política de contraseñas
│   │   ├── pacientes/    → CRUD con bloqueo de borrado si hay historial
│   │   ├── citas/        → Agenda médica y máquina de estados
│   │   ├── atenciones/   → Historial clínico
│   │   ├── auditoria/    → A09: registro append-only con correlación
│   │   ├── middleware/   → Cabeceras de seguridad y request_id
│   │   ├── config.py     → Arranque fail-closed
│   │   └── main.py       → Aplicación, CORS, hosts y limitador de tasa
│   ├── tests/            → 246 casos en 11 archivos
│   ├── seed.py           → Datos de demostración idempotentes
│   └── docs_cobertura.json
├── frontend/
│   ├── public/index.html → CSP y Subresource Integrity
│   └── src/              → Páginas, componentes, contexto de autenticación
└── docs/iso/             → Documentación normativa (ver docs/iso/README.md)
```

---

## 🔑 Credenciales de demostración

Creadas por `backend/seed.py`. Las tres exigen rotación de contraseña en el primer acceso.

| Rol | Correo | Contraseña inicial |
|---|---|---|
| Administrador | admin@clinica.pe | `Huancayo#Root2026` |
| Médico | medico@clinica.pe | `Huancayo#Dr2026` |
| Recepcionista | recep@clinica.pe | `Huancayo#Agenda2026` |

> Son credenciales de demostración publicadas en el repositorio. No las utilices en un entorno real.

---

## 📊 Normas ISO aplicadas

La documentación completa está en [`docs/iso/`](docs/iso/README.md).

| Norma | Documentación |
|---|---|
| ISO 9001:2015 | Sistema de gestión de calidad, política, mapa de procesos y trazabilidad |
| ISO/IEC 25010 | Calidad del producto de software: métricas de eficiencia, fiabilidad y seguridad |
| ISO/IEC 27001:2022 | Política de seguridad, evaluación de riesgos (27005), declaración de aplicabilidad y matriz OWASP |
| ISO/IEC 29119-2:2021 | Plan de pruebas, especificación de casos e informe de ejecución |

> Esta documentación describe la aplicación de los requisitos dentro del proyecto. **No constituye
> una certificación** ni reemplaza una auditoría externa.
