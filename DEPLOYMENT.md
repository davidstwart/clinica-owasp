# Despliegue (Render + Vercel)

El repositorio incluye dos definiciones listas para usar:

- `render.yaml`: API FastAPI + PostgreSQL + sitio estático (todo en Render).
- `vercel.json`: solo el frontend React (el API sigue en Render).

La API **no** se despliega en Vercel: es un servidor FastAPI de larga duración.
Vercel se usa únicamente para el sitio estático de React.

---

## Opción A — Todo en Render (recomendado, más simple)

1. Sube este commit a GitHub.
2. En Render: **New → Blueprint**.
3. Conecta el repositorio `davidstwart/clinica-owasp`, rama `main`.
4. Render detectará `render.yaml` y creará:
   - `clinica-owasp-api` (web service, Python)
   - `clinica-owasp-db` (PostgreSQL)
   - `clinica-owasp-web` (sitio estático)
5. **Apply**. Espera a que los tres recursos estén `Live`.
6. Tras el primer deploy, `initialDeployHook` ejecuta `python seed.py`.
   Revisa los logs del servicio API: ahí se imprime **una sola vez** la clave
   TOTP del administrador. Guárdala en tu autenticador.
7. Abre la URL del sitio web (`https://clinica-owasp-web.onrender.com`) y entra
   con las credenciales de demostración del README. El administrador pedirá
   además el código TOTP y el cambio de contraseña inicial.

> Si Render añade un sufijo al nombre de algún servicio o usas dominios
> propios, actualiza `ALLOWED_ORIGINS` en la API (y `REACT_APP_API_URL` en el
> frontend si cambia el dominio del API) y vuelve a desplegar.

---

## Opción B — Frontend en Vercel + API en Render

1. Aplica el Blueprint de Render (opción A). Si no quieres el sitio estático de
   Render, elimina del `render.yaml` el bloque `name: clinica-owasp-web` antes
   de aplicarlo.
2. En Vercel: **Add New → Project** e importa el mismo repositorio.
3. No hace falta cambiar el Root Directory: `vercel.json` ya ejecuta los
   comandos dentro de `frontend/`.
4. En **Environment Variables** añade, para Production:

   ```text
   REACT_APP_API_URL = https://clinica-owasp-api.onrender.com
   ```

5. Deploy. El mismo valor se usa para `axios` y para generar el
   `connect-src` de la Content-Security-Policy.
6. Si tu proyecto de Vercel tiene otro nombre, añade su dominio real a
   `ALLOWED_ORIGINS` en la API de Render, por ejemplo:

   ```text
   https://clinica-owasp.vercel.app,https://mi-proyecto.vercel.app
   ```

   y vuelve a desplegar la API (CORS con `allow_credentials` exige orígenes
   exactos; no admite comodines).

---

## Detalles importantes

| Tema | Valor / comportamiento |
|---|---|
| Start command (Render) | `uvicorn src.main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"` |
| Health check | `/health` |
| CSP del frontend | Se genera desde `REACT_APP_API_URL` mediante `frontend/scripts/generate-index.js` (`prestart` / `prebuild`). La plantilla es `frontend/public/index.template.html`. |
| Hosts confiables | Render inyecta `RENDER_EXTERNAL_HOSTNAME`; `backend/src/config.py` lo añade a `TRUSTED_HOSTS`. |
| Formato de listas | `ALLOWED_ORIGINS` y `TRUSTED_HOSTS` aceptan `a,b,c` o `["a","b"]` en variables de entorno. |
| TLS | `FORZAR_TLS=true` + `--proxy-headers` evitan redirecciones infinitas detrás del proxy de Render. |
| Semilla | `initialDeployHook` solo corre en el **primer** deploy. Si se recrea la BD, ejecuta `python seed.py` desde el Shell de Render. |
| Plan gratuito | El web service se suspende por inactividad (primera petición lenta) y la BD gratuita tiene limitaciones de retención. Revisa las condiciones vigentes de Render. |

## Seguridad

- Las credenciales de demostración están publicadas en el README: cámbialas
  antes de usar el sistema con datos reales.
- `SECRET_KEY` y `CIFRADO_CLAVE` se generan automáticamente en Render y no se
  versionan. No las reemplaces por los valores de `backend/.env.example`.
- El secreto TOTP del administrador aparece en los logs de la semilla; no
  compartas esos logs.
- `HABILITAR_DOCS=false` desactiva `/docs`, `/redoc` y `/openapi.json` en producción.
