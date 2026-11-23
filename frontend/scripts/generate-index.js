/**
 * Genera `public/index.html` a partir de la plantilla, inyectando en la CSP
 * el origen real del API. CRA no sustituye variables de entorno dentro de
 * index.html, así que la política de connect-src se construye en el build.
 *
 * Uso: se ejecuta automáticamente como `prestart` y `prebuild`.
 */
const fs = require('fs');
const path = require('path');

const plantilla = path.join(__dirname, '..', 'public', 'index.template.html');
const destino = path.join(__dirname, '..', 'public', 'index.html');
const apiUrl = (process.env.REACT_APP_API_URL || 'http://localhost:8000').trim();

function origenDe(valor) {
  // Un baseURL relativo (/api) implica que el API se sirve en el mismo origen.
  if (valor.startsWith('/')) return "'self'";
  try {
    const url = new URL(valor);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('el protocolo debe ser http o https');
    }
    return url.origin;
  } catch (error) {
    console.error(`REACT_APP_API_URL inválido: ${valor} (${error.message})`);
    process.exit(1);
  }
}

const origen = origenDe(apiUrl);
const marcador = "connect-src 'self' __API_ORIGIN__;";
let html = fs.readFileSync(plantilla, 'utf8');

if (!html.includes(marcador)) {
  console.error('No se encontró el marcador de connect-src en la plantilla');
  process.exit(1);
}
html = html.replace(marcador, `connect-src 'self' ${origen};`);

fs.writeFileSync(destino, html, 'utf8');
console.log(`CSP connect-src generado para: ${origen}`);
