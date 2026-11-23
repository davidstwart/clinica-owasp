/**
 * Cliente HTTP — ISO/IEC 27001:2022 A.8.24 / OWASP A02, A05, A07.
 *
 * Controles aplicados en el lado del cliente:
 *  · El token JWT se mantiene en `sessionStorage`, no en `localStorage`:
 *    `localStorage` persiste entre sesiones y es legible por cualquier script
 *    inyectado (XSS) de forma indefinida (A.8.25).
 *  · Se envía `X-Request-ID` para correlacionar la acción con el registro de
 *    auditoría del servidor (A.8.15 / A.8.16).
 *  · Una respuesta 401 o la cabecera `X-Auth-Error-Code` provocan cierre de
 *    sesión local; nunca se guarda la contraseña ni el token en el registro.
 */
import axios from 'axios';

const CLAVE_TOKEN = 'clinica_token';
const CLAVE_USUARIO = 'clinica_usuario';

const idRequest = () => {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  if (window.crypto?.getRandomValues) {
    const bytes = window.crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  return `${Date.now()}`;
};

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
  headers: { 'X-Request-ID': idRequest() },
});

export const guardarSesion = (token, usuario) => {
  sessionStorage.setItem(CLAVE_TOKEN, token);
  sessionStorage.setItem(CLAVE_USUARIO, JSON.stringify(usuario));
};

export const leerToken = () => sessionStorage.getItem(CLAVE_TOKEN);

export const leerUsuario = () => {
  try {
    return JSON.parse(sessionStorage.getItem(CLAVE_USUARIO) || 'null');
  } catch {
    return null;
  }
};

export const limpiarSesion = () => {
  sessionStorage.removeItem(CLAVE_TOKEN);
  sessionStorage.removeItem(CLAVE_USUARIO);
};

api.interceptors.request.use((config) => {
  const token = leerToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const estado = err.response?.status;
    const codigo = err.response?.headers?.['x-auth-error-code'];
    if (estado === 401 || codigo === 'DEBE_CAMBIAR_CONTRASENA') {
      limpiarSesion();
      if (estado === 401 && window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export default api;
