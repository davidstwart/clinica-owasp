import { createContext, useContext, useEffect, useState } from 'react';
import api, { guardarSesion, leerToken, leerUsuario, limpiarSesion } from '../services/api';

/**
 * Estado de autenticación — ISO/IEC 27001:2022 A.5.17 (información de
 * autenticación) y A.5.25 (revocación de sesiones).
 *
 * `debeCambiarContrasena` refleja la rotación obligatoria de la contraseña
 * inicial o restablecida por el administrador (A.5.17): mientras esté activa,
 * la interfaz solo permite cambiar la contraseña.
 *
 * OWASP A07 — cuando el servidor responde `mfa_requerido`, la sesión NO se
 * guarda: el cliente conserva el `mfa_token` de desafío (vida corta) y lo
 * canjea por el token real en `/api/auth/mfa/verificar`.
 */
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [usuario, setUsuario] = useState(null);
  const [cargando, setCargando] = useState(true);

  useEffect(() => {
    if (leerToken() && leerUsuario()) setUsuario(leerUsuario());
    setCargando(false);
  }, []);

  const iniciarSesion = (data) => {
    const u = {
      id: data.id,
      nombre: data.nombre,
      rol: data.rol,
      email: data.email,
      debeCambiarContrasena: data.debe_cambiar_contrasena,
    };
    guardarSesion(data.access_token, u);
    setUsuario(u);
    return u;
  };

  const login = async (email, password) => {
    const res = await api.post('/api/auth/login', { email, password });
    if (res.data.mfa_requerido) {
      return {
        mfaRequerido: true,
        mfaPendiente: Boolean(res.data.mfa_pendiente),
        mfaToken: res.data.mfa_token,
        nombre: res.data.nombre,
        rol: res.data.rol,
        email: res.data.email,
        debeCambiarContrasena: res.data.debe_cambiar_contrasena,
      };
    }
    return iniciarSesion(res.data);
  };

  /** A07 — canjea el código TOTP por el token de sesión. */
  const verificarMfa = async (mfaToken, codigo) => {
    const res = await api.post('/api/auth/mfa/verificar', {
      mfa_token: mfaToken,
      codigo,
    });
    return iniciarSesion(res.data);
  };

  /** A07 — genera (o rota) el secreto TOTP; se expone una sola vez. */
  const configurarMfa = async (mfaToken) => {
    const res = await api.post('/api/auth/mfa/configurar', { mfa_token: mfaToken });
    return res.data;
  };

  /** A07 — confirma el secreto demostrando posesión con un código válido. */
  const activarMfa = async (mfaToken, codigo) => {
    await api.post('/api/auth/mfa/activar', { mfa_token: mfaToken, codigo });
  };

  const cambiarContrasena = async (passwordActual, passwordNueva) => {
    await api.post('/api/auth/change-password', {
      password_actual: passwordActual,
      password_nueva: passwordNueva,
    });
    // El servidor revoca todos los tokens: es obligatorio volver a iniciar sesión.
    limpiarSesion();
    setUsuario(null);
  };

  const logout = async () => {
    try {
      await api.post('/api/auth/logout');
    } finally {
      limpiarSesion();
      setUsuario(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        usuario,
        login,
        verificarMfa,
        configurarMfa,
        activarMfa,
        logout,
        cambiarContrasena,
        cargando,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
