import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// Cuentas de demostración — deben coincidir con backend/seed.py.
// ISO/IEC 27001 A.5.17: el sistema exige rotarlas en el primer acceso, por lo
// que se piden aquí solo para facilitar la evaluación.
const DEMOS = [
  { rol: 'Admin',     email: 'admin@clinica.pe', pass: 'Huancayo#Root2026'   },
  { rol: 'Médico',    email: 'medico@clinica.pe', pass: 'Huancayo#Dr2026'    },
  { rol: 'Recepción', email: 'recep@clinica.pe',  pass: 'Huancayo#Agenda2026' },
];

/**
 * Acceso al sistema en tres pasos: credenciales → (opcional) configuración de
 * TOTP cuando el segundo factor está pendiente → código de verificación.
 * OWASP A07:2021 y A05:2021 (diseño seguro de autenticación).
 */
export default function Login() {
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [error,    setError]    = useState('');
  const [loading,  setLoading]  = useState(false);
  const [showPass, setShowPass] = useState(false);

  // flujo MFA
  const [paso,     setPaso]     = useState('credenciales'); // credenciales | configurar | codigo
  const [desafio,  setDesafio]  = useState(null);
  const [config,   setConfig]   = useState(null);
  const [codigo,   setCodigo]   = useState('');

  const { login, verificarMfa, configurarMfa, activarMfa } = useAuth();
  const navigate  = useNavigate();

  const navegar = (u) => {
    void navigate(u.debeCambiarContrasena ? '/cambiar-contrasena' : '/dashboard');
  };

  const detalleError = (err, fallback) => {
    const d = err.response?.data?.detail;
    return typeof d === 'string' ? d : fallback;
  };

  // El secreto TOTP se pide al entrar al paso de configuración (una sola vez).
  useEffect(() => {
    if (paso !== 'configurar' || !desafio || config) return;
    configurarMfa(desafio.mfaToken)
      .then(setConfig)
      .catch((err) => setError(detalleError(err, 'No se pudo generar el secreto MFA.')));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paso, desafio, config]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      const r = await login(email, password);
      if (r.mfaRequerido) {
        setDesafio(r);
        setConfig(null);
        setCodigo('');
        setPaso(r.mfaPendiente ? 'configurar' : 'codigo');
      } else {
        navegar(r);
      }
    } catch (err) {
      setError(detalleError(err, 'Error al iniciar sesión. Verifica tus credenciales.'));
    } finally {
      setLoading(false);
    }
  };

  const enviarCodigo = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      const u = await verificarMfa(desafio.mfaToken, codigo);
      navegar(u);
    } catch (err) {
      setError(detalleError(err, 'No se pudo verificar el código MFA.'));
    } finally {
      setLoading(false);
    }
  };

  const activarYEntrar = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      await activarMfa(desafio.mfaToken, codigo);
      // Con el secreto activo, el mismo código canjea la sesión.
      const u = await verificarMfa(desafio.mfaToken, codigo);
      navegar(u);
    } catch (err) {
      setError(detalleError(err, 'No se pudo activar el MFA.'));
    } finally {
      setLoading(false);
    }
  };

  const volver = () => {
    setError(''); setCodigo(''); setConfig(null); setDesafio(null);
    setPaso('credenciales');
  };

  const campoCodigo = (
    <div style={{ marginBottom: 22 }}>
      <label className="form-label-custom" htmlFor="login-codigo">Código de 6 dígitos</label>
      <input
        id="login-codigo"
        inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]*"
        className="form-control-custom" placeholder="000000"
        maxLength={6} value={codigo}
        onChange={e => setCodigo(e.target.value.replace(/\D/g, ''))}
        required
        style={{ letterSpacing: '6px', textAlign: 'center', fontSize: 20 }}
      />
      <p style={{ fontSize: 11, color: '#94a3b8', marginTop: 8 }}>
        <i className="bi bi-shield-lock"></i> Open Authenticator / Google Authenticator
      </p>
    </div>
  );

  const bloqueError = error && (
    <div className="alert-custom alert-error">
      <i className="bi bi-exclamation-circle-fill" style={{ flexShrink: 0 }}></i>
      <span>{error}</span>
    </div>
  );

  const boton = (texto, icono) => (
    <button type="submit" className="btn-primary-custom"
      style={{ width:'100%', justifyContent:'center', padding:'11px 0', fontSize:14 }}
      disabled={loading}>
      {loading
        ? <><i className="bi bi-hourglass-split"></i> Verificando...</>
        : <><i className={`bi bi-${icono}`}></i> {texto}</>
      }
    </button>
  );

  return (
    <div className="login-page">
      <div className="login-card">

        {/* Logo */}
        <div className="login-logo">
          <div className="icon-wrap"><i className="bi bi-hospital"></i></div>
          <h1>Sistema Clínica</h1>
          <p>Gestión segura de información médica</p>
          <div className="owasp-tag">
            <i className="bi bi-shield-check"></i>
            OWASP Top 10 2021 · ISO/IEC 27001
          </div>
        </div>

        {bloqueError}

        {/* ── Paso 1: credenciales ─────────────────────────── */}
        {paso === 'credenciales' && (
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: 16 }}>
              <label className="form-label-custom" htmlFor="login-email">Correo electrónico</label>
              <input
                id="login-email"
                type="email" className="form-control-custom"
                placeholder="usuario@clinica.pe"
                value={email} onChange={e => setEmail(e.target.value)}
                required autoComplete="username" maxLength={150}
              />
            </div>

            <div style={{ marginBottom: 22 }}>
              <label className="form-label-custom" htmlFor="login-password">Contraseña</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="login-password"
                  type={showPass ? 'text' : 'password'}
                  className="form-control-custom"
                  placeholder="••••••••"
                  value={password} onChange={e => setPassword(e.target.value)}
                  required autoComplete="current-password" maxLength={128}
                  style={{ paddingRight: 42 }}
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  aria-label={showPass ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                  style={{ position:'absolute', right:10, top:'50%', transform:'translateY(-50%)',
                    background:'none', border:'none', cursor:'pointer', color:'#94a3b8', fontSize:16 }}>
                  <i className={`bi bi-eye${showPass ? '-slash' : ''}`}></i>
                </button>
              </div>
            </div>

            {boton('Ingresar al sistema', 'box-arrow-in-right')}
          </form>
        )}

        {/* ── Paso 2a: configuración pendiente del segundo factor ── */}
        {paso === 'configurar' && desafio && (
          <form onSubmit={activarYEntrar}>
            <p style={{ fontSize: 13, color: '#334155', marginBottom: 14 }}>
              <i className="bi bi-shield-exclamation" style={{ color: '#b45309' }}></i>
              Hola <strong>{desafio.nombre}</strong>: tu cuenta administrativa debe
              activar el segundo factor (A07). Registra esta clave en tu
              autenticador y confirma con un código.
            </p>

            <span className="form-label-custom">Clave secreta TOTP</span>
            <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:10 }}>
              <code className="tag" style={{ fontSize:13, wordBreak:'break-all', flex:1 }}>
                {config ? config.clave : 'Generando...'}
              </code>
              {config && (
                <button type="button" className="btn-outline-custom"
                  style={{ padding:'5px 10px', fontSize:12 }}
                  onClick={() => navigator.clipboard?.writeText(config.clave)}>
                  <i className="bi bi-clipboard"></i>
                </button>
              )}
            </div>

            {config && (
              <a href={config.otpauth_uri} target="_blank" rel="noreferrer"
                style={{ fontSize:11, color:'#0f4c81', display:'block', marginBottom:16 }}>
                <i className="bi bi-phone"></i> Abrir en la aplicación de autenticación
              </a>
            )}

            {campoCodigo}
            {boton('Activar y entrar', 'shield-check')}
            <button type="button" className="btn-outline-custom"
              style={{ width:'100%', justifyContent:'center', marginTop:10 }}
              onClick={volver}>
              <i className="bi bi-arrow-left"></i> Volver
            </button>
          </form>
        )}

        {/* ── Paso 2b: código del segundo factor ya configurado ── */}
        {paso === 'codigo' && desafio && (
          <form onSubmit={enviarCodigo}>
            <p style={{ fontSize: 13, color: '#334155', marginBottom: 14 }}>
              <i className="bi bi-shield-lock-fill" style={{ color: '#0f4c81' }}></i>
              Segundo factor requerido para <strong>{desafio.email}</strong>
            </p>
            {campoCodigo}
            {boton('Verificar código', 'shield-check')}
            <button type="button" className="btn-outline-custom"
              style={{ width:'100%', justifyContent:'center', marginTop:10 }}
              onClick={volver}>
              <i className="bi bi-arrow-left"></i> Otra cuenta
            </button>
          </form>
        )}

        {/* Demo accounts */}
        {paso === 'credenciales' && (
          <div style={{ marginTop:24, padding:'14px 16px', background:'#f8fafc',
            borderRadius:10, border:'1px solid #e2e8f0' }}>
            <p style={{ fontSize:11, fontWeight:700, color:'#64748b', marginBottom:8, textTransform:'uppercase', letterSpacing:'.5px' }}>
              Cuentas de demostración
            </p>
            {DEMOS.map(d => (
              <button type="button" key={d.rol}
                onClick={() => { setEmail(d.email); setPassword(d.pass); }}
                style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                  width:'100%', padding:'5px 0', cursor:'pointer', border:'none',
                  borderBottom:'1px solid #f1f5f9', background:'transparent',
                  font:'inherit', textAlign:'left' }}>
                <span style={{ fontSize:12, fontWeight:600, color:'#0f4c81' }}>{d.rol}</span>
                <span style={{ fontSize:11, color:'#64748b' }}>{d.email}</span>
              </button>
            ))}
            <p style={{ fontSize:10, color:'#94a3b8', marginTop:7 }}>
              ISO/IEC 27001 A.5.17: el sistema exigirá cambiar la contraseña en el
              primer acceso. El administrador además requiere TOTP (A07).
            </p>
          </div>
        )}

      </div>
    </div>
  );
}
