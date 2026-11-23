import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

/**
 * Cambio de contraseña — ISO/IEC 27001:2022 A.5.17 y A.8.5.
 * Pantalla a la que el sistema redirige cuando la contraseña es la inicial o
 * fue restablecida por el administrador. El servidor revoca todos los tokens
 * al completarlo, por lo que hay que iniciar sesión de nuevo.
 */
export default function CambioPassword({ obligatorio = false }) {
  const [actual,  setActual]  = useState('');
  const [nueva,   setNueva]   = useState('');
  const [repetir, setRepetir] = useState('');
  const [error,   setError]   = useState('');
  const [ok,      setOk]      = useState('');
  const [loading, setLoading] = useState(false);
  const [show,    setShow]    = useState(false);
  const { cambiarContrasena, usuario } = useAuth();
  const navigate = useNavigate();

  const enviar = async (e) => {
    e.preventDefault();
    setError(''); setOk('');
    if (nueva !== repetir) {
      setError('Las contraseñas nuevas no coinciden.');
      return;
    }
    setLoading(true);
    try {
      await cambiarContrasena(actual, nueva);
      setOk('Contraseña actualizada. Vuelva a iniciar sesión.');
      setTimeout(() => void navigate('/login', { replace: true }), 1800);
    } catch (err) {
      const detalle = err.response?.data?.detail;
      setError(typeof detalle === 'string' ? detalle : 'No se pudo actualizar la contraseña.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">
          <div className="icon-wrap"><i className="bi bi-shield-lock"></i></div>
          <h1>Actualizar contraseña</h1>
          <p>{usuario?.nombre}</p>
        </div>

        {obligatorio && (
          <div className="alert-custom alert-warning">
            <i className="bi bi-exclamation-triangle-fill" style={{ flexShrink: 0 }}></i>
            <span style={{ fontSize: 12 }}>
              <strong>ISO/IEC 27001 A.5.17.</strong> Debe definir una contraseña propia
              antes de usar el sistema.
            </span>
          </div>
        )}

        {error && (
          <div className="alert-custom alert-error">
            <i className="bi bi-exclamation-circle-fill" style={{ flexShrink: 0 }}></i>
            <span>{error}</span>
          </div>
        )}
        {ok && (
          <div className="alert-custom alert-success">
            <i className="bi bi-check-circle-fill" style={{ flexShrink: 0 }}></i>
            <span>{ok}</span>
          </div>
        )}

        <form onSubmit={enviar}>
          <div style={{ marginBottom: 16 }}>
            <label className="form-label-custom" htmlFor="password-actual">Contraseña actual *</label>
            <input id="password-actual" type="password" className="form-control-custom"
              value={actual} onChange={e => setActual(e.target.value)}
              required autoComplete="current-password" maxLength={128} />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="form-label-custom" htmlFor="password-nueva">Contraseña nueva *</label>
            <div style={{ position: 'relative' }}>
              <input id="password-nueva" type={show ? 'text' : 'password'} className="form-control-custom"
                value={nueva} onChange={e => setNueva(e.target.value)}
                required autoComplete="new-password" maxLength={128}
                style={{ paddingRight: 42 }} />
              <button type="button" onClick={() => setShow(!show)}
                aria-label={show ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                style={{ position:'absolute', right:10, top:'50%', transform:'translateY(-50%)',
                  background:'none', border:'none', cursor:'pointer', color:'#94a3b8', fontSize:16 }}>
                <i className={`bi bi-eye${show ? '-slash' : ''}`}></i>
              </button>
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <label className="form-label-custom" htmlFor="password-repetir">Repetir contraseña nueva *</label>
            <input id="password-repetir" type={show ? 'text' : 'password'} className="form-control-custom"
              value={repetir} onChange={e => setRepetir(e.target.value)}
              required autoComplete="new-password" maxLength={128} />
          </div>

          <div className="alert-custom alert-info" style={{ marginBottom: 18 }}>
            <i className="bi bi-info-circle-fill" style={{ flexShrink: 0 }}></i>
            <span style={{ fontSize: 11 }}>
              Mínimo 8 caracteres, con mayúscula, minúscula y número. No puede contener
              partes de su correo ni ser igual a la actual.
            </span>
          </div>

          <button type="submit" className="btn-primary-custom"
            style={{ width:'100%', justifyContent:'center', padding:'11px 0', fontSize:14 }}
            disabled={loading}>
            {loading
              ? <><i className="bi bi-hourglass-split"></i> Guardando...</>
              : <><i className="bi bi-check2-circle"></i> Guardar contraseña</>
            }
          </button>
        </form>

        {!obligatorio && (
          <button type="button" className="btn-outline-custom"
            onClick={() => void navigate(-1)} style={{ width:'100%', marginTop:12, justifyContent:'center' }}>
            Volver
          </button>
        )}
      </div>
    </div>
  );
}
