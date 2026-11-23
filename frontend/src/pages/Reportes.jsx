import { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import api from '../services/api';

const SECCIONES = [
  { clave: 'pacientes',     titulo: 'Pacientes',      icono: 'people'          },
  { clave: 'citas',         titulo: 'Citas',          icono: 'calendar3'       },
  { clave: 'atenciones',    titulo: 'Atenciones',     icono: 'clipboard2-pulse'},
  { clave: 'usuarios',      titulo: 'Usuarios',       icono: 'person-gear'     },
  { clave: 'auditoria_24h', titulo: 'Auditoría 24 h', icono: 'shield-check'    },
];

const etiqueta = (k) =>
  k.replace(/_/g, ' ').replace('24 h', '24 h').replace(/^./, c => c.toUpperCase());

/**
 * Reportes gerenciales — ISO/IEC 27001 A.5.34 (protección de registros) y
 * A.8.15 (registro de actividades). El sello SHA-256 emitido por el servidor
 * permite demostrar qué versión exacta del reporte revisó el administrador.
 */
export default function Reportes() {
  const [resumen, setResumen] = useState(null);
  const [sello,   setSello]   = useState(null);
  const [error,   setError]   = useState('');
  const [cargando, setCargando] = useState(false);

  useEffect(() => {
    api.get('/api/reportes/resumen').then(r => setResumen(r.data)).catch(() => {});
  }, []);

  const validar = async () => {
    setError(''); setCargando(true); setSello(null);
    try {
      const r = await api.post('/api/reportes/validar', { reporte: resumen });
      setSello(r.data);
    } catch (e) {
      const d = e.response?.data?.detail;
      setError(typeof d === 'string' ? d : 'No se pudo sellar el reporte.');
    } finally { setCargando(false); }
  };

  return (
    <Layout titulo="Reportes de Gestión">
      <div className="alert-custom alert-info" style={{ marginBottom:20 }}>
        <i className="bi bi-file-earmark-bar-graph" style={{ flexShrink:0, fontSize:16 }}></i>
        <div>
          <strong>ISO/IEC 27001 A.5.34 · OWASP A09</strong>
          <br />
          <span style={{ fontSize:12 }}>
            Indicadores consolidados sin datos identificables. La validación sella el
            reporte con SHA-256 y deja constancia en el registro de auditoría
            (<code>VALIDAR_REPORTE</code>).
          </span>
        </div>
      </div>

      {error && (
        <div className="alert-custom alert-error">
          <i className="bi bi-exclamation-circle-fill" style={{ flexShrink:0 }}></i>{error}
        </div>
      )}
      {sello && (
        <div className="alert-custom alert-success">
          <i className="bi bi-patch-check-fill" style={{ flexShrink:0 }}></i>
          <div style={{ wordBreak:'break-all' }}>
            <strong>Reporte sellado el {new Date(sello.registrado_en).toLocaleString('es-PE')}</strong>
            <br />
            <span style={{ fontSize:12 }}>SHA-256: <code>{sello.hash_sha256}</code></span>
          </div>
        </div>
      )}

      {!resumen ? (
        <div className="empty-state">
          <i className="bi bi-hourglass-split"></i><p>Cargando indicadores...</p>
        </div>
      ) : (
        <>
          <div className="row g-3" style={{ marginBottom:20 }}>
            {SECCIONES.map(s => (
              <div className="col-12 col-md-6 col-xl-4" key={s.clave}>
                <div className="card" style={{ padding:'16px 18px' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10 }}>
                    <i className={`bi bi-${s.icono}`} style={{ color:'#0f4c81', fontSize:16 }}></i>
                    <strong style={{ fontSize:13 }}>{s.titulo}</strong>
                  </div>
                  {Object.entries(resumen[s.clave] || {}).map(([k, v]) => (
                    <div key={k}
                      style={{ display:'flex', justifyContent:'space-between',
                        fontSize:12, padding:'4px 0', borderBottom:'1px solid #f1f5f9' }}>
                      <span style={{ color:'#64748b' }}>{etiqueta(k)}</span>
                      <strong style={{ color:'#0f172a' }}>{v}</strong>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="card" style={{ padding:'16px 18px',
            display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:12 }}>
            <div style={{ fontSize:12, color:'#64748b' }}>
              <i className="bi bi-clock-history me-1"></i>
              Generado: <strong>{new Date(resumen.generado_en).toLocaleString('es-PE')}</strong>
            </div>
            <button className="btn-primary-custom" onClick={validar} disabled={cargando}>
              {cargando
                ? <><i className="bi bi-hourglass-split"></i> Sellando...</>
                : <><i className="bi bi-patch-check"></i> Validar y sellar reporte</>}
            </button>
          </div>
        </>
      )}
    </Layout>
  );
}
