import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import api    from '../services/api';

const NIVELES = ['', 'INFO', 'WARNING', 'SECURITY', 'ERROR', 'CRITICAL'];

/**
 * Registro de auditoría — OWASP A09:2021 / ISO/IEC 27001 A.8.15 y A.8.16.
 * Consume el endpoint paginado y filtrable (nivel, usuario, rango de fechas y
 * acción); el servidor nunca permite modificar ni eliminar entradas (el
 * registro es de solo agregado). Incluye el panel de alertas automáticas.
 */
export default function Auditoria() {
  const [datos,    setDatos]    = useState({ total: 0, resultados: [] });
  const [resumen,  setResumen]  = useState(null);
  const [alertas,  setAlertas]  = useState({ total: 0, resultados: [] });
  const [usuarios, setUsuarios] = useState([]);
  const [filtro,   setFiltro]   = useState('');
  const [nivel,    setNivel]    = useState('');
  const [usuarioId, setUsuarioId] = useState('');
  const [desde,    setDesde]    = useState('');
  const [hasta,    setHasta]    = useState('');
  const [pagina,   setPagina]   = useState(0);
  const LIMITE = 25;

  const cargar = () => {
    const params = { skip: pagina * LIMITE, limit: LIMITE };
    if (nivel) params.nivel = nivel;
    if (usuarioId) params.usuario_id = usuarioId;
    if (desde) params.desde = `${desde}T00:00:00`;
    if (hasta) params.hasta = `${hasta}T23:59:59`;
    api.get('/api/auditoria/', { params })
      .then(r => setDatos(r.data))
      .catch(() => {});
  };

  useEffect(cargar, [pagina, nivel, usuarioId, desde, hasta]);
  useEffect(() => {
    api.get('/api/auditoria/resumen').then(r => setResumen(r.data)).catch(() => {});
    api.get('/api/auditoria/alertas', { params: { limit: 20 } })
      .then(r => setAlertas(r.data)).catch(() => {});
    api.get('/api/auth/usuarios').then(r => setUsuarios(r.data)).catch(() => {});
  }, []);

  const filtrados = datos.resultados.filter(l =>
    `${l.accion} ${l.tabla_afectada} ${l.ip_address}`.toLowerCase().includes(filtro.toLowerCase())
  );

  const paginas = Math.max(1, Math.ceil(datos.total / LIMITE));
  const indicador = (etiqueta, valor, icono, color) => (
    <div className="card" key={etiqueta} style={{ padding: '14px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <i className={`bi bi-${icono}`} style={{ fontSize: 18, color }}></i>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#0f172a' }}>{valor ?? '—'}</div>
          <div style={{ fontSize: 11, color: '#64748b' }}>{etiqueta}</div>
        </div>
      </div>
    </div>
  );

  return (
    <Layout titulo="Auditoría de Seguridad">

      {/* Info OWASP */}
      <div className="alert-custom alert-info" style={{ marginBottom:20 }}>
        <i className="bi bi-shield-fill-check" style={{ flexShrink:0, fontSize:16 }}></i>
        <div>
          <strong>OWASP A09:2021 · ISO/IEC 27001 A.8.15 / A.8.16</strong>
          <br/>
          <span style={{ fontSize:12 }}>
            Cada acción crítica (logins, altas, ediciones, eliminaciones y cambios de
            credencial) queda registrada con usuario, IP, nivel de severidad y
            correlation ID. El registro es de solo agregado.
          </span>
        </div>
      </div>

      {/* Indicadores de monitoreo 24 h */}
      {resumen && (
        <div className="row g-3" style={{ marginBottom: 20 }}>
          <div className="col-6 col-md-4">{indicador('Eventos 24 h', resumen.eventos_24h, 'activity', '#0f4c81')}</div>
          <div className="col-6 col-md-4">{indicador('Accesos exitosos 24 h', resumen.logins_exitosos_24h, 'box-arrow-in-right', '#16a34a')}</div>
          <div className="col-6 col-md-4">{indicador('Accesos fallidos 24 h', resumen.logins_fallidos_24h, 'exclamation-triangle', '#ea580c')}</div>
          <div className="col-6 col-md-4">{indicador('Cuentas bloqueadas 24 h', resumen.cuentas_bloqueadas_24h, 'lock', '#dc2626')}</div>
          <div className="col-6 col-md-4">{indicador('Cambios de contraseña 24 h', resumen.cambios_contrasena_24h, 'key', '#7c3aed')}</div>
          <div className="col-6 col-md-4">{indicador('Eventos de seguridad 24 h', resumen.eventos_seguridad_24h, 'shield-exclamation', '#dc2626')}</div>
        </div>
      )}

        {/* A.8.16 — alertas automáticas generadas por las reglas de monitoreo */}
        <div className="card" style={{ margin:'0 0 20px', padding:0 }}>
          <div className="card-header-custom" style={{ marginBottom:0 }}>
            <h5 style={{ fontSize:14 }}>
              <i className="bi bi-bell-fill" style={{ color:'#dc2626' }}></i>
              Alertas de seguridad
              <span style={{ fontSize:12, fontWeight:400, color:'#64748b', marginLeft:8 }}>
                {alertas.total} alerta(s) crítica(s)
              </span>
            </h5>
          </div>
          {alertas.resultados.length === 0
            ? <div style={{ padding:'14px 22px', fontSize:13, color:'#16a34a' }}>
                <i className="bi bi-check2-circle"></i> Sin alertas activas: las reglas de
                intrusión, bloqueo y ráfaga de eventos no se han disparado.
              </div>
            : <div style={{ padding:'10px 22px 16px', display:'flex', flexDirection:'column', gap:8 }}>
                {alertas.resultados.map(a => (
                  <div key={a.id}
                    style={{ display:'flex', gap:10, alignItems:'flex-start',
                      border:'1px solid #fecaca', background:'#fef2f2',
                      borderRadius:8, padding:'8px 12px' }}>
                    <i className="bi bi-exclamation-octagon-fill"
                      style={{ color:'#dc2626', fontSize:15, marginTop:2 }}></i>
                    <div style={{ flex:1 }}>
                      <code className="tag-err" style={{ fontSize:11 }}>{a.accion}</code>
                      <span style={{ fontSize:11, color:'#7f1d1d', marginLeft:8 }}>{a.detalle}</span>
                    </div>
                    <span style={{ fontSize:11, color:'#94a3b8', whiteSpace:'nowrap' }}>
                      {new Date(a.created_at).toLocaleString('es-PE')}
                    </span>
                  </div>
                ))}
              </div>
          }
        </div>

        <div className="card">
        <div className="card-header-custom">
          <h5><i className="bi bi-shield-check"></i>Log de Auditoría</h5>
          <span style={{ fontSize:12, color:'#64748b' }}>
            <i className="bi bi-clock me-1"></i>{datos.total} evento(s) · retención {datos.retencion_dias} días
          </span>
        </div>

        <div style={{ padding:'14px 22px', borderBottom:'1px solid #e2e8f0', display:'flex', gap:12, flexWrap:'wrap' }}>
          <div className="search-wrap" style={{ flex:1, minWidth:220 }}>
            <i className="bi bi-search si"></i>
            <input className="form-control-custom search-input"
              placeholder="Buscar por acción, tabla o IP..."
              value={filtro} onChange={e => setFiltro(e.target.value)} />
          </div>
          <select className="form-control-custom" style={{ width:'auto' }}
            value={usuarioId} onChange={e => { setUsuarioId(e.target.value); setPagina(0); }}
            aria-label="Filtrar por usuario">
            <option value="">Todos los usuarios</option>
            {usuarios.map(u => (
              <option key={u.id} value={u.id}>{u.nombre} (#{u.id})</option>
            ))}
          </select>
          <select className="form-control-custom" style={{ width:'auto' }}
            value={nivel} onChange={e => { setNivel(e.target.value); setPagina(0); }}
            aria-label="Filtrar por nivel de severidad">
            {NIVELES.map(n => (
              <option key={n} value={n}>{n === '' ? 'Todos los niveles' : n}</option>
            ))}
          </select>
          <input type="date" className="form-control-custom" style={{ width:'auto' }}
            value={desde} onChange={e => { setDesde(e.target.value); setPagina(0); }}
            aria-label="Desde (fecha)" title="Fecha inicial" />
          <input type="date" className="form-control-custom" style={{ width:'auto' }}
            value={hasta} onChange={e => { setHasta(e.target.value); setPagina(0); }}
            aria-label="Hasta (fecha)" title="Fecha final" />
          {(usuarioId || desde || hasta || nivel) && (
            <button className="btn-outline-custom" style={{ padding:'5px 12px', fontSize:12 }}
              onClick={() => { setUsuarioId(''); setDesde(''); setHasta(''); setNivel(''); setPagina(0); }}>
              <i className="bi bi-x-circle"></i> Limpiar
            </button>
          )}
        </div>

        <div style={{ overflowX:'auto' }}>
          {filtrados.length === 0
            ? <div className="empty-state">
                <i className="bi bi-shield-check"></i>
                <p>No hay registros de auditoría para este filtro.</p>
              </div>
            : <table className="table-custom">
                <thead><tr>
                  <th>#</th><th>Usuario ID</th><th>Acción</th><th>Nivel</th>
                  <th>Tabla</th><th>Registro</th><th>IP</th><th>Fecha y hora</th>
                </tr></thead>
                <tbody>
                  {filtrados.map(l => {
                    const critico = ['SECURITY', 'ERROR', 'CRITICAL'].includes(l.nivel);
                    return (
                      <tr key={l.id}>
                        <td style={{ color:'#94a3b8', fontSize:12 }}>#{l.id}</td>
                        <td style={{ fontSize:13 }}>
                          {l.usuario_id
                            ? <code className="tag">#{l.usuario_id}</code>
                            : <span style={{ color:'#94a3b8' }}>—</span>}
                        </td>
                        <td>
                          <code className={critico ? 'tag-err' : 'tag-ok'}>{l.accion}</code>
                          {l.detalle && (
                            <div style={{ fontSize:10, color:'#94a3b8', marginTop:2 }}>{l.detalle}</div>
                          )}
                        </td>
                        <td>
                          <span className={`badge-custom ${critico ? 'badge-inactivo' : 'badge-activo'}`}
                            style={{ fontSize:10 }}>{l.nivel}</span>
                        </td>
                        <td style={{ fontSize:12, color:'#475569' }}>{l.tabla_afectada || '—'}</td>
                        <td style={{ fontSize:12, color:'#475569' }}>
                          {l.registro_id ? `#${l.registro_id}` : '—'}
                        </td>
                        <td style={{ fontSize:12 }}>
                          <code className="tag">{l.ip_address || '—'}</code>
                        </td>
                        <td style={{ fontSize:12, color:'#64748b', whiteSpace:'nowrap' }}>
                          {new Date(l.created_at).toLocaleString('es-PE')}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
          }
        </div>

        <div className="table-footer" style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <span>
            Página {pagina + 1} de {paginas} · {filtrados.length} de {datos.total} evento(s)
          </span>
          <span style={{ display:'flex', gap:6 }}>
            <button className="btn-outline-custom" style={{ padding:'5px 12px', fontSize:12 }}
              disabled={pagina === 0} onClick={() => setPagina(p => p - 1)}>
              <i className="bi bi-chevron-left"></i>
            </button>
            <button className="btn-outline-custom" style={{ padding:'5px 12px', fontSize:12 }}
              disabled={pagina + 1 >= paginas} onClick={() => setPagina(p => p + 1)}>
              <i className="bi bi-chevron-right"></i>
            </button>
          </span>
        </div>
      </div>
    </Layout>
  );
}
