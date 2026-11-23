import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import Modal  from '../components/Modal';
import api    from '../services/api';

const EMPTY = { nombre:'', email:'', password:'', rol:'recepcionista', activo:true, reiniciar_mfa:false };

export default function Usuarios() {
  const [lista,  setLista]  = useState([]);
  const [filtro, setFiltro] = useState('');
  const [modal,  setModal]  = useState(false);
  const [form,   setForm]   = useState(EMPTY);
  const [editId, setEditId] = useState(null);
  const [error,  setError]  = useState('');
  const [ok,     setOk]     = useState('');
  const [loading,setLoading]= useState(false);
  // A07 — el secreto TOTP de una cuenta administrativa nueva se expone UNA vez.
  const [secreto, setSecreto] = useState(null);

  const cargar = () => api.get('/api/auth/usuarios').then(r => setLista(r.data)).catch(() => {});
  useEffect(() => { void cargar(); }, []);

  const filtrados = lista.filter(u =>
    `${u.nombre} ${u.email} ${u.rol}`.toLowerCase().includes(filtro.toLowerCase())
  );

  const ROLES = { admin:'badge-admin', medico:'badge-medico', recepcionista:'badge-recepcionista' };

  const abrirNuevo  = () => { setForm(EMPTY); setEditId(null); setError(''); setModal(true); };
  const abrirEditar = u  => {
    setForm({ nombre:u.nombre, email:u.email, password:'', rol:u.rol, activo:u.activo,
      reiniciar_mfa:false, mfa_habilitado:u.mfa_habilitado });
    setEditId(u.id); setError(''); setModal(true);
  };

  const guardar = async () => {
    setError(''); setLoading(true);
    try {
      if (editId) {
        const payload = { nombre:form.nombre, email:form.email, rol:form.rol, activo:form.activo };
        if (form.password) payload.password = form.password;
        if (form.reiniciar_mfa) payload.reiniciar_mfa = true;
        await api.put(`/api/auth/usuarios/${editId}`, payload);
      } else {
        const r = await api.post('/api/auth/usuarios', form);
        if (r.data.mfa_secreto) {
          setSecreto({ nombre: r.data.nombre, email: r.data.email, clave: r.data.mfa_secreto });
        }
      }
      setModal(false); setForm(EMPTY); void cargar();
      setOk(editId ? 'Usuario actualizado correctamente.' : 'Usuario creado correctamente.');
      setTimeout(() => setOk(''), 3500);
    } catch (e) {
      const detalle = e.response?.data?.detail;
      setError(typeof detalle === 'string' ? detalle : 'Error al guardar el usuario.');
    } finally { setLoading(false); }
  };

  // A.5.15 — aprobación explícita del acceso de una cuenta dada de alta pendiente.
  const aprobar = async u => {
    try {
      await api.post(`/api/auth/usuarios/${u.id}/aprobar`);
      void cargar();
      setOk(`Acceso aprobado para ${u.email}.`);
      setTimeout(() => setOk(''), 3500);
    } catch (e) {
      setError(e.response?.data?.detail || 'No se pudo aprobar el acceso.');
      setTimeout(() => setError(''), 3500);
    }
  };

  const cambiarEstado = async u => {
    try {
      await api.put(`/api/auth/usuarios/${u.id}`, { activo: !u.activo });
      void cargar();
    } catch (e) {
      setOk(''); setError(e.response?.data?.detail || 'No se pudo cambiar el estado.');
      setTimeout(() => setError(''), 3500);
    }
  };

  const eliminar = async id => {
    if (!window.confirm('¿Eliminar este usuario? Esta acción no se puede deshacer.')) return;
    try { await api.delete(`/api/auth/usuarios/${id}`); void cargar(); } catch (e) {
      setOk(''); setError(e.response?.data?.detail || 'Error al eliminar el usuario.');
      setTimeout(() => setError(''), 3500);
    }
  };

  return (
    <Layout titulo="Gestión de Usuarios">
      {ok    && <div className="alert-custom alert-success"><i className="bi bi-check-circle-fill"></i>{ok}</div>}
      {error && <div className="alert-custom alert-error"><i className="bi bi-exclamation-circle-fill"></i>{error}</div>}

      <div className="alert-custom alert-warning">
        <i className="bi bi-person-fill-lock" style={{ flexShrink: 0 }}></i>
        <div>
          <strong>OWASP A01 + A07 · ISO/IEC 27001 A.5.17:</strong> Solo administradores
          gestionan usuarios. Las contraseñas se almacenan con <strong>bcrypt</strong>
          (coste 12 rondas) y nunca en texto plano. Al restablecer una contraseña,
          el sistema fuerza su cambio y revoca las sesiones activas del usuario.
        </div>
      </div>

      <div className="card">
        <div className="card-header-custom">
          <h5><i className="bi bi-person-gear"></i>Usuarios del Sistema</h5>
          <button className="btn-primary-custom" onClick={abrirNuevo}>
            <i className="bi bi-person-plus"></i>Nuevo usuario
          </button>
        </div>

        <div style={{ padding:'14px 22px', borderBottom:'1px solid #e2e8f0' }}>
          <div className="search-wrap">
            <i className="bi bi-search si"></i>
            <input className="form-control-custom search-input"
              placeholder="Buscar por nombre, correo o rol..."
              value={filtro} onChange={e => setFiltro(e.target.value)} />
          </div>
        </div>

        <div style={{ overflowX:'auto' }}>
          {filtrados.length === 0
            ? <div className="empty-state">
                <i className="bi bi-person-gear"></i>
                <p>{filtro ? 'No se encontraron resultados.' : 'No hay usuarios registrados aún.'}</p>
              </div>
            : <table className="table-custom">
                <thead><tr>
                  <th>#</th><th>Nombre</th><th>Correo electrónico</th><th>Rol</th>
                  <th>Estado</th><th>MFA</th><th>Acciones</th>
                </tr></thead>
                <tbody>
                  {filtrados.map((u, i) => (
                    <tr key={u.id}>
                      <td style={{ color:'#94a3b8', fontSize:12 }}>{i+1}</td>
                      <td><strong>{u.nombre}</strong></td>
                      <td style={{ fontSize:13 }}>{u.email}</td>
                      <td><span className={`badge-custom ${ROLES[u.rol]||''}`}>{u.rol}</span></td>
                      <td>
                        <span className={`badge-custom ${u.activo ? 'badge-activo' : 'badge-inactivo'}`}>
                          {u.activo ? 'Activo' : 'Pendiente'}
                        </span>
                        {u.debe_cambiar_contrasena && (
                          <div style={{ fontSize:10, color:'#b45309', marginTop:3 }}>
                            <i className="bi bi-key"></i> Rotar contraseña
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={`badge-custom ${u.mfa_habilitado ? 'badge-activo' : 'badge-inactivo'}`}
                          style={{ fontSize:10 }}>
                          {u.mfa_habilitado ? 'TOTP activo' : 'Sin MFA'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display:'flex', gap:6 }}>
                          <button className="btn-edit-sm" title="Editar" onClick={() => abrirEditar(u)}>
                            <i className="bi bi-pencil"></i>
                          </button>
                          {!u.activo ? (
                            <button className="btn-edit-sm" title="Aprobar acceso"
                              onClick={() => aprobar(u)}>
                              <i className="bi bi-check2-circle"></i>
                            </button>
                          ) : (
                            <button className="btn-edit-sm" title="Desactivar"
                              onClick={() => cambiarEstado(u)}>
                              <i className="bi bi-pause-circle"></i>
                            </button>
                          )}
                          <button className="btn-danger-sm" title="Eliminar" onClick={() => eliminar(u.id)}>
                            <i className="bi bi-trash"></i>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </div>
        <div className="table-footer">{filtrados.length} usuario(s) registrado(s)</div>
      </div>

      {modal && (
        <Modal titulo={editId ? 'Editar usuario' : 'Crear nuevo usuario'} onClose={() => setModal(false)}>
          <div className="modal-body">
            {error && <div className="alert-custom alert-error"><i className="bi bi-exclamation-circle-fill"></i>{error}</div>}
            {!editId && (
              <div className="alert-custom alert-info" style={{ marginBottom:16 }}>
                <i className="bi bi-shield-lock" style={{ flexShrink:0 }}></i>
                <span style={{ fontSize:12 }}>
                  <strong>ISO/IEC 27001 A.5.17:</strong> mínimo 8 caracteres, con
                  mayúscula, minúscula y número. No puede contener partes del correo.
                </span>
              </div>
            )}
            <div className="row g-3">
              <div className="col-12">
                <label className="form-label-custom" htmlFor="usuario-nombre">Nombre completo *</label>
                <input id="usuario-nombre" type="text" className="form-control-custom"
                  value={form.nombre} onChange={e => setForm({ ...form, nombre:e.target.value })} />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="usuario-email">Correo electrónico *</label>
                <input id="usuario-email" type="email" className="form-control-custom"
                  value={form.email} onChange={e => setForm({ ...form, email:e.target.value })} />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="usuario-password">
                  {editId ? 'Nueva contraseña (opcional)' : 'Contraseña *'}
                </label>
                <input id="usuario-password" type="password" className="form-control-custom"
                  placeholder={editId ? 'Dejar en blanco para conservarla' : 'Mínimo 8 caracteres, 1 mayúscula, 1 minúscula, 1 número'}
                  value={form.password} onChange={e => setForm({ ...form, password:e.target.value })} />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="usuario-rol">Rol *</label>
                <select id="usuario-rol" className="form-control-custom" value={form.rol}
                  onChange={e => setForm({ ...form, rol:e.target.value })}>
                  <option value="admin">Administrador</option>
                  <option value="medico">Médico</option>
                  <option value="recepcionista">Recepcionista</option>
                </select>
              </div>
              {editId && (
                <div className="col-12">
                  <label className="form-label-custom" htmlFor="usuario-estado">Estado</label>
                  <select id="usuario-estado" className="form-control-custom" value={form.activo}
                    onChange={e => setForm({ ...form, activo:e.target.value === 'true' })}>
                    <option value="true">Activo</option>
                    <option value="false">Pendiente de aprobación</option>
                  </select>
                </div>
              )}
              {!editId && (
                <div className="col-12">
                  <label className="form-label-custom" htmlFor="usuario-estado-inicial">Estado inicial</label>
                  <select id="usuario-estado-inicial" className="form-control-custom" value={form.activo}
                    onChange={e => setForm({ ...form, activo:e.target.value === 'true' })}>
                    <option value="true">Activo — accesible de inmediato</option>
                    <option value="false">Pendiente de aprobación del administrador (A.5.15)</option>
                  </select>
                </div>
              )}
              {editId && form.mfa_habilitado && (
                <div className="col-12">
                  <label className="form-label-custom" style={{ display:'flex', gap:8, alignItems:'center' }}>
                    <input type="checkbox"
                      checked={form.reiniciar_mfa}
                      onChange={e => setForm({ ...form, reiniciar_mfa:e.target.checked })} />
                    Reiniciar MFA (autenticador perdido — A.5.17)
                  </label>
                  <p style={{ fontSize:11, color:'#94a3b8' }}>
                    Borra el secreto TOTP y revoca las sesiones: tendrás que entregar
                    un nuevo secreto a la cuenta.
                  </p>
                </div>
              )}
            </div>
          </div>
          <div className="modal-footer">
            <button className="btn-outline-custom" onClick={() => setModal(false)}>Cancelar</button>
            <button className="btn-primary-custom" onClick={guardar} disabled={loading}>
              {loading
                ? <><i className="bi bi-hourglass-split"></i> Guardando...</>
                : <><i className="bi bi-check2"></i>{editId ? 'Actualizar' : 'Crear usuario'}</>
              }
            </button>
          </div>
        </Modal>
      )}

      {/* A07 — el secreto TOTP se muestra exactamente una vez al crear admin */}
      {secreto && (
        <Modal titulo="Secreto MFA — una sola exhibición" onClose={() => setSecreto(null)}>
          <div className="modal-body">
            <div className="alert-custom alert-warning" style={{ marginBottom:16 }}>
              <i className="bi bi-exclamation-triangle-fill" style={{ flexShrink:0 }}></i>
              <span style={{ fontSize:12 }}>
                Guarda esta clave en el autenticador de <strong>{secreto.nombre}</strong>.
                El sistema <strong>no volverá a mostrarla</strong>: si se pierde, el
                administrador debe reiniciar el MFA desde esta pantalla.
              </span>
            </div>
            <span className="form-label-custom">Clave secreta TOTP</span>
            <div style={{ display:'flex', gap:8, alignItems:'center' }}>
              <code className="tag" style={{ fontSize:14, wordBreak:'break-all', flex:1 }}>
                {secreto.clave}
              </code>
              <button className="btn-outline-custom" style={{ padding:'5px 10px', fontSize:12 }}
                onClick={() => navigator.clipboard?.writeText(secreto.clave)}>
                <i className="bi bi-clipboard"></i>
              </button>
            </div>
            <p style={{ fontSize:11, color:'#64748b', marginTop:12 }}>
              Cuenta: <strong>{secreto.email}</strong> · OWASP A07 y ISO/IEC 27001 A.5.17:
              el segundo factor es obligatorio para el rol administrador.
            </p>
          </div>
          <div className="modal-footer">
            <button className="btn-primary-custom" onClick={() => setSecreto(null)}>
              <i className="bi bi-check2"></i> Entendido, quedó guardada
            </button>
          </div>
        </Modal>
      )}
    </Layout>
  );
}