import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import Modal  from '../components/Modal';
import api    from '../services/api';
import { useAuth } from '../context/AuthContext';

// A.5.26 / A.5.15 — la atención se registra SIEMPRE sobre una cita; el
// `medico_id` lo toma el servidor del token, nunca del navegador.
const EMPTY = { paciente_id:'', cita_id:'', diagnostico:'', tratamiento:'', observaciones:'' };

export default function Atenciones() {
  const [lista,     setLista]     = useState([]);
  const [pacientes, setPacientes] = useState([]);
  const [medicos,   setMedicos]   = useState([]);
  const [citas,     setCitas]     = useState([]);
  const [modal,     setModal]     = useState(false);
  const [form,      setForm]      = useState(EMPTY);
  const [error,     setError]     = useState('');
  const [ok,        setOk]        = useState('');
  const { usuario } = useAuth();

  const cargar = () => api.get('/api/atenciones/').then(r => setLista(r.data)).catch(() => {});

  useEffect(() => {
    void cargar();
    api.get('/api/pacientes/').then(r => setPacientes(r.data)).catch(() => {});
    api.get('/api/auth/medicos').then(r => setMedicos(r.data)).catch(() => {});
    api.get('/api/citas/').then(r => setCitas(r.data)).catch(() => {});
  }, []);

  // Solo las citas asignadas al profesional que inicia sesión pueden dar
  // origen a una atención: el servidor rechaza cualquier otra (403).
  const citasDisponibles = citas.filter(c =>
    c.medico_id === usuario?.id &&
    c.estado !== 'cancelada' &&
    (!form.paciente_id || c.paciente_id === +form.paciente_id)
  );

  const guardar = async () => {
    setError('');
    if (!form.paciente_id || !form.cita_id || !form.diagnostico || !form.tratamiento) {
      setError('Selecciona paciente, cita y completa diagnóstico y tratamiento.'); return;
    }
    try {
      await api.post('/api/atenciones/', {
        paciente_id: +form.paciente_id,
        cita_id:     +form.cita_id,
        diagnostico: form.diagnostico,
        tratamiento: form.tratamiento,
        observaciones: form.observaciones || null,
      });
      setModal(false); setForm(EMPTY); void cargar();
      setOk('Atención registrada correctamente.'); setTimeout(() => setOk(''), 3500);
    } catch (e) { setError(e.response?.data?.detail || 'Error al registrar.'); }
  };

  const nombrePaciente = id => { const p = pacientes.find(x => x.id === id); return p ? `${p.apellidos}, ${p.nombres}` : `#${id}`; };
  const nombreMedico   = id => { const m = medicos.find(x => x.id === id);   return m ? m.nombre : `#${id}`; };

  return (
    <Layout titulo="Atenciones Médicas">
      {ok && <div className="alert-custom alert-success"><i className="bi bi-check-circle-fill"></i>{ok}</div>}

      <div className="alert-custom alert-info">
        <i className="bi bi-info-circle-fill" style={{ flexShrink:0 }}></i>
        <span>
          Solo médicos y administradores ven y registran atenciones — <strong>OWASP A01</strong>.
          Cada atención exige una <strong>cita asignada al profesional</strong> y el
          médico se toma del token de sesión — <strong>A.5.15 / A.5.26</strong>.
        </span>
      </div>

      <div className="card">
        <div className="card-header-custom">
          <h5><i className="bi bi-clipboard2-pulse"></i>Historial de Atenciones</h5>
          <button className="btn-primary-custom" onClick={() => { setForm(EMPTY); setError(''); setModal(true); }}>
            <i className="bi bi-clipboard2-plus"></i>Nueva atención
          </button>
        </div>
        <div style={{ overflowX:'auto' }}>
          {lista.length === 0
            ? <div className="empty-state"><i className="bi bi-clipboard2-pulse"></i><p>No hay atenciones registradas.</p></div>
            : <table className="table-custom">
                <thead><tr>
                  <th>#</th><th>Paciente</th><th>Cita</th><th>Médico</th>
                  <th>Diagnóstico</th><th>Tratamiento</th><th>Fecha</th>
                </tr></thead>
                <tbody>
                  {lista.map((a, i) => (
                    <tr key={a.id}>
                      <td style={{ color:'#94a3b8', fontSize:12 }}>{i+1}</td>
                      <td><strong>{nombrePaciente(a.paciente_id)}</strong></td>
                      <td style={{ fontSize:12 }}>{a.cita_id ? <code className="tag">#{a.cita_id}</code> : '—'}</td>
                      <td style={{ fontSize:13 }}>{nombreMedico(a.medico_id)}</td>
                      <td style={{ maxWidth:200, fontSize:13 }}>{a.diagnostico}</td>
                      <td style={{ maxWidth:200, fontSize:13 }}>{a.tratamiento}</td>
                      <td style={{ fontSize:12, whiteSpace:'nowrap' }}>
                        {new Date(a.created_at).toLocaleDateString('es-PE')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </div>
        <div className="table-footer">{lista.length} atención(es) registrada(s)</div>
      </div>

      {modal && (
        <Modal titulo="Registrar atención médica" onClose={() => setModal(false)}>
          <div className="modal-body">
            {error && <div className="alert-custom alert-error"><i className="bi bi-exclamation-circle-fill"></i>{error}</div>}
            <div className="row g-3">
              <div className="col-6">
                <label className="form-label-custom" htmlFor="atencion-paciente">Paciente *</label>
                <select id="atencion-paciente" className="form-control-custom" value={form.paciente_id}
                  onChange={e => setForm({ ...form, paciente_id:e.target.value, cita_id:'' })}>
                  <option value="">Seleccionar...</option>
                  {pacientes.map(p => <option key={p.id} value={p.id}>{p.apellidos}, {p.nombres}</option>)}
                </select>
              </div>
              <div className="col-6">
                <label className="form-label-custom" htmlFor="atencion-medico">Médico tratante *</label>
                <input id="atencion-medico" className="form-control-custom" value={usuario?.nombre || ''}
                  readOnly disabled title="El servidor asigna el médico desde el token (A.5.15)" />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="atencion-cita">Cita asociada *</label>
                <select id="atencion-cita" className="form-control-custom" value={form.cita_id}
                  onChange={e => setForm({ ...form, cita_id:e.target.value })}>
                  <option value="">Seleccionar cita...</option>
                  {citasDisponibles.map(c => (
                    <option key={c.id} value={c.id}>
                      #{c.id} — {new Date(c.fecha_hora).toLocaleString('es-PE')} — {c.motivo}
                    </option>
                  ))}
                </select>
                {citasDisponibles.length === 0 ? (
                  <p style={{ fontSize:11, color:'#b45309', marginTop:6 }}>
                    <i className="bi bi-exclamation-triangle"></i>
                    {form.paciente_id
                      ? 'No hay citas no canceladas de este paciente asignadas a tu cuenta.'
                      : 'Selecciona primero el paciente: la atención debe estar ligada a una cita de tu agenda.'}
                  </p>
                ) : (
                  <p style={{ fontSize:11, color:'#94a3b8', marginTop:6 }}>
                    A.5.26: la historia clínica solo se registra sobre una cita — sin
                    ella el servidor responde 422.
                  </p>
                )}
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="atencion-diagnostico">Diagnóstico *</label>
                <textarea id="atencion-diagnostico" className="form-control-custom" rows={2}
                  placeholder="Describe el diagnóstico del paciente..."
                  value={form.diagnostico} onChange={e => setForm({ ...form, diagnostico:e.target.value })} />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="atencion-tratamiento">Tratamiento *</label>
                <textarea id="atencion-tratamiento" className="form-control-custom" rows={2}
                  placeholder="Indica el tratamiento prescrito..."
                  value={form.tratamiento} onChange={e => setForm({ ...form, tratamiento:e.target.value })} />
              </div>
              <div className="col-12">
                <label className="form-label-custom" htmlFor="atencion-observaciones">Observaciones adicionales</label>
                <textarea id="atencion-observaciones" className="form-control-custom" rows={2}
                  value={form.observaciones} onChange={e => setForm({ ...form, observaciones:e.target.value })} />
              </div>
            </div>
          </div>
          <div className="modal-footer">
            <button className="btn-outline-custom" onClick={() => setModal(false)}>Cancelar</button>
            <button className="btn-primary-custom" onClick={guardar}>
              <i className="bi bi-check2"></i>Registrar atención
            </button>
          </div>
        </Modal>
      )}
    </Layout>
  );
}
