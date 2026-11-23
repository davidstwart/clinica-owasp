import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login           from './pages/Login';
import CambioPassword  from './pages/CambioPassword';
import Dashboard       from './pages/Dashboard';
import Pacientes       from './pages/Pacientes';
import Citas           from './pages/Citas';
import Atenciones      from './pages/Atenciones';
import Auditoria       from './pages/Auditoria';
import Usuarios        from './pages/Usuarios';
import Reportes        from './pages/Reportes';

const PantallaCarga = () => (
  <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
    height:'100vh', flexDirection:'column', gap:16, color:'#0f4c81' }}>
    <i className="bi bi-hospital" style={{ fontSize:40 }}></i>
    <p style={{ fontFamily:'Inter,sans-serif', fontWeight:500 }}>Cargando sistema...</p>
  </div>
);

/**
 * Ruta protegida — ISO/IEC 27001 A.5.15.
 * Además de exigir sesión, aplica la restricción de A.5.17: si la contraseña
 * es la inicial o debe rotarse, solo se permite la pantalla de cambio.
 */
function PrivateRoute({ children }) {
  const { usuario, cargando } = useAuth();
  if (cargando) return <PantallaCarga />;
  if (!usuario) return <Navigate to="/login" replace />;
  if (usuario.debeCambiarContrasena && window.location.pathname !== '/cambiar-contrasena') {
    return <Navigate to="/cambiar-contrasena" replace />;
  }
  return children;
}

function AdminRoute({ children }) {
  const { usuario } = useAuth();
  return usuario?.rol === 'admin' ? children : <Navigate to="/dashboard" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Públicas */}
          <Route path="/login" element={<Login />} />
          <Route path="/cambiar-contrasena" element={<CambioPassword obligatorio />} />

          {/* Protegidas */}
          <Route path="/dashboard"  element={<PrivateRoute><Dashboard /></PrivateRoute>} />
          <Route path="/pacientes"  element={<PrivateRoute><Pacientes /></PrivateRoute>} />
          <Route path="/citas"      element={<PrivateRoute><Citas /></PrivateRoute>} />
          <Route path="/atenciones" element={<PrivateRoute><Atenciones /></PrivateRoute>} />
          <Route path="/mi-cuenta"  element={<PrivateRoute><CambioPassword /></PrivateRoute>} />

          {/* Solo admin */}
          <Route path="/auditoria" element={<PrivateRoute><AdminRoute><Auditoria /></AdminRoute></PrivateRoute>} />
          <Route path="/usuarios"  element={<PrivateRoute><AdminRoute><Usuarios /></AdminRoute></PrivateRoute>} />
          <Route path="/reportes"  element={<PrivateRoute><AdminRoute><Reportes /></AdminRoute></PrivateRoute>} />

          {/* Redireccionamientos */}
          <Route path="/"   element={<Navigate to="/dashboard" replace />} />
          <Route path="*"   element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
