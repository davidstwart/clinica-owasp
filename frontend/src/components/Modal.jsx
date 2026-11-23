import { useEffect } from 'react';

export default function Modal({ titulo, onClose, children }) {
  useEffect(() => {
    const cerrarConEscape = (evento) => {
      if (evento.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', cerrarConEscape);
    return () => document.removeEventListener('keydown', cerrarConEscape);
  }, [onClose]);

  return (
    <div className="modal-overlay">
      <button
        type="button"
        aria-label="Cerrar modal"
        onClick={onClose}
        style={{ position:'absolute', inset:0, background:'transparent', border:0, cursor:'default' }}
      />
      <div className="modal-box" style={{ position:'relative', zIndex:1 }}>
        <div className="modal-header">
          <h5>{titulo}</h5>
          <button className="modal-close" onClick={onClose} aria-label="Cerrar">
            <i className="bi bi-x"></i>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
