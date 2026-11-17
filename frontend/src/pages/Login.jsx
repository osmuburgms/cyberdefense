import { useState } from 'react';
import { Activity, GitBranch, Loader2, Server, ShieldCheck } from 'lucide-react';
import { useAuth } from '../auth';
import { LogoHorizontal } from '../components/Logo.jsx';

// Pantalla de acceso: operador o administrador según el rol de la cuenta.
export default function Login({ backendUrl, onBackendUrl }) {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [urlDraft, setUrlDraft] = useState(backendUrl);
  const [showUrl, setShowUrl] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message || 'No se pudo iniciar sesión');
      setBusy(false);
    }
  };

  const applyUrl = () => {
    const v = urlDraft.trim().replace(/\/+$/, '');
    if (!/^https?:\/\/.+/.test(v)) {
      setError('La URL debe empezar por http:// o https://');
      return;
    }
    onBackendUrl(v); // App recarga para revalidar la sesión contra el nuevo backend
  };

  const inputClass = 'cd-login-input w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500';

  return (
    <div className="cd-login-shell min-h-screen">
      <section className="cd-login-overview">
        <div className="cd-login-intro">
          <div className="cd-login-brandmark">
            <LogoHorizontal className="w-[340px] max-w-full" />
          </div>
          <p className="cd-login-eyebrow"><span /> PLATAFORMA DE CIBERDEFENSA · ESPOL / FIEC</p>
          <h1>Detección y respuesta<br /><span>adaptativa</span></h1>
          <p className="cd-login-lede">Detección de anomalías, mitigación automatizada y registro auditable desde un mismo panel.</p>
        </div>
        <div className="cd-login-capabilities">
          <div className="cd-login-capability">
            <span className="cd-login-capability-icon"><Activity size={17} /></span>
            <span><strong>Detección</strong><small>Clasificación de tráfico con IA</small></span>
          </div>
          <div className="cd-login-capability">
            <span className="cd-login-capability-icon"><GitBranch size={17} /></span>
            <span><strong>Respuesta SDN</strong><small>Mitigación de flujos en la red</small></span>
          </div>
          <div className="cd-login-capability">
            <span className="cd-login-capability-icon"><ShieldCheck size={17} /></span>
            <span><strong>Trazabilidad</strong><small>Registro auditable de eventos</small></span>
          </div>
        </div>
      </section>

      <section className="cd-login-content">
        <div className="cd-login-content-top"><span>ACCESO AL SISTEMA</span><span className="cd-login-private"><ShieldCheck size={13} /> Entorno privado</span></div>
        <div className="modal-in cd-login-form-wrap">
          <div className="cd-login-form-heading">
            <span className="cd-login-form-icon"><ShieldCheck size={20} /></span>
            <div>
              <h2>Iniciar sesión</h2>
              <p>Ingresa con las credenciales de tu cuenta.</p>
            </div>
          </div>

          <form onSubmit={submit} className="cd-login-form-card space-y-4">
            <div>
              <label htmlFor="login-user" className="cd-login-label block text-xs text-gray-400 mb-1">Usuario</label>
              <input
                id="login-user"
                className={inputClass}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                placeholder="Nombre de usuario"
              />
            </div>
            <div>
              <label htmlFor="login-pass" className="cd-login-label block text-xs text-gray-400 mb-1">Contraseña</label>
              <input
                id="login-pass"
                type="password"
                className={inputClass}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <p className="cd-login-error text-xs text-red-400 font-mono bg-red-900/20 border border-red-800 rounded px-2.5 py-2">{error}</p>
            )}

            <button
              type="submit"
              disabled={busy || !username.trim() || !password}
              className="cd-login-submit w-full flex items-center justify-center gap-2 text-sm font-semibold py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white transition-colors"
            >
              {busy && <Loader2 size={15} className="animate-spin" />}
              {busy ? 'Verificando…' : 'Entrar'}
            </button>

            <button
              type="button"
              onClick={() => setShowUrl((v) => !v)}
              className="cd-login-backend-toggle w-full flex items-center justify-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300"
            >
              <Server size={11} /> {showUrl ? 'Ocultar conexión' : 'Cambiar backend'}
            </button>
            {showUrl && (
              <div className="flex gap-2">
                <input
                  value={urlDraft}
                  onChange={(e) => setUrlDraft(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), applyUrl())}
                  className="cd-login-input flex-1 min-w-0 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"
                />
                <button type="button" onClick={applyUrl} className="cd-login-apply text-xs px-3 rounded bg-gray-700 hover:bg-gray-600 text-gray-100 shrink-0">
                  Aplicar
                </button>
              </div>
            )}
          </form>
          <p className="cd-login-account-note">¿Necesitas una cuenta? Solicítala al administrador de la plataforma.</p>
        </div>
        <p className="cd-login-content-footer"><ShieldCheck size={13} /> Acceso autenticado · monitoreo de infraestructura SDN</p>
      </section>
    </div>
  );
}
