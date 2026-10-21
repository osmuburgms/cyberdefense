import { useState } from 'react';
import { Loader2, Server } from 'lucide-react';
import { useAuth } from '../auth';

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

  const inputClass = 'w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500';

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="modal-in w-full max-w-sm">
        <div className="flex flex-col items-center mb-6">
          <img
            src="/logo-escudo.png"
            alt="CyberDefense SDN"
            className="h-20 w-auto mb-3 drop-shadow-[0_0_18px_rgba(56,189,248,0.35)]"
          />
          <h1 className="text-xl font-bold text-gray-100">SDN Cyberdefense</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">Acceso de operadores y administradores</p>
        </div>

        <form onSubmit={submit} className="bg-gray-800 border border-gray-700 rounded-xl p-5 shadow-2xl space-y-3">
          <div>
            <label htmlFor="login-user" className="block text-xs text-gray-400 mb-1">Usuario</label>
            <input
              id="login-user"
              className={inputClass}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              placeholder="p. ej. osmuburg"
            />
          </div>
          <div>
            <label htmlFor="login-pass" className="block text-xs text-gray-400 mb-1">Contraseña</label>
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
            <p className="text-xs text-red-400 font-mono bg-red-900/20 border border-red-800 rounded px-2.5 py-2">{error}</p>
          )}

          <button
            type="submit"
            disabled={busy || !username.trim() || !password}
            className="w-full flex items-center justify-center gap-2 text-sm font-semibold py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white transition-colors"
          >
            {busy && <Loader2 size={15} className="animate-spin" />}
            {busy ? 'Verificando…' : 'Entrar'}
          </button>

          <button
            type="button"
            onClick={() => setShowUrl((v) => !v)}
            className="w-full flex items-center justify-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-300"
          >
            <Server size={11} /> {showUrl ? 'Ocultar conexión' : 'Cambiar backend'}
          </button>
          {showUrl && (
            <div className="flex gap-2">
              <input
                value={urlDraft}
                onChange={(e) => setUrlDraft(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), applyUrl())}
                className="flex-1 min-w-0 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"
              />
              <button type="button" onClick={applyUrl} className="text-xs px-3 rounded bg-gray-700 hover:bg-gray-600 text-gray-100 shrink-0">
                Aplicar
              </button>
            </div>
          )}
        </form>

        <p className="text-center text-[10px] text-gray-600 mt-4 leading-relaxed">
          ¿Primera vez? Crea las cuentas en el servidor con<br />
          <span className="font-mono text-gray-500">backend/crear_usuarios_iniciales.py</span>
        </p>
      </div>
    </div>
  );
}
