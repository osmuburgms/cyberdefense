/* eslint-disable react-refresh/only-export-components -- este módulo expone el contexto + hook juntos a propósito */
import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { apiFetch, getToken, setToken } from './api';

const AuthCtx = createContext(null);

// Sesión del dashboard: guarda el JWT, expone login/logout y el usuario con su rol.
export function AuthProvider({ backendUrl, children }) {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);

  const logout = useCallback(() => {
    setToken('');
    setUser(null);
  }, []);

  // Valida el token guardado contra el backend al arrancar / cambiar de URL.
  useEffect(() => {
    let alive = true;
    (async () => {
      setChecking(true);
      if (!getToken()) {
        if (alive) {
          setUser(null);
          setChecking(false);
        }
        return;
      }
      try {
        const me = await apiFetch(backendUrl, '/api/auth/me');
        if (alive) setUser(me);
      } catch {
        setToken('');
        if (alive) setUser(null);
      }
      if (alive) setChecking(false);
    })();
    return () => { alive = false; };
  }, [backendUrl]);

  const login = useCallback(async (username, password) => {
    const data = await apiFetch(backendUrl, '/api/auth/login', {
      method: 'POST',
      body: { username: username.trim(), password },
    });
    setToken(data.token);
    setUser(data.user);
    return data.user;
  }, [backendUrl]);

  return (
    <AuthCtx.Provider value={{ user, checking, login, logout, isAdmin: user?.role === 'admin' }}>
      {children}
    </AuthCtx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth fuera de AuthProvider');
  return ctx;
}
