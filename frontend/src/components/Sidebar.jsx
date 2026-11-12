import { LayoutDashboard, Activity, Server, Users, Settings, Menu } from 'lucide-react';
import { LogoIcon } from './Logo.jsx';

// Barra lateral estilo Issabel: oscura, con grupos, colapsable a iconos.
const NAV_ITEMS = [
  { group: 'Monitoreo' },
  { key: 'dashboard', label: 'Panel principal', Icon: LayoutDashboard },
  { key: 'eventos', label: 'Eventos y análisis', Icon: Activity },
  { group: 'Sistema' },
  { key: 'sistema', label: 'Servicios y blockchain', Icon: Server },
  { group: 'Administración' },
  { key: 'usuarios', label: 'Usuarios', Icon: Users, admin: true },
  { key: 'config', label: 'Configuración', Icon: Settings },
];

export default function Sidebar({ view, setView, collapsed, setCollapsed, isAdmin }) {
  return (
    <aside
      // Colapsada la barra no puede bajar de ~76px: el logo (28) + el botón de
      // menú (24) + el hueco entre ellos (6) + el padding (16) suman 74px. Con
      // menos ancho el botón se salía del raíl y quedaba tapado por el panel
      // principal, de modo que ya no se podía volver a desplegar.
      className={`cd-sidebar shrink-0 bg-[#101a2e] border-r border-gray-800 flex flex-col transition-all duration-150 h-screen sticky top-0 ${collapsed ? 'w-[76px]' : 'w-[218px]'}`}
      aria-label="Navegación principal"
    >
      <div className={`flex items-center h-14 border-b border-gray-800 shrink-0 ${collapsed ? 'px-2 gap-1.5' : 'px-3 gap-2'}`}>
        <LogoIcon className={`${collapsed ? 'w-7 h-7' : 'w-8 h-8'} shrink-0`} />
        {!collapsed && (
          <span className="flex-1 min-w-0">
            <span className="block text-[13px] font-bold text-gray-100 leading-tight truncate">CyberDefense AI</span>
            <span className="block text-[9px] text-gray-500 font-mono">SOC · datacenter</span>
          </span>
        )}
        <button
          onClick={() => setCollapsed((v) => !v)}
          className={`shrink-0 rounded text-gray-500 hover:text-gray-100 hover:bg-gray-800 ${collapsed ? 'p-1' : 'p-1.5'}`}
          aria-label={collapsed ? 'Expandir menú' : 'Contraer menú'}
          title={collapsed ? 'Expandir menú' : 'Contraer menú'}
        >
          <Menu size={16} />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto py-2 terminal-scroll">
        {NAV_ITEMS.map((it, i) => {
          if (it.group) {
            if (collapsed) return <div key={i} className="mx-3 my-2 border-t border-gray-800" />;
            return (
              <p key={i} className="px-4 mt-3 mb-1 text-[9px] font-semibold text-gray-600 uppercase tracking-widest">
                {it.group}
              </p>
            );
          }
          if (it.admin && !isAdmin) return null;
          const active = view === it.key;
          const Icon = it.Icon;
          return (
            <button
              key={it.key}
              onClick={() => setView(it.key)}
              title={collapsed ? it.label : undefined}
              className={`w-full flex items-center gap-3 px-4 py-2 text-[13px] transition-colors border-l-2 ${
                active
                  ? 'bg-blue-600/10 border-blue-500 text-gray-100 font-semibold'
                  : 'border-transparent text-gray-400 hover:text-gray-100 hover:bg-gray-800/50'
              } ${collapsed ? 'justify-center px-0' : ''}`}
              aria-current={active ? 'page' : undefined}
            >
              <Icon size={17} className={`shrink-0 ${active ? 'text-blue-400' : ''}`} />
              {!collapsed && <span className="truncate">{it.label}</span>}
            </button>
          );
        })}
      </nav>

      {!collapsed && (
        <div className="px-4 py-2.5 border-t border-gray-800 shrink-0">
          <p className="text-[9px] text-gray-600 font-mono">IPS · SDN + Solana</p>
        </div>
      )}
    </aside>
  );
}
