import { LayoutDashboard, Activity, Server, Users, Settings, Menu, ShieldAlert } from 'lucide-react';

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
      className={`shrink-0 bg-[#141a29] border-r border-gray-800 flex flex-col transition-all duration-150 h-screen sticky top-0 ${collapsed ? 'w-[60px]' : 'w-[218px]'}`}
      aria-label="Navegación principal"
    >
      <div className="flex items-center gap-2 px-3 h-14 border-b border-gray-800 shrink-0">
        <span className="w-8 h-8 rounded-lg bg-red-600/15 border border-red-800 flex items-center justify-center shrink-0">
          <ShieldAlert size={17} className="text-red-500" />
        </span>
        {!collapsed && (
          <span className="flex-1 min-w-0">
            <span className="block text-[13px] font-bold text-gray-100 leading-tight truncate">SDN Cyberdefense</span>
            <span className="block text-[9px] text-gray-500 font-mono">SOC · datacenter</span>
          </span>
        )}
        <button
          onClick={() => setCollapsed((v) => !v)}
          className="p-1.5 rounded text-gray-500 hover:text-gray-100 hover:bg-gray-800 shrink-0"
          aria-label={collapsed ? 'Expandir menú' : 'Contraer menú'}
          title="Menú"
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
