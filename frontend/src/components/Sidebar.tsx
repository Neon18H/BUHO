import React from 'react';

type ViewKey = 'dashboard' | 'attack-paths' | 'targets';

interface SidebarProps {
  activeView: ViewKey;
  collapsed: boolean;
  onSelect: (view: ViewKey) => void;
  onToggleCollapse: () => void;
}

const MENU: Array<{ key: ViewKey; label: string; description: string; icon: string }> = [
  {
    key: 'dashboard',
    label: 'Orquestación de escaneos',
    description: 'Configura herramientas y consulta resultados en tiempo real.',
    icon: '🛠️'
  },
  {
    key: 'attack-paths',
    label: 'Rutas de ataque',
    description: 'Visualiza cómo un atacante encadenaría vulnerabilidades.',
    icon: '🧭'
  },
  {
    key: 'targets',
    label: 'Objetivos y riesgos',
    description: 'Supervisa CVE asociadas, impacto y remediaciones.',
    icon: '🎯'
  }
];

const Sidebar: React.FC<SidebarProps> = ({ activeView, collapsed, onSelect, onToggleCollapse }) => {
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo">Buh</div>
        <button type="button" className="sidebar-toggle" onClick={onToggleCollapse}>
          {collapsed ? '➤' : '◀'}
        </button>
      </div>
      <nav className="sidebar-menu">
        {MENU.map((item) => {
          const isActive = item.key === activeView;
          return (
            <button
              key={item.key}
              type="button"
              className={`menu-item ${isActive ? 'menu-item-active' : ''}`}
              onClick={() => onSelect(item.key)}
              title={collapsed ? item.label : undefined}
            >
              <span className="menu-icon" aria-hidden>{item.icon}</span>
              {!collapsed && (
                <span className="menu-text">
                  <strong>{item.label}</strong>
                  <small>{item.description}</small>
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </aside>
  );
};

export type { ViewKey };
export default Sidebar;
