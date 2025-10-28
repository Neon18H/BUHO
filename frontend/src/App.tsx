import React, { useState } from 'react';
import DashboardCards from './components/DashboardCards';
import FindingsTable from './components/FindingsTable';
import ScanLauncher from './components/ScanLauncher';
import ScanMap from './components/ScanMap';
import ScanList from './components/ScanList';
import Sidebar, { ViewKey } from './components/Sidebar';
import AttackPathsView from './components/AttackPathsView';
import AssetsOverview from './components/AssetsOverview';
import { useScans } from './hooks/useScans';

const App: React.FC = () => {
  const {
    scans,
    isLoading,
    severityTally,
    createScan,
    isCreating,
    error,
    deleteScan,
    deletingIds
  } = useScans();
  const [activeView, setActiveView] = useState<ViewKey>('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);

  const renderDashboard = () => (
    <>
      <ScanLauncher onCreate={createScan} isCreating={isCreating} error={error} />
      <DashboardCards
        totalScans={scans.length}
        activeScans={scans.filter((scan) => scan.status === 'running').length}
        severityTally={severityTally}
      />
      <div className="grid grid-two" style={{ margin: '2rem 0' }}>
        <ScanMap scans={scans} />
        <ScanList scans={scans} onDelete={deleteScan} deletingIds={deletingIds} />
      </div>
      <FindingsTable scans={scans} />
    </>
  );

  const renderView = () => {
    switch (activeView) {
      case 'attack-paths':
        return <AttackPathsView scans={scans} />;
      case 'targets':
        return <AssetsOverview scans={scans} />;
      case 'dashboard':
      default:
        return renderDashboard();
    }
  };

  return (
    <div className={`app-shell ${sidebarCollapsed ? 'sidebar-is-collapsed' : ''}`}>
      <Sidebar
        activeView={activeView}
        collapsed={sidebarCollapsed}
        onSelect={setActiveView}
        onToggleCollapse={() => setSidebarCollapsed((prev) => !prev)}
      />
      <main className="app-main">
        <header className="app-header">
          <div>
            <h1>Buh - Plataforma de Escaneo</h1>
            <p>
              Orquesta Wapiti, Nikto, SQLmap y GoBuster con enriquecimiento automático, rutas de ataque
              y priorización accionable.
            </p>
          </div>
          <div className="header-meta">
            <span className="meta-label">Escaneos totales</span>
            <strong>{scans.length}</strong>
          </div>
        </header>
        <section className="app-content">
          {isLoading ? <div className="card">Cargando escaneos...</div> : renderView()}
        </section>
      </main>
    </div>
  );
};

export default App;
