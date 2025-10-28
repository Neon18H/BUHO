import React from 'react';
import DashboardCards from './components/DashboardCards';
import FindingsTable from './components/FindingsTable';
import ScanMap from './components/ScanMap';
import { useScans } from './hooks/useScans';

const App: React.FC = () => {
  const { scans, isLoading, severityTally } = useScans();

  return (
    <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
      <header style={{ marginBottom: '2rem' }}>
        <h1 style={{ margin: 0 }}>Buh - Plataforma de Escaneo</h1>
        <p style={{ opacity: 0.8 }}>
          Orquestación inteligente de Wapiti, Nikto, SQLmap y GoBuster con priorización y asistencia IA.
        </p>
      </header>
      {isLoading ? (
        <p>Cargando escaneos...</p>
      ) : (
        <>
          <DashboardCards
            totalScans={scans.length}
            activeScans={scans.filter((scan) => scan.status === 'running').length}
            severityTally={severityTally}
          />
          <div className="grid" style={{ margin: '2rem 0' }}>
            <ScanMap scans={scans} />
          </div>
          <FindingsTable scans={scans} />
        </>
      )}
    </div>
  );
};

export default App;
