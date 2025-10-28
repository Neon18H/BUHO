import React from 'react';

interface DashboardCardsProps {
  totalScans: number;
  activeScans: number;
  severityTally: Record<string, number>;
}

const DashboardCards: React.FC<DashboardCardsProps> = ({ totalScans, activeScans, severityTally }) => {
  return (
    <div className="grid grid-two">
      <div className="card">
        <h3>Escaneos totales</h3>
        <p style={{ fontSize: '2.5rem', margin: '0.5rem 0' }}>{totalScans}</p>
        <small>{activeScans} en progreso</small>
      </div>
      <div className="card">
        <h3>Vulnerabilidades por criticidad</h3>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {Object.entries(severityTally).map(([level, count]) => (
            <li key={level} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <span style={{ textTransform: 'capitalize' }}>{level}</span>
              <strong>{count}</strong>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default DashboardCards;
