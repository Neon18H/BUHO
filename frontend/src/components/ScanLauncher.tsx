import React, { useState } from 'react';

const DEFAULT_TOOLS = ['wapiti', 'nikto', 'sqlmap', 'gobuster'];

interface ScanLauncherProps {
  onCreate: (target: string, tools: string[]) => Promise<unknown>;
  isCreating: boolean;
  error: string | null;
}

const toolsMetadata: Record<string, { label: string; description: string }> = {
  wapiti: {
    label: 'Wapiti',
    description: 'Scanner web enfocado en detectar vulnerabilidades OWASP.'
  },
  nikto: {
    label: 'Nikto',
    description: 'Scanner de servidores web y configuraciones inseguras.'
  },
  sqlmap: {
    label: 'SQLmap',
    description: 'Automatiza la explotación de vulnerabilidades SQL Injection.'
  },
  gobuster: {
    label: 'GoBuster',
    description: 'Descubrimiento de directorios y recursos ocultos.'
  }
};

const ScanLauncher: React.FC<ScanLauncherProps> = ({ onCreate, isCreating, error }) => {
  const [target, setTarget] = useState('');
  const [selectedTools, setSelectedTools] = useState<string[]>(DEFAULT_TOOLS);
  const [localError, setLocalError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const toggleTool = (tool: string) => {
    setSelectedTools((prev) => {
      if (prev.includes(tool)) {
        const next = prev.filter((value) => value !== tool);
        return next.length ? next : prev; // evitar dejar cero herramientas
      }
      return [...prev, tool];
    });
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLocalError(null);
    setSuccessMessage(null);

    if (!target.trim()) {
      setLocalError('Ingresa una URL objetivo válida.');
      return;
    }

    try {
      await onCreate(target.trim(), selectedTools);
      setSuccessMessage('Escaneo iniciado correctamente.');
      setTarget('');
      setSelectedTools(DEFAULT_TOOLS);
    } catch (err) {
      if (!(err instanceof Error)) {
        setLocalError('No se pudo iniciar el escaneo, intenta nuevamente.');
      }
    }
  };

  return (
    <div className="card" style={{ marginBottom: '2rem' }}>
      <h2 style={{ marginTop: 0 }}>Iniciar nuevo escaneo</h2>
      <p style={{ marginTop: 0, opacity: 0.8 }}>
        Define el objetivo y selecciona las herramientas a ejecutar. Buh orquestará el flujo para
        generar hallazgos, CVE asociadas y remediaciones.
      </p>
      <form onSubmit={handleSubmit} className="scan-form">
        <label htmlFor="target-input" className="scan-label">
          URL objetivo
        </label>
        <input
          id="target-input"
          type="url"
          inputMode="url"
          placeholder="https://ejemplo.com"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          className="scan-input"
          required
        />

        <fieldset className="scan-fieldset">
          <legend>Herramientas a ejecutar</legend>
          <div className="tools-grid">
            {DEFAULT_TOOLS.map((tool) => (
              <label key={tool} className="tool-option">
                <input
                  type="checkbox"
                  checked={selectedTools.includes(tool)}
                  onChange={() => toggleTool(tool)}
                />
                <span>
                  <strong>{toolsMetadata[tool].label}</strong>
                  <small>{toolsMetadata[tool].description}</small>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        {(localError || error) && (
          <p className="scan-error">{error ?? localError}</p>
        )}
        {successMessage && <p className="scan-success">{successMessage}</p>}

        <button type="submit" className="scan-button" disabled={isCreating}>
          {isCreating ? 'Iniciando escaneo...' : 'Lanzar escaneo' }
        </button>
      </form>
    </div>
  );
};

export default ScanLauncher;
