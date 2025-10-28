import { useEffect, useState } from 'react'
import { MapContainer, Marker, Popup, TileLayer } from 'react-leaflet'
import { fetchDisclaimer, fetchVulnerabilities, fetchVulnerability, requestRemediation } from '../api'
import 'leaflet/dist/leaflet.css'

const severityColors = {
  critical: 'bg-red-600',
  high: 'bg-red-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
}

const defaultPosition = [40.4168, -3.7038]

export default function VulnsPage() {
  const [vulns, setVulns] = useState([])
  const [selectedVuln, setSelectedVuln] = useState(null)
  const [remediation, setRemediation] = useState(null)
  const [disclaimer, setDisclaimer] = useState('')
  const [filters, setFilters] = useState({ severity: '' })

  useEffect(() => {
    fetchDisclaimer().then((data) => setDisclaimer(data.message))
  }, [])

  useEffect(() => {
    fetchVulnerabilities(filters.severity ? { severity: filters.severity } : {}).then((items) => setVulns(items))
  }, [filters])

  const handleSelect = async (id) => {
    const data = await fetchVulnerability(id)
    setSelectedVuln(data)
    setRemediation(null)
  }

  const handleRemediate = async (id) => {
    const data = await requestRemediation(id)
    setRemediation(data.remediation)
  }

  const exportCSV = () => {
    const headers = ['ID', 'Tool', 'Target', 'Title', 'Severity', 'Priority', 'Score']
    const rows = vulns.map((v) => [v.id, v.tool, v.target, v.title, v.severity, v.priority_label, v.priority_score])
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', 'vulnerabilities.csv')
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  return (
    <div className="min-h-screen p-6 space-y-6">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold text-slate-900">Panel Buho</h1>
        <p className="text-sm text-slate-600">Solo escanear sistemas con permiso explícito y por escrito. El autor no se responsabiliza por uso malicioso.</p>
        <p className="text-xs text-slate-500">{disclaimer}</p>
      </header>

      <section className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <label htmlFor="severity">Severidad</label>
          <select
            id="severity"
            className="border border-slate-300 rounded px-2 py-1"
            value={filters.severity}
            onChange={(e) => setFilters((prev) => ({ ...prev, severity: e.target.value }))}
          >
            <option value="">Todas</option>
            <option value="critical">Crítica</option>
            <option value="high">Alta</option>
            <option value="medium">Media</option>
            <option value="low">Baja</option>
          </select>
        </div>
        <button onClick={exportCSV} className="bg-slate-800 text-white px-3 py-1 rounded">Exportar CSV</button>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white shadow rounded-lg overflow-hidden">
          <table className="min-w-full divide-y divide-slate-200">
            <thead className="bg-slate-100">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">ID</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Tool</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Título</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Severidad</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Prioridad</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Score</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-slate-200">
              {vulns.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-slate-50">
                  <td className="px-4 py-2 text-sm text-slate-700">{vuln.id}</td>
                  <td className="px-4 py-2 text-sm text-slate-700">{vuln.tool}</td>
                  <td className="px-4 py-2 text-sm text-slate-700">{vuln.title}</td>
                  <td className="px-4 py-2 text-sm">
                    <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold text-white rounded ${severityColors[vuln.severity] || 'bg-slate-400'}`}>
                      {vuln.severity || 'N/A'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-sm text-slate-700">{vuln.priority_label || 'P4'}</td>
                  <td className="px-4 py-2 text-sm text-slate-700">{vuln.priority_score?.toFixed?.(2) || '—'}</td>
                  <td className="px-4 py-2 text-right">
                    <button onClick={() => handleSelect(vuln.id)} className="text-indigo-600 hover:text-indigo-800 text-sm">Ver</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <aside className="space-y-4">
          <div className="bg-white shadow rounded-lg p-4">
            <h2 className="text-lg font-semibold text-slate-800 mb-2">Mapa de cobertura</h2>
            <MapContainer center={defaultPosition} zoom={3} style={{ height: '240px', width: '100%' }}>
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              />
              {vulns.slice(0, 5).map((vuln) => (
                <Marker key={`marker-${vuln.id}`} position={defaultPosition}>
                  <Popup>
                    <strong>{vuln.title}</strong>
                    <p>{vuln.tool}</p>
                  </Popup>
                </Marker>
              ))}
            </MapContainer>
          </div>

          {selectedVuln && (
            <div className="bg-white shadow rounded-lg p-4 space-y-2">
              <div className="flex justify-between items-center">
                <h2 className="text-lg font-semibold text-slate-800">Detalle</h2>
                <button
                  className="text-indigo-600 hover:text-indigo-800 text-sm"
                  onClick={() => handleRemediate(selectedVuln.id)}
                >
                  Generar remediación (IA)
                </button>
              </div>
              <p className="text-sm text-slate-700">{selectedVuln.description}</p>
              <p className="text-sm text-slate-500">CVSS: {selectedVuln.cvss_v3 || 'N/A'}</p>
              <p className="text-sm text-slate-500">CVE: {(selectedVuln.cve || []).join(', ') || 'N/A'}</p>
              <div>
                <h3 className="text-xs uppercase text-slate-500">Evidencia</h3>
                <pre className="bg-slate-900 text-slate-200 text-xs p-2 rounded overflow-x-auto max-h-40">
                  {JSON.stringify(selectedVuln.evidence, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {remediation && (
            <div className="bg-white shadow rounded-lg p-4 space-y-2">
              <h2 className="text-lg font-semibold text-slate-800">Plan de remediación</h2>
              <p className="text-sm text-slate-700">{remediation.remediation_short}</p>
              <ul className="list-disc list-inside text-sm text-slate-600">
                {remediation.remediation_steps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ul>
              <div className="text-xs text-slate-500">
                <p><strong>Inmediato:</strong> {remediation.mitigation_timeline.immediate}</p>
                <p><strong>Corto plazo:</strong> {remediation.mitigation_timeline.short_term}</p>
                <p><strong>Largo plazo:</strong> {remediation.mitigation_timeline.long_term}</p>
              </div>
            </div>
          )}
        </aside>
      </section>
    </div>
  )
}
