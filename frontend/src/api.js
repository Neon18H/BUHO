import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('buho_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const fetchVulnerabilities = async (filters = {}) => {
  const params = new URLSearchParams(filters).toString()
  const { data } = await api.get(`/api/vulns${params ? `?${params}` : ''}`)
  return data.items
}

export const fetchVulnerability = async (id) => {
  const { data } = await api.get(`/api/vulns/${id}`)
  return data
}

export const requestRemediation = async (id) => {
  const { data } = await api.post(`/api/vulns/${id}/remediate`)
  return data
}

export const fetchDisclaimer = async () => {
  const { data } = await api.get('/legal-disclaimer')
  return data
}

export default api
