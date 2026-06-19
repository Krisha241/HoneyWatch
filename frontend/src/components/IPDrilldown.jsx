import { useEffect, useState } from 'react'
import { ExternalLink } from 'lucide-react'

const SERVICE_COLORS = {
  SSH:  'bg-teal-900 text-teal-300',
  HTTP: 'bg-blue-900 text-blue-300',
  FTP:  'bg-amber-900 text-amber-300',
}

export default function IPDrilldown({ ip, onClose }) {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!ip) return
    fetch(`/api/events?ip=${ip}&per_page=100`)
      .then(r => r.json())
      .then(data => { setEvents(data.events || []); setLoading(false) })
      .catch(console.error)
  }, [ip])

  if (!ip) return null

  const services    = [...new Set(events.map(e => e.service))]
  const credentials = events.filter(e => e.username || e.password)
  const location    = events.find(e => e.country)
  const firstSeen   = events.length ? new Date(events[events.length - 1].timestamp).toLocaleString() : '—'
  const lastSeen    = events.length ? new Date(events[0].timestamp).toLocaleString() : '—'

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-800">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Attacker IP</p>
            <p className="text-lg font-mono text-white">{ip}</p>
          </div>
          <div className="flex items-center gap-2">
            <a href={`https://www.shodan.io/host/${ip}`} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 px-2 py-1
                border border-blue-900 rounded transition-colors">
              Shodan <ExternalLink size={10} />
            </a>
            <a href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300 px-2 py-1
                border border-purple-900 rounded transition-colors">
              AbuseIPDB <ExternalLink size={10} />
            </a>
            <button onClick={onClose} className="text-gray-500 hover:text-white text-xl leading-none ml-2">×</button>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {loading ? (
            <p className="text-gray-500 text-sm text-center py-8">Loading...</p>
          ) : (
            <>
              {/* Summary grid */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-gray-950 rounded-lg p-3">
                  <p className="text-gray-500 text-xs mb-1">Total Events</p>
                  <p className="text-white font-mono text-lg">{events.length}</p>
                </div>
                <div className="bg-gray-950 rounded-lg p-3">
                  <p className="text-gray-500 text-xs mb-1">Location</p>
                  <p className="text-white text-sm">
                    {location
                      ? `${location.city || ''} ${location.country || ''}`.trim()
                      : 'Unknown / Private'}
                  </p>
                </div>
                <div className="bg-gray-950 rounded-lg p-3">
                  <p className="text-gray-500 text-xs mb-1">First Seen</p>
                  <p className="text-white font-mono text-xs">{firstSeen}</p>
                </div>
                <div className="bg-gray-950 rounded-lg p-3">
                  <p className="text-gray-500 text-xs mb-1">Last Seen</p>
                  <p className="text-white font-mono text-xs">{lastSeen}</p>
                </div>
              </div>

              {/* Services hit */}
              <div>
                <p className="text-gray-500 text-xs uppercase tracking-wide mb-2">Services Targeted</p>
                <div className="flex gap-2 flex-wrap">
                  {services.map(s => (
                    <span key={s} className={`px-3 py-1 rounded-full text-xs font-medium ${SERVICE_COLORS[s] || 'bg-gray-800 text-gray-300'}`}>
                      {s}
                    </span>
                  ))}
                </div>
              </div>

              {/* Credentials tried */}
              {credentials.length > 0 && (
                <div>
                  <p className="text-gray-500 text-xs uppercase tracking-wide mb-2">
                    Credentials Tried ({credentials.length})
                  </p>
                  <div className="bg-gray-950 rounded-lg overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-gray-800">
                          <th className="text-left px-3 py-2 text-gray-500">Service</th>
                          <th className="text-left px-3 py-2 text-gray-500">Username</th>
                          <th className="text-left px-3 py-2 text-gray-500">Password</th>
                          <th className="text-left px-3 py-2 text-gray-500">Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {credentials.map(e => (
                          <tr key={e.id} className="border-b border-gray-800/50">
                            <td className="px-3 py-2">
                              <span className={`px-1.5 py-0.5 rounded text-xs ${SERVICE_COLORS[e.service] || ''}`}>
                                {e.service}
                              </span>
                            </td>
                            <td className="px-3 py-2 font-mono text-red-300">{e.username || '—'}</td>
                            <td className="px-3 py-2 font-mono text-amber-300">{e.password || '—'}</td>
                            <td className="px-3 py-2 text-gray-500">
                              {new Date(e.timestamp).toLocaleTimeString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Attack sequence */}
              <div>
                <p className="text-gray-500 text-xs uppercase tracking-wide mb-2">Attack Timeline</p>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {events.map(e => (
                    <div key={e.id} className="flex items-center gap-3 text-xs">
                      <span className="text-gray-600 font-mono w-20 shrink-0">
                        {new Date(e.timestamp).toLocaleTimeString()}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-xs shrink-0 ${SERVICE_COLORS[e.service] || ''}`}>
                        {e.service}
                      </span>
                      <span className="text-gray-400 truncate">
                        {e.username ? `tried: ${e.username}` : 'probe / scan'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}