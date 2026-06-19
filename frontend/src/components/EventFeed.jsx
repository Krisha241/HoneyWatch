import { useEffect, useState, useRef } from 'react'
import { Shield, Globe, Terminal, Server } from 'lucide-react'

const SERVICE_STYLES = {
  SSH:  { bg: 'bg-teal-900',  text: 'text-teal-300',  icon: Terminal },
  HTTP: { bg: 'bg-blue-900',  text: 'text-blue-300',  icon: Globe    },
  FTP:  { bg: 'bg-amber-900', text: 'text-amber-300', icon: Server   },
}

const SEVERITY_STYLES = {
  High:   'text-red-400',
  Medium: 'text-yellow-400',
  Low:    'text-green-400',
}

const FLAG_MAP = {
  CN: '🇨🇳', RU: '🇷🇺', US: '🇺🇸', DE: '🇩🇪', IN: '🇮🇳',
  BR: '🇧🇷', FR: '🇫🇷', GB: '🇬🇧', KR: '🇰🇷', NL: '🇳🇱',
  VN: '🇻🇳', TR: '🇹🇷', ID: '🇮🇩', UA: '🇺🇦', PK: '🇵🇰',
}

function ServiceBadge({ service }) {
  const style = SERVICE_STYLES[service] || { bg: 'bg-gray-800', text: 'text-gray-300', icon: Shield }
  const Icon  = style.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium ${style.bg} ${style.text}`}>
      <Icon size={11} />
      {service}
    </span>
  )
}

function EventRow({ event, onClick, isNew }) {
  const time = new Date(event.timestamp).toLocaleTimeString()
  const flag = event.country_code ? (FLAG_MAP[event.country_code] || '🌐') : '🔒'
  const location = event.city && event.country
    ? `${event.city}, ${event.country}`
    : event.country || 'Private / Local'

  return (
    <div
      onClick={() => onClick(event)}
      className={`flex items-center gap-3 px-4 py-2.5 border-b border-gray-800
        hover:bg-gray-800 cursor-pointer transition-colors text-sm
        ${isNew ? 'animate-pulse bg-gray-800' : ''}`}
    >
      <span className="text-gray-500 font-mono text-xs w-20 shrink-0">{time}</span>
      <ServiceBadge service={event.service} />
      <span className="text-gray-300 font-mono text-xs w-32 shrink-0 truncate">
        {event.source_ip}
      </span>
      <span className="text-gray-400 text-xs w-36 shrink-0 truncate">
        {flag} {location}
      </span>
      <span className="text-gray-400 text-xs truncate flex-1">
        {event.username
          ? <span>user: <span className="text-white font-mono">{event.username}</span></span>
          : <span className="text-gray-600">no credentials</span>
        }
      </span>
      <span className={`text-xs font-medium shrink-0 ${SEVERITY_STYLES[event.severity] || 'text-gray-400'}`}>
        {event.severity}
      </span>
    </div>
  )
}

function EventDetail({ event, onClose }) {
  if (!event) return null
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <ServiceBadge service={event.service} />
            <span className="font-mono text-sm text-gray-300">{event.source_ip}</span>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl leading-none">×</button>
        </div>
        <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Timestamp</p>
              <p className="text-gray-200 font-mono">{new Date(event.timestamp).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Severity</p>
              <p className={`font-medium ${SEVERITY_STYLES[event.severity]}`}>{event.severity}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Location</p>
              <p className="text-gray-200">
                {event.city && event.country
                  ? `${event.city}, ${event.country}`
                  : 'Unknown / Private'}
              </p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Source Port</p>
              <p className="text-gray-200 font-mono">{event.source_port || '—'}</p>
            </div>
            {event.username && (
              <div>
                <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Username tried</p>
                <p className="text-red-300 font-mono">{event.username}</p>
              </div>
            )}
            {event.password && (
              <div>
                <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Password tried</p>
                <p className="text-red-300 font-mono">{event.password}</p>
              </div>
            )}
          </div>
          {event.raw_payload && (
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wide mb-2">Raw Payload</p>
              <pre className="bg-gray-950 rounded-lg p-3 text-xs text-green-400 font-mono
                overflow-x-auto whitespace-pre-wrap break-all border border-gray-800">
                {event.raw_payload}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function EventFeed() {
  const [events, setEvents]         = useState([])
  const [selected, setSelected]     = useState(null)
  const [newIds, setNewIds]         = useState(new Set())
  const [paused, setPaused]         = useState(false)
  const pausedRef                   = useRef(false)

  // Load last 50 events on mount
  useEffect(() => {
    fetch('/api/events?per_page=50')
      .then(r => r.json())
      .then(data => setEvents(data.events || []))
      .catch(console.error)
  }, [])

  // SSE stream for live updates
  useEffect(() => {
    const es = new EventSource('/api/events/stream')
    es.onmessage = (e) => {
      if (pausedRef.current) return
      const event = JSON.parse(e.data)
      setEvents(prev => [event, ...prev].slice(0, 200))
      setNewIds(prev => new Set([...prev, event.id]))
      setTimeout(() => {
        setNewIds(prev => { const n = new Set(prev); n.delete(event.id); return n })
      }, 2000)
    }
    es.onerror = () => es.close()
    return () => es.close()
  }, [])

  const togglePause = () => {
    pausedRef.current = !pausedRef.current
    setPaused(pausedRef.current)
  }

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
          <h2 className="text-sm font-medium text-gray-200">Live Event Feed</h2>
          <span className="text-xs text-gray-500 font-mono">({events.length} events)</span>
        </div>
        <button
          onClick={togglePause}
          className="text-xs px-3 py-1 rounded border border-gray-700
            hover:border-gray-500 text-gray-400 hover:text-white transition-colors"
        >
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
      </div>

      {/* Column headers */}
      <div className="flex items-center gap-3 px-4 py-2 bg-gray-950 text-xs text-gray-600 font-medium uppercase tracking-wide">
        <span className="w-20 shrink-0">Time</span>
        <span className="w-16 shrink-0">Service</span>
        <span className="w-32 shrink-0">Source IP</span>
        <span className="w-36 shrink-0">Location</span>
        <span className="flex-1">Credentials</span>
        <span className="shrink-0">Severity</span>
      </div>

      {/* Event rows */}
      <div className="max-h-96 overflow-y-auto">
        {events.length === 0 ? (
          <div className="text-center text-gray-600 py-12 text-sm">
            Waiting for attackers...
          </div>
        ) : (
          events.map(event => (
            <EventRow
              key={event.id}
              event={event}
              onClick={setSelected}
              isNew={newIds.has(event.id)}
            />
          ))
        )}
      </div>

      {/* Detail modal */}
      <EventDetail event={selected} onClose={() => setSelected(null)} />
    </div>
  )
}