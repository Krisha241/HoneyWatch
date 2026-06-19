import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { Activity, Users, Globe, Shield } from 'lucide-react'

const FLAG_MAP = {
  CN: '🇨🇳', RU: '🇷🇺', US: '🇺🇸', DE: '🇩🇪', IN: '🇮🇳',
  BR: '🇧🇷', FR: '🇫🇷', GB: '🇬🇧', KR: '🇰🇷', NL: '🇳🇱',
  VN: '🇻🇳', TR: '🇹🇷', ID: '🇮🇩', UA: '🇺🇦', PK: '🇵🇰',
}

const SERVICE_COLORS = { SSH: '#14b8a6', HTTP: '#3b82f6', FTP: '#f59e0b' }
const SEVERITY_COLORS = { High: '#f87171', Medium: '#fbbf24', Low: '#4ade80' }

function MetricCard({ icon: Icon, label, value, sub }) {
  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
        <Icon size={16} className="text-gray-600" />
      </div>
      <p className="text-2xl font-bold text-white font-mono">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  )
}

export default function StatsPanel() {
  const [stats, setStats]   = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchStats = () => {
    fetch('/api/events/stats')
      .then(r => r.json())
      .then(data => { setStats(data); setLoading(false) })
      .catch(console.error)
  }

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 30000) // refresh every 30s
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="text-center text-gray-600 py-12 text-sm">
        Loading stats...
      </div>
    )
  }

  // Recharts data
  const serviceData = Object.entries(stats.by_service || {}).map(([name, value]) => ({
    name, value, fill: SERVICE_COLORS[name] || '#6b7280'
  }))

  const severityData = Object.entries(stats.by_severity || {}).map(([name, value]) => ({
    name, value
  }))

  const topService = Object.entries(stats.by_service || {})
    .sort((a, b) => b[1] - a[1])[0]?.[0] || '—'

  return (
    <div className="space-y-4">
      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard icon={Activity} label="Total Events"  value={stats.total}      sub="all time" />
        <MetricCard icon={Users}    label="Unique IPs"    value={stats.unique_ips} sub="attackers seen" />
        <MetricCard icon={Globe}    label="Top Country"
          value={stats.top_countries[0]
            ? `${FLAG_MAP[stats.top_countries[0].country_code] || '🌐'} ${stats.top_countries[0].country_code || '?'}`
            : '—'}
          sub={stats.top_countries[0]?.country || 'no geo data yet'}
        />
        <MetricCard icon={Shield}   label="Most Targeted" value={topService} sub="service" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Service breakdown — pie */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-xs text-gray-500 uppercase tracking-wide mb-4">By Service</h3>
          {serviceData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={serviceData} dataKey="value" nameKey="name"
                  cx="50%" cy="50%" outerRadius={60} label={({name, value}) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {serviceData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  labelStyle={{ color: '#9ca3af' }} itemStyle={{ color: '#e5e7eb' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-600 text-sm text-center py-8">No data yet</p>}
        </div>

        {/* Severity breakdown — bar */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-xs text-gray-500 uppercase tracking-wide mb-4">By Severity</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={severityData} barSize={32}>
                <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  labelStyle={{ color: '#9ca3af' }} itemStyle={{ color: '#e5e7eb' }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[entry.name] || '#6b7280'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-600 text-sm text-center py-8">No data yet</p>}
        </div>

        {/* Top countries */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-xs text-gray-500 uppercase tracking-wide mb-4">Top Countries</h3>
          {stats.top_countries.length > 0 ? (
            <div className="space-y-2">
              {stats.top_countries.slice(0, 6).map((c, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-sm">{FLAG_MAP[c.country_code] || '🌐'}</span>
                  <span className="text-xs text-gray-300 flex-1 truncate">{c.country}</span>
                  <span className="text-xs font-mono text-gray-400">{c.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-8">
              No geo data yet.<br/>
              <span className="text-xs">External IPs needed for GeoIP.</span>
            </p>
          )}
        </div>
      </div>

      {/* Credentials tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Top usernames */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-xs text-gray-500 uppercase tracking-wide mb-3">Top Usernames Tried</h3>
          {stats.top_usernames.length > 0 ? (
            <div className="space-y-1.5">
              {stats.top_usernames.map((u, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-sm font-mono text-red-300">{u.username}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 rounded-full bg-red-900"
                      style={{ width: `${(u.count / stats.top_usernames[0].count) * 80}px` }} />
                    <span className="text-xs text-gray-500 font-mono w-6 text-right">{u.count}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="text-gray-600 text-sm">No credentials captured yet.</p>}
        </div>

        {/* Top passwords */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <h3 className="text-xs text-gray-500 uppercase tracking-wide mb-3">Top Passwords Tried</h3>
          {stats.top_passwords.length > 0 ? (
            <div className="space-y-1.5">
              {stats.top_passwords.map((p, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-sm font-mono text-amber-300">{p.password}</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 rounded-full bg-amber-900"
                      style={{ width: `${(p.count / stats.top_passwords[0].count) * 80}px` }} />
                    <span className="text-xs text-gray-500 font-mono w-6 text-right">{p.count}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="text-gray-600 text-sm">No credentials captured yet.</p>}
        </div>

      </div>
    </div>
  )
}