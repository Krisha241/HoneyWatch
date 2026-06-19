import { useState } from 'react'
import { Shield } from 'lucide-react'
import EventFeed from '../components/EventFeed'
import StatsPanel from '../components/StatsPanel'
import IPDrilldown from '../components/IPDrilldown'

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('feed')
  const [drilldownIP, setDrilldownIP] = useState(null)

  const tabs = [
    { id: 'feed', label: 'Live Feed' },
    { id: 'stats', label: 'Statistics' },
  ]

  return (
    <div className="min-h-screen bg-gray-950">

      <nav className="border-b border-gray-800 bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield size={20} className="text-teal-400" />
            <span className="font-bold text-white tracking-tight">HoneyWatch</span>
            <span className="text-xs text-gray-600 font-mono">v0.4.0</span>
          </div>

          <div className="flex items-center gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={
                  activeTab === tab.id
                    ? 'px-4 py-1.5 rounded text-sm font-medium bg-gray-700 text-white'
                    : 'px-4 py-1.5 rounded text-sm font-medium text-gray-400 hover:text-white'
                }
              >
                {tab.label}
              </button>
            ))}
          </div>

          
            <a href="/api/events?per_page=200"
            target="_blank"
            rel="noreferrer"
            className="text-xs text-gray-500 hover:text-gray-300 font-mono"
          >
            API
          </a>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">

        {activeTab === 'feed' && (
          <div className="space-y-4">
            <div>
              <h1 className="text-lg font-semibold text-white">Live Event Feed</h1>
              <p className="text-sm text-gray-500 mt-0.5">
                Real-time capture from SSH, HTTP, and FTP honeypots
              </p>
            </div>
            <EventFeed onIPClick={setDrilldownIP} />
          </div>
        )}

        {activeTab === 'stats' && (
          <div className="space-y-4">
            <div>
              <h1 className="text-lg font-semibold text-white">Attack Statistics</h1>
              <p className="text-sm text-gray-500 mt-0.5">
                Aggregated data from all honeypot services — refreshes every 30s
              </p>
            </div>
            <StatsPanel onIPClick={setDrilldownIP} />
          </div>
        )}

      </main>

      <IPDrilldown ip={drilldownIP} onClose={() => setDrilldownIP(null)} />
    </div>
  )
}