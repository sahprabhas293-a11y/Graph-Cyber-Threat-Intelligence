import { useEffect, useMemo, useRef, useState } from 'react'
import axios from 'axios'
import CytoscapeComponent from 'react-cytoscapejs'
import {
  Activity, AlertTriangle, BarChart3, Bug, CircleDot,
  Database, GitBranch, Globe, LayoutDashboard, LoaderCircle,
  Network, Search, Shield, ShieldAlert, Wifi, X
} from 'lucide-react'
import './App.css'

const api = axios.create({ baseURL: '/api', timeout: 15000 })

const graphStyle = [
  {
    selector: 'node',
    style: {
      'background-color': '#16b8a6',
      'label': 'data(label)',
      'color': '#e8f1ff',
      'font-size': 10,
      'text-wrap': 'wrap',
      'text-max-width': 110,
      'text-valign': 'bottom',
      'text-margin-y': 8,
      'border-width': 1,
      'border-color': '#5eead4',
      'width': 34,
      'height': 34
    }
  },
  { selector: 'node[type = "IP"]', style: { 'background-color': '#3b82f6', 'border-color': '#93c5fd' } },
  { selector: 'node[type = "Domain"]', style: { 'background-color': '#8b5cf6', 'border-color': '#c4b5fd' } },
  {
    selector: 'node[type = "MaliciousURL"]',
    style: {
      'background-color': '#ef4444',
      'border-color': '#fca5a5',
      'width': 25,
      'height': 25,
      'font-size': 8,
      'text-max-width': 75,
      'text-wrap': 'wrap'
    }
  },
  { selector: 'node[type = "ThreatTag"]', style: { 'background-color': '#d97706', 'border-color': '#fcd34d', 'width': 24, 'height': 24 } },
  { selector: 'node[type = "Malware"]', style: { 'background-color': '#db2777', 'border-color': '#f9a8d4' } },
  { selector: 'node[type = "ThreatActor"]', style: { 'background-color': '#64748b', 'border-color': '#cbd5e1' } },
  { selector: 'node[type = "ThreatPulse"]', style: { 'background-color': '#0f766e', 'border-color': '#5eead4', 'width': 42, 'height': 42, 'shape': 'hexagon' } },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': '#40516d',
      'target-arrow-color': '#64748b',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 0.8,
      'opacity': 0.8
    }
  },
  { selector: 'node:selected', style: { 'border-width': 4, 'border-color': '#ffffff' } }
]

function compactLabel(type, identifier) {
  const value = String(identifier)

  if (type === 'MaliciousURL') {
    try {
      const parsed = new URL(value)
      const host = parsed.hostname.replace(/^www\./, '')
      const filename = parsed.pathname.split('/').filter(Boolean).pop() || ''
      const shortFile = filename.length > 12
        ? filename.slice(0, 9) + '...'
        : filename

      return shortFile ? `${host.slice(0, 13)}/…${shortFile}` : host.slice(0, 18)
    } catch {
      return value.slice(0, 20) + '...'
    }
  }

  return value.length > 22 ? value.slice(0, 19) + '...' : value
}

function relationshipSummary(relation = {}) {
  const evidence = relation.evidence
  const type = relation.relationship_type || relation.relationship || relation.type

  if (
    type === 'SHARES_TAG' &&
    evidence &&
    Array.isArray(evidence.shared_tags) &&
    evidence.shared_tags.length
  ) {
    const source = evidence.source ? ` · ${evidence.source}` : ''
    return `Shared tags: ${evidence.shared_tags.join(', ')}${source}`
  }

  if (type === 'HOSTED_ON') {
    return 'Observed host association'
  }

  if (type === 'TAGGED_WITH') {
    return `Recorded threat tag: ${relation.target || 'Tag recorded'}`
  }

  if (typeof evidence === 'string' && evidence.trim()) {
    return evidence
  }

  if (
    evidence &&
    typeof evidence === 'object' &&
    !Array.isArray(evidence) &&
    Object.keys(evidence).length
  ) {
    return Object.entries(evidence)
      .map(([key, value]) => `${key.replaceAll('_', ' ')}: ${Array.isArray(value) ? value.join(', ') : value}`)
      .join(' · ')
  }

  return relation.classification === 'analytical_association'
    ? 'Analytical association; not proof of common attacker identity'
    : 'Relationship recorded in threat intelligence data'
}

function nodeIdentity(labels = [], properties = {}) {
  const type = labels[0] || 'Indicator'
  const identifier = properties.value || properties.name || properties.url || properties.id
  if (!identifier) return null
  return {
    id: encodeURIComponent(`${type}|${identifier}`),
    label: compactLabel(type, identifier),
    type,
    source: properties.source || 'Unknown',
    properties
  }
}

function makeGraphElements(graph) {
  const nodes = new Map()
  const edges = []

  for (const item of graph?.nodes || []) {
    const node = nodeIdentity(item.labels, item.properties || {})
    if (node) nodes.set(node.id, node)
  }

  for (const [index, relation] of (graph?.relationships || []).entries()) {
    const source = nodeIdentity(relation.source_labels, relation.source || {})
    const target = nodeIdentity(relation.target_labels, relation.target || {})
    if (!source || !target) continue

    nodes.set(source.id, source)
    nodes.set(target.id, target)

    edges.push({
      data: {
        id: `edge-${index}`,
        source: source.id,
        target: target.id,
        label: relation.relationship || 'RELATED_TO',
        relationship: relation.relationship || 'RELATED_TO',
        evidence: relation.evidence || '',
        sourceInformation: relation.source_information || 'Not specified',
        confidence: relation.confidence
      }
    })
  }

  return [
    ...[...nodes.values()].map(node => ({
      data: node
    })),
    ...edges
  ]
}

function MetricCard({ title, value, subtitle, icon: Icon, tone = 'teal' }) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${tone}`}><Icon size={19} /></div>
      <div className="metric-content">
        <span>{title}</span>
        <strong>{value ?? '—'}</strong>
        <small>{subtitle}</small>
      </div>
    </div>
  )
}

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [summary, setSummary] = useState(null)
  const [otxSummary, setOtxSummary] = useState(null)
  const [graph, setGraph] = useState(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [graphError, setGraphError] = useState('')
  const [graphRetry, setGraphRetry] = useState(0)
  const graphLoadStarted = useRef(false)
  const cyRef = useRef(null)
  const [rankings, setRankings] = useState([])
  const [evaluation, setEvaluation] = useState(null)
  const [realWorldEvaluation, setRealWorldEvaluation] = useState(null)
  const [investigation, setInvestigation] = useState(null)
  const [indicator, setIndicator] = useState('')
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [graphView, setGraphView] = useState('complete')
  const [graphTypeFilter, setGraphTypeFilter] = useState('all')
  const [graphSearch, setGraphSearch] = useState('')
  const [clusterOnly, setClusterOnly] = useState(false)
  const [clusterMessage, setClusterMessage] = useState('')
  const [loading, setLoading] = useState(true)
  const [searching, setSearching] = useState(false)
  const [error, setError] = useState('')

  const elements = useMemo(() => makeGraphElements(graph), [graph])

  const graphLayout = useMemo(() => ({
    name: 'cose',
    animate: false,
    padding: 50,
    nodeRepulsion: 9000,
    idealEdgeLength: 90,
    nodeOverlap: 12,
    numIter: 180,
    randomize: true
  }), [])

  const displayedElements = useMemo(() => {
    if (graphView === 'complete') return elements

    const nodes = elements.filter(item => !item.data.target)
    const edges = elements.filter(item => item.data.target)
    const query = graphSearch.trim().toLowerCase()

    if (clusterOnly && selectedNodeId) {
      const visibleIds = new Set([selectedNodeId])

      for (let depth = 0; depth < 2; depth++) {
        for (const edge of edges) {
          if (visibleIds.has(edge.data.source)) visibleIds.add(edge.data.target)
          if (visibleIds.has(edge.data.target)) visibleIds.add(edge.data.source)
        }
      }

      return elements.filter(item =>
        item.data.target
          ? visibleIds.has(item.data.source) && visibleIds.has(item.data.target)
          : visibleIds.has(item.data.id)
      )
    }

    const matchingNodes = nodes.filter(item => {
      const typeMatches =
        graphTypeFilter === 'all' || item.data.type === graphTypeFilter

      const searchMatches =
        !query ||
        String(item.data.label || '').toLowerCase().includes(query) ||
        String(item.data.type || '').toLowerCase().includes(query) ||
        JSON.stringify(item.data.properties || {}).toLowerCase().includes(query)

      return typeMatches && searchMatches
    })

    const visibleIds = new Set(matchingNodes.map(item => item.data.id))

    for (const edge of edges) {
      if (visibleIds.has(edge.data.source)) visibleIds.add(edge.data.target)
      if (visibleIds.has(edge.data.target)) visibleIds.add(edge.data.source)
    }

    return elements.filter(item =>
      item.data.target
        ? visibleIds.has(item.data.source) && visibleIds.has(item.data.target)
        : visibleIds.has(item.data.id)
    )
  }, [elements, graphView, graphTypeFilter, graphSearch, clusterOnly, selectedNodeId])


  useEffect(() => {
    if (activePage === 'Threat Graph' && cyRef.current) {
      cyRef.current.resize()
    }
  }, [activePage])

  useEffect(() => {
    async function loadDashboard() {
      setLoading(true)
      setError('')
      const results = await Promise.allSettled([
        api.get('/analytics/summary'),
        api.get('/analytics/risk-ranking'),
        api.get('/analytics/evaluation'),
        api.get('/analytics/otx-summary'),
        api.get('/analytics/real-world-evaluation')
      ])

      if (results[0].status === 'fulfilled') setSummary(results[0].value.data)
      if (results[1].status === 'fulfilled') {
        setRankings(results[1].value.data.risk_rankings || [])
      }
      if (results[2].status === 'fulfilled') setEvaluation(results[2].value.data)
      if (results[3].status === 'fulfilled') setOtxSummary(results[3].value.data)
      if (results[4].status === 'fulfilled') setRealWorldEvaluation(results[4].value.data)

      const failed = results.filter(result => result.status === 'rejected')
      if (failed.length) {
        setError(`${failed.length} dashboard service(s) could not be loaded. Check that the backend and Neo4j are running.`)
      }
      setLoading(false)
    }

    loadDashboard()
  }, [])

  useEffect(() => {
    if (activePage !== 'Threat Graph' || graph !== null || graphLoadStarted.current) return

    graphLoadStarted.current = true

    async function loadGraph() {
      setGraphLoading(true)
      setGraphError('')

      try {
        const response = await api.get('/graph')
        setGraph(response.data)
      } catch (err) {
        setGraphError(
          err.response?.data?.detail ||
          'The threat graph could not be loaded. Check that the backend and Neo4j are running.'
        )
        graphLoadStarted.current = false
      } finally {
        setGraphLoading(false)
      }
    }

    loadGraph()
  }, [activePage, graph, graphRetry])

  async function runInvestigation(event) {
    event.preventDefault()
    if (!indicator.trim()) return

    setSearching(true)
    setInvestigation(null)
    setError('')
    try {
      const response = await api.get('/investigate', {
        params: { indicator: indicator.trim(), hops: 2 }
      })
      setInvestigation(response.data)
    } catch (err) {
      setInvestigation({
        found: false,
        message: err.response?.data?.detail || 'The investigation request failed. Check the backend.'
      })
    } finally {
      setSearching(false)
    }
  }

  const entities = summary?.entities || []
  const entityTotal = summary?.total_nodes ?? graph?.total_entities ?? 0
  const relationshipTotal = summary?.total_relationships ?? graph?.total_relationships ?? 0
  const urlTotal = entities.find(item => item.entity_type === 'MaliciousURL')?.total ?? rankings.length
  const highRisk = rankings.filter(item => item.risk_level === 'High').length

  const navItems = [
    { name: 'Overview', icon: LayoutDashboard },
    { name: 'Threat Graph', icon: Network },
    { name: 'Investigation', icon: Search },
    { name: 'Risk Ranking', icon: ShieldAlert },
    { name: 'Evaluation', icon: BarChart3 }
  ]

  function navigate(page) {
    setActivePage(page)
    setSelectedNode(null)
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={23} /></div>
          <div>
            <strong>CYBERGRAPH</strong>
            <span>THREAT INTELLIGENCE</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="side-nav">
          {navItems.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={activePage === name ? 'nav-item active' : 'nav-item'}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
              {activePage === name && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-indicator">
            <span className="pulse-dot" />
            <div><strong>API CONNECTION</strong><small>Local backend</small></div>
          </div>
          <div className="sidebar-version">CYBERGRAPH · VERSION 1.0</div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> {activePage}</div>
          <div className="topbar-right">
            <span className="live-status"><span className="pulse-dot" /> SYSTEM MONITORING</span>
            <div className="avatar">CG</div>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">CYBER THREAT INTELLIGENCE PLATFORM</div>
              <h1>{activePage === 'Overview' ? 'Security Overview' : activePage}</h1>
              <p>Discover connections, investigate indicators, and analyze threat infrastructure.</p>
            </div>
            <button className="refresh-button" onClick={() => window.location.reload()}>
              <Activity size={16} /> Refresh data
            </button>
          </div>

          {error && <div className="error-banner"><AlertTriangle size={17} />{error}</div>}

          {loading ? (
            <div className="loading-state"><LoaderCircle className="spin" size={28} /> Loading threat intelligence...</div>
          ) : (
            <>
              {activePage === 'Overview' && (
                <>
                  <section className="metric-grid">
                    <MetricCard title="Total Entities" value={entityTotal} subtitle="Nodes in threat graph" icon={Database} />
                    <MetricCard title="Relationships" value={relationshipTotal} subtitle="Recorded graph connections" icon={GitBranch} tone="blue" />
                    <MetricCard title="Malicious URLs" value={urlTotal} subtitle="Indicators from collected data" icon={Globe} tone="purple" />
                    <MetricCard title="High Risk URLs" value={highRisk} subtitle="Heuristic risk classification" icon={AlertTriangle} tone="red" />
                  </section>

                  <section className="panel otx-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>AlienVault OTX Intelligence</h2>
                        <p>Threat pulses and indicators imported into the Neo4j graph</p>
                      </div>
                      <span className="graph-count">EXTERNAL THREAT SOURCE</span>
                    </div>
                    <div className="metric-grid">
                      <MetricCard title="OTX Pulses" value={otxSummary?.pulses ?? '—'} subtitle="Imported threat reports" icon={Activity} />
                      <MetricCard title="OTX Domains" value={otxSummary?.domains ?? '—'} subtitle="Domain indicators" icon={Globe} tone="purple" />
                      <MetricCard title="OTX IP Addresses" value={otxSummary?.ips ?? '—'} subtitle="IP indicators" icon={Wifi} tone="blue" />
                      <MetricCard title="OTX URLs" value={otxSummary?.urls ?? '—'} subtitle="URL indicators" icon={Bug} tone="red" />
                    </div>
                    <p className="disclaimer">
                      {otxSummary?.indicators ?? 0} distinct indicators connected through {otxSummary?.relationships ?? 0} OTX evidence relationships.
                    </p>
                  </section>
                  <section className="content-grid">
                    <div className="panel graph-panel">
                      <div className="panel-heading">
                        <div><h2>Threat Infrastructure Graph</h2><p>Connected indicators from your Neo4j database</p></div>
                        <button className="text-button" onClick={() => navigate('Threat Graph')}>Explore graph <span>→</span></button>
                      </div>
                      <div className="mini-graph">
                        <div
                          className="graph-preview-placeholder"
                          style={{
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '12px',
                            height: '320px',
                            textAlign: 'center'
                          }}
                        >
                          <Network size={34} />
                          <strong>Interactive graph loads when opened</strong>
                          <span>Open Threat Graph to explore all recorded entities and relationships.</span>
                        </div>
                      </div>
                      <div className="graph-legend">
                        <span><i className="legend-dot domain" /> Domains</span>
                        <span><i className="legend-dot ip" /> IP addresses</span>
                        <span><i className="legend-dot url" /> Malicious URLs</span>
                        <span><i className="legend-dot tag" /> Threat tags</span>
                    <span><i className="legend-dot otx" /> OTX threat pulses</span>
                      </div>
                    </div>

                    <div className="panel entity-panel">
                      <div className="panel-heading"><div><h2>Entity Distribution</h2><p>Records by entity type</p></div></div>
                      <div className="entity-list">
                        {entities.map(item => {
                          const percent = entityTotal ? (item.total / entityTotal) * 100 : 0
                          return (
                            <div className="entity-row" key={item.entity_type}>
                              <div className="entity-row-top"><span>{item.entity_type}</span><strong>{item.total}</strong></div>
                              <div className="progress-track"><div style={{ width: `${percent}%` }} /></div>
                            </div>
                          )
                        })}
                        {!entities.length && <p className="empty-state">No entity statistics available.</p>}
                      </div>
                    </div>
                  </section>

                  <section className="panel ranking-preview">
                    <div className="panel-heading">
                      <div><h2>Priority Threat Indicators</h2><p>Highest heuristic risk scores from URLhaus records</p></div>
                      <button className="text-button" onClick={() => navigate('Risk Ranking')}>View all <span>→</span></button>
                    </div>
                    <RiskTable rankings={rankings.slice(0, 5)} />
                  </section>
                </>
              )}

              {(
                <section
                  className="panel full-graph-panel"
                  style={{ display: activePage === 'Threat Graph' ? 'block' : 'none' }}
                >
                  <div className="panel-heading">
                    <div><h2>Interactive Relationship Map</h2><p>Select a node to inspect its properties. Drag, zoom, and pan to explore.</p></div>
                    <span className="graph-count">
                      {graphLoading ? 'LOADING GRAPH' : `${displayedElements.filter(item => item.data.target).length} connections`}
                    </span>
                  </div>
                  <div className="graph-explorer">
                    <div className="graph-mode-tabs">
                      <button
                        type="button"
                        className={graphView === 'complete' ? 'graph-mode-button active' : 'graph-mode-button'}
                        onClick={() => {
                          setGraphView('complete')
                          setClusterOnly(false)
                        }}
                      >
                        <Network size={15} /> Complete Network
                      </button>
                      <button
                        type="button"
                        className={graphView === 'explore' ? 'graph-mode-button active' : 'graph-mode-button'}
                        onClick={() => {
                          setGraphView('explore')
                          setClusterOnly(false)
                        }}
                      >
                        <Search size={15} /> Explore Connections
                      </button>
                    </div>

                    {graphView === 'explore' && (
                      <div className="graph-filter-bar">
                        <input
                          type="search"
                          value={graphSearch}
                          onChange={event => {
                            setGraphSearch(event.target.value)
                            setClusterOnly(false)
                          }}
                          onKeyDown={event => {
                            if (event.key === 'Escape') {
                              setGraphSearch('')
                              setClusterOnly(false)
                            }
                          }}
                          autoComplete="off"
                          spellCheck={false}
                          placeholder="Search a domain, IP, URL, malware, or threat actor..."
                          aria-label="Search graph entities"
                        />
                        <select
                          value={graphTypeFilter}
                          onChange={event => {
                            setGraphTypeFilter(event.target.value)
                            setClusterOnly(false)
                          }}
                          aria-label="Filter graph by entity type"
                        >
                          <option value="all">All entity types</option>
                          <option value="Domain">Domains</option>
                          <option value="IP">IP addresses</option>
                          <option value="MaliciousURL">Malicious URLs</option>
                          <option value="Malware">Malware</option>
                          <option value="ThreatActor">Threat actors</option>
                          <option value="ThreatPulse">OTX threat pulses</option>
                          <option value="ThreatTag">Threat tags</option>
                        </select>
                        <button
                          type="button"
                          className="graph-cluster-button"
                          onClick={() => {
                            if (!selectedNodeId) {
                              setClusterMessage('Select a node in the graph first, then explore its connected cluster.')
                              return
                            }
                            setClusterMessage('')
                            setClusterOnly(value => !value)
                          }}
                        >
                          {clusterOnly ? 'Show filtered results' : 'Explore selected cluster'}
                        </button>
                      </div>
                    )}
                    {clusterMessage && (
                      <p className="graph-result-summary">{clusterMessage}</p>
                    )}

                    <div className="graph-result-summary">
                      Showing {displayedElements.filter(item => !item.data.target).length.toLocaleString()} entities
                      and {displayedElements.filter(item => item.data.target).length.toLocaleString()} relationships
                      {clusterOnly ? ' · Two-hop connected cluster' : graphView === 'complete' ? ' · Complete network' : ' · Filtered exploration'}
                    </div>
                  </div>
                  <div className="full-graph">
                    {graphLoading ? (
                      <div className="loading-state">
                        <LoaderCircle className="spin" size={28} /> Loading graph data...
                      </div>
                    ) : graphError ? (
                      <div className="error-banner">
                        <AlertTriangle size={17} />
                        {graphError}
                        <button
                          className="text-button"
                          onClick={() => {
                            graphLoadStarted.current = false
                            setGraphError('')
                            setGraphRetry(value => value + 1)
                          }}
                        >
                          Retry
                        </button>
                      </div>
                    ) : graph ? (
                      <CytoscapeComponent
                        elements={displayedElements}
                        stylesheet={graphStyle}
                        layout={graphLayout}
                        hideEdgesOnViewport
                        textureOnViewport
                        motionBlur
                        style={{ width: '100%', height: '600px' }}
                        cy={cy => {
                          cy.off('tap', 'node')
                          cy.on('tap', 'node', event => {
                            const node = event.target
                            setSelectedNode(node.data())
                            setSelectedNodeId(node.id())
                            setClusterMessage('')
                          })
                        }}
                      />
                    ) : (
                      <div className="empty-state">No graph data is available.</div>
                    )}
                  </div>
                  <div className="graph-legend">
                    <span><i className="legend-dot domain" /> Domains</span>
                    <span><i className="legend-dot ip" /> IP addresses</span>
                    <span><i className="legend-dot url" /> Malicious URLs</span>
                    <span><i className="legend-dot tag" /> Threat tags</span>
                    <span><i className="legend-dot otx" /> OTX threat pulses</span>
                  </div>
                  {selectedNode && (
                    <div className="detail-panel">
                      <button className="close-detail" onClick={() => {
                        setSelectedNode(null)
                        setSelectedNodeId('')
                        setClusterOnly(false)
                        setClusterMessage('')
                      }}><X size={17} /></button>
                      <span className="eyebrow">SELECTED ENTITY · {selectedNode.type}</span>
                      <h3>{selectedNode.label}</h3>
                      <p>Source: {selectedNode.source}</p>
                      <pre>{JSON.stringify(selectedNode.properties, null, 2)}</pre>
                    </div>
                  )}
                </section>
              )}

              {activePage === 'Investigation' && (
                <section className="panel investigation-panel">
                  <div className="panel-heading">
                    <div><h2>Indicator Investigation</h2><p>Trace connected threat intelligence across two relationship hops.</p></div>
                    <Search size={22} className="muted-icon" />
                  </div>
                  <form className="investigation-form" onSubmit={runInvestigation}>
                    <label htmlFor="indicator">Domain, IP address, URL, or known indicator</label>
                    <div className="search-control">
                      <Search size={18} />
                      <input id="indicator" value={indicator} onChange={event => setIndicator(event.target.value)} placeholder="e.g. github.com or 192.0.2.10" />
                      <button type="submit" disabled={searching || !indicator.trim()}>
                        {searching ? <LoaderCircle className="spin" size={17} /> : 'Investigate'}
                      </button>
                    </div>
                  </form>
                  {investigation && (
                    <div className="investigation-result">
                      <div className="result-heading">
                        <div><span className="eyebrow">INVESTIGATION RESULT</span><h3>{investigation.found ? 'Indicator located' : 'No matching indicator found'}</h3></div>
                        <span className={investigation.found ? 'result-badge found' : 'result-badge not-found'}>{investigation.found ? 'FOUND' : 'NOT FOUND'}</span>
                      </div>
                      {investigation.message && <p>{investigation.message}</p>}
                      {investigation.evidence_note && <p className="evidence-note">{investigation.evidence_note}</p>}
                      {investigation.nodes?.length > 0 && (
                        <>
                          <h4>Connected entities ({investigation.nodes.length})</h4>
                          <div className="investigation-nodes">
                            {investigation.nodes.map((node, index) => (
                              <div className="investigation-node" key={node.id || node.identifier || index}>
                                <CircleDot size={16} />
                                <div><strong>{compactLabel(node.entity_type || node.type || '', node.identifier || node.value || node.name || node.label || 'Entity')}</strong><small>{node.entity_type || node.type || 'Connected entity'}</small></div>
                              </div>
                            ))}
                          </div>
                        </>
                      )}
                      {investigation.relationships?.length > 0 && (
                        <><h4>Supporting relationships ({investigation.relationships.length})</h4>
                          <div className="relationship-list">
                            {investigation.relationships.map((relation, index) => (
                              <div key={index}>{relation.relationship_type || relation.relationship || relation.type || 'RELATED_TO'} <span>·</span> {relationshipSummary(relation)}</div>
                            ))}
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </section>
              )}

              {activePage === 'Risk Ranking' && (
                <section className="panel ranking-panel">
                  <div className="panel-heading">
                    <div><h2>Risk-ranked URL Indicators</h2><p>Prioritization based on threat status, tags, and shared connections.</p></div>
                    <span className="graph-count">{rankings.length} indicators</span>
                  </div>
                  <RiskTable rankings={rankings} />
                  <p className="disclaimer"><AlertTriangle size={15} /> Risk scores are heuristic prioritization values, not probabilities or independently verified verdicts.</p>
                </section>
              )}

              {activePage === 'Evaluation' && (
                <>
                <section className="panel evaluation-panel">
                  <div className="panel-heading">
                    <div><h2>Model Evaluation</h2><p>Graph-based model compared with the rule-based baseline.</p></div>
                    <BarChart3 size={22} className="muted-icon" />
                  </div>
                  {evaluation ? (
                    <>
                      <div className="evaluation-source">
                        <span>DATASET</span><strong>{evaluation.dataset || 'Evaluation dataset'}</strong>
                        <span>TEST RECORDS</span><strong>{evaluation.testing_records ?? '—'}</strong>
                        <span>METHOD</span><strong>{evaluation.evaluation_type || 'Not specified'}</strong>
                      </div>
                      <div className="comparison-grid">
                        {[
                          ['Graph-based model', evaluation.models?.graph_based_model],
                          ['Rule-based baseline', evaluation.models?.rule_based_baseline]
                        ].map(([name, model]) => (
                          <div className="comparison-card" key={name}>
                            <h3>{name}</h3>
                            {['accuracy', 'precision', 'recall', 'f1_score'].map(metric => (
                              <div className="comparison-metric" key={metric}>
                                <span>{metric.replace('_', ' ')}</span>
                                <strong>{model?.[metric] == null ? '—' : `${(model[metric] * 100).toFixed(1)}%`}</strong>
                                <div className="progress-track"><div style={{ width: `${Math.min(100, (model?.[metric] || 0) * 100)}%` }} /></div>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                      {evaluation.feature_importance && (
                        <div className="feature-section">
                          <h3>Feature Importance</h3>
                          {Object.entries(evaluation.feature_importance).map(([name, value]) => (
                            <div className="entity-row" key={name}>
                              <div className="entity-row-top"><span>{name.replaceAll('_', ' ')}</span><strong>{(value * 100).toFixed(1)}%</strong></div>
                              <div className="progress-track"><div style={{ width: `${value * 100}%` }} /></div>
                            </div>
                          ))}
                        </div>
                      )}
                      {evaluation.limitations && <p className="disclaimer"><AlertTriangle size={15} /> {evaluation.limitations}</p>}
                    </>
                  ) : <p className="empty-state">Evaluation results are not available from the backend.</p>}
                </section>

                <section className="panel real-world-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Real-World URL Evaluation</h2>
                      <p>Independent classification experiment using the ISCX-URL2016 labelled dataset.</p>
                    </div>
                    <span className="graph-count">PUBLIC BENCHMARK DATASET</span>
                  </div>

                  {realWorldEvaluation ? (
                    <>
                      <div className="evaluation-source real-world-source">
                        <span>DATASET</span>
                        <strong>ISCX-URL2016</strong>
                        <span>RECORDS AFTER CLEANING</span>
                        <strong>{realWorldEvaluation.records_after_cleaning?.toLocaleString() ?? '—'}</strong>
                        <span>TEST RECORDS</span>
                        <strong>{realWorldEvaluation.testing_records?.toLocaleString() ?? '—'}</strong>
                        <span>FEATURES</span>
                        <strong>{realWorldEvaluation.feature_count ?? '—'}</strong>
                      </div>

                      <h3 className="real-world-subheading">Multiclass classification · five URL categories</h3>
                      <div className="comparison-grid">
                        {[
                          ['Random Forest', realWorldEvaluation.multiclass_results?.random_forest],
                          ['Decision Tree', realWorldEvaluation.multiclass_results?.decision_tree],
                          ['Majority Baseline', realWorldEvaluation.multiclass_results?.majority_baseline]
                        ].map(([name, model]) => (
                          <div className="comparison-card" key={name}>
                            <h3>{name}</h3>
                            {[
                              ['Accuracy', model?.accuracy],
                              ['Macro F1', model?.macro_f1],
                              ['Balanced accuracy', model?.balanced_accuracy]
                            ].map(([label, value]) => (
                              <div className="comparison-metric" key={label}>
                                <span>{label}</span>
                                <strong>{value == null ? '—' : `${(value * 100).toFixed(2)}%`}</strong>
                                <div className="progress-track">
                                  <div style={{ width: `${Math.min(100, (value || 0) * 100)}%` }} />
                                </div>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>

                      <h3 className="real-world-subheading">Binary classification · benign versus malicious</h3>
                      <div className="metric-grid real-world-metrics">
                        {[
                          ['Accuracy', realWorldEvaluation.binary_results?.random_forest?.accuracy],
                          ['Precision', realWorldEvaluation.binary_results?.random_forest?.precision],
                          ['Recall', realWorldEvaluation.binary_results?.random_forest?.recall],
                          ['F1-score', realWorldEvaluation.binary_results?.random_forest?.f1],
                          ['Specificity', realWorldEvaluation.binary_results?.random_forest?.specificity],
                          ['ROC-AUC', realWorldEvaluation.binary_results?.random_forest?.roc_auc]
                        ].map(([label, value]) => (
                          <div className="real-world-metric" key={label}>
                            <span>{label}</span>
                            <strong>{value == null ? '—' : `${(value * 100).toFixed(2)}%`}</strong>
                          </div>
                        ))}
                      </div>

                      <h3 className="real-world-subheading">Top Random Forest features</h3>
                      <div className="feature-section">
                        {(realWorldEvaluation.top_random_forest_features || []).slice(0, 10).map(item => (
                          <div className="entity-row" key={item.feature}>
                            <div className="entity-row-top">
                              <span>{item.feature}</span>
                              <strong>{(item.importance * 100).toFixed(2)}%</strong>
                            </div>
                            <div className="progress-track">
                              <div style={{ width: `${item.importance * 100}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="real-world-notice">
                        <strong>Methodology and limitations</strong>
                        <p>
                          This experiment evaluates classification using engineered URL features from a historical,
                          labelled dataset. It does not directly measure the accuracy of the Neo4j graph-based
                          investigation system. The dataset does not provide original URL or domain identifiers.
                          Results use a stratified random train/test split and should not be interpreted as current
                          threat prevalence or guaranteed performance on new data.
                        </p>
                        <p>
                          Original records: {realWorldEvaluation.original_records?.toLocaleString() ?? '—'}.
                          Training records: {realWorldEvaluation.training_records?.toLocaleString() ?? '—'}.
                          Repeated feature records removed: {realWorldEvaluation.duplicate_feature_records_removed?.toLocaleString() ?? '—'}.
                        </p>
                      </div>
                    </>
                  ) : (
                    <p className="empty-state">
                      Real-world evaluation results are unavailable. Run the ISCX-URL2016 evaluation script and restart the backend.
                    </p>
                  )}
                </section>
                </>
              )}
            </>
          )}

          <footer className="page-footer">
            <span>CYBERGRAPH · GRAPH-BASED CYBER THREAT INTELLIGENCE</span>
            <span><Wifi size={13} /> Local research environment</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

function RiskTable({ rankings }) {
  if (!rankings?.length) return <p className="empty-state">No risk ranking records are available.</p>

  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>INDICATOR</th><th>THREAT</th><th>STATUS</th><th>TAGS</th><th>RISK SCORE</th><th>LEVEL</th></tr></thead>
        <tbody>
          {rankings.map((item, index) => (
            <tr key={`${item.url}-${index}`}>
              <td className="url-cell" title={item.url}>{item.url}</td>
              <td>{item.threat || '—'}</td>
              <td><span className="status-text">{item.status || '—'}</span></td>
              <td><span className="tag-count">{item.tag_count ?? 0} tags</span></td>
              <td><strong className="score">{item.risk_score ?? '—'}</strong></td>
              <td><span className={`risk-badge ${(item.risk_level || 'low').toLowerCase()}`}>{item.risk_level || 'Unknown'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default App
