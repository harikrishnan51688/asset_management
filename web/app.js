let network = null;
let graphData = { nodes: [], edges: [] };
let allVisNodes = [];
let allVisEdges = [];
let activeCategory = 'all';

// Node Color Scheme & Icons
const NODE_STYLES = {
    ManagerAgent: { color: { background: '#00f2fe', border: '#38bdf8' }, shape: 'diamond', size: 30, icon: 'fa-shield-halved' },
    EndpointAgent: { color: { background: '#0284c7', border: '#38bdf8' }, shape: 'dot', size: 24, icon: 'fa-server' },
    Agent: { color: { background: '#0284c7', border: '#38bdf8' }, shape: 'dot', size: 24, icon: 'fa-server' },
    IPAddress: { color: { background: '#10b981', border: '#34d399' }, shape: 'hexagon', size: 18, icon: 'fa-network-wired' },
    OperatingSystem: { color: { background: '#3b82f6', border: '#60a5fa' }, shape: 'square', size: 20, icon: 'fa-brands fa-linux' },
    HardwareSpec: { color: { background: '#8b5cf6', border: '#a78bfa' }, shape: 'triangle', size: 18, icon: 'fa-microchip' },
    Vulnerability_Critical: { color: { background: '#ef4444', border: '#f87171' }, shape: 'star', size: 24, icon: 'fa-triangle-exclamation' },
    Vulnerability_High: { color: { background: '#f97316', border: '#fb923c' }, shape: 'triangleDown', size: 20, icon: 'fa-bug' },
    Vulnerability_Medium: { color: { background: '#eab308', border: '#facc15' }, shape: 'dot', size: 16, icon: 'fa-bug' },
    Vulnerability_Low: { color: { background: '#3b82f6', border: '#60a5fa' }, shape: 'dot', size: 14, icon: 'fa-bug' },
    SoftwarePackage: { color: { background: '#64748b', border: '#94a3b8' }, shape: 'box', size: 14, icon: 'fa-box' },
    NetworkPort: { color: { background: '#06b6d4', border: '#22d3ee' }, shape: 'ellipse', size: 14, icon: 'fa-plug' },
    AgentGroup: { color: { background: '#ec4899', border: '#f472b6' }, shape: 'ellipse', size: 16, icon: 'fa-users' }
};

document.addEventListener('DOMContentLoaded', () => {
    initEvents();
    loadGraphData();
});

function initEvents() {
    document.getElementById('refreshBtn').addEventListener('click', refreshData);
    document.getElementById('btnFitView').addEventListener('click', () => {
        if (network) network.fit({ animation: { duration: 500 } });
    });
    document.getElementById('btnTogglePhysics').addEventListener('click', togglePhysics);

    document.getElementById('searchInput').addEventListener('input', (e) => {
        filterGraph(e.target.value, activeCategory);
    });

    document.querySelectorAll('.category-pills .pill').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.category-pills .pill').forEach(p => p.classList.remove('active'));
            e.target.classList.add('active');
            activeCategory = e.target.getAttribute('data-cat');
            filterGraph(document.getElementById('searchInput').value, activeCategory);
        });
    });
}

async function loadGraphData() {
    try {
        const response = await fetch('/api/graph');
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        graphData = await response.json();
        renderDashboard(graphData);
    } catch (err) {
        console.warn("Could not fetch /api/graph, trying fallback asset_graph.json:", err);
        try {
            const fallbackRes = await fetch('../asset_graph.json');
            graphData = await fallbackRes.json();
            renderDashboard(graphData);
        } catch (e2) {
            console.error("Failed to load graph data:", e2);
        }
    }
}

async function refreshData() {
    const btn = document.getElementById('refreshBtn');
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Syncing...';
    btn.disabled = true;

    try {
        const res = await fetch('/api/refresh', { method: 'POST' });
        const data = await res.json();
        await loadGraphData();
    } catch (err) {
        console.error("Refresh failed:", err);
        await loadGraphData();
    } finally {
        btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Sync Wazuh API';
        btn.disabled = false;
    }
}

function renderDashboard(data) {
    updateMetrics(data);
    buildVisGraph(data);
}

function updateMetrics(data) {
    const nodes = data.nodes || [];
    const edges = data.edges || [];

    const agents = nodes.filter(n => n.type.includes('Agent'));
    const ips = nodes.filter(n => n.type === 'IPAddress');
    const vulns = nodes.filter(n => n.type === 'Vulnerability');

    document.getElementById('statAgentCount').textContent = agents.length;
    document.getElementById('statIpCount').textContent = ips.length;
    document.getElementById('statNodeCount').textContent = nodes.length;
    document.getElementById('statEdgeCount').textContent = edges.length;

    // Vulnerability Counts
    const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    vulns.forEach(v => {
        const s = v.properties.severity || 'Medium';
        if (sevCounts[s] !== undefined) sevCounts[s]++;
        else sevCounts['Medium']++;
    });

    const maxVuln = Math.max(...Object.values(sevCounts), 1);
    document.getElementById('countCritical').textContent = sevCounts.Critical;
    document.getElementById('countHigh').textContent = sevCounts.High;
    document.getElementById('countMedium').textContent = sevCounts.Medium;
    document.getElementById('countLow').textContent = sevCounts.Low;

    document.getElementById('barCritical').style.width = `${(sevCounts.Critical / maxVuln) * 100}%`;
    document.getElementById('barHigh').style.width = `${(sevCounts.High / maxVuln) * 100}%`;
    document.getElementById('barMedium').style.width = `${(sevCounts.Medium / maxVuln) * 100}%`;
    document.getElementById('barLow').style.width = `${(sevCounts.Low / maxVuln) * 100}%`;
}

function buildVisGraph(data) {
    const container = document.getElementById('networkGraph');

    allVisNodes = (data.nodes || []).map(node => {
        let styleKey = node.type;
        if (node.type === 'Vulnerability') {
            const sev = node.properties.severity || 'Medium';
            styleKey = `Vulnerability_${sev}`;
        }
        const style = NODE_STYLES[styleKey] || NODE_STYLES.SoftwarePackage;

        return {
            id: node.id,
            label: node.label,
            shape: style.shape,
            size: style.size,
            color: {
                background: style.color.background,
                border: style.color.border,
                highlight: { background: '#ffffff', border: style.color.background }
            },
            font: { color: '#f3f4f6', face: 'Outfit', size: 12 },
            borderWidth: 2,
            shadow: true,
            rawNode: node
        };
    });

    allVisEdges = (data.edges || []).map(edge => ({
        from: edge.source,
        to: edge.target,
        label: edge.label || edge.relationship,
        color: { color: 'rgba(255, 255, 255, 0.15)', highlight: '#00f2fe' },
        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
        font: { color: '#9ca3af', size: 9, align: 'middle', strokeWidth: 0 }
    }));

    const visData = {
        nodes: new vis.DataSet(allVisNodes),
        edges: new vis.DataSet(allVisEdges)
    };

    const options = {
        nodes: {
            shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 10 }
        },
        edges: {
            smooth: { type: 'continuous' }
        },
        physics: {
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -35,
                centralGravity: 0.005,
                springLength: 90,
                springConstant: 0.18
            },
            maxVelocity: 50,
            timestep: 0.35,
            stabilization: { iterations: 150 }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            zoomView: true
        }
    };

    network = new vis.Network(container, visData, options);

    // Node click event
    network.on('click', params => {
        if (params.nodes.length > 0) {
            const selectedId = params.nodes[0];
            const foundNode = data.nodes.find(n => n.id === selectedId);
            if (foundNode) {
                renderNodeInspector(foundNode);
            }
        }
    });
}

function renderNodeInspector(node) {
    const container = document.getElementById('inspectorContent');
    const props = node.properties || {};

    let propsRows = '';
    for (const [key, val] of Object.entries(props)) {
        if (val) {
            propsRows += `
                <tr>
                    <td class="props-key">${key.replace(/_/g, ' ')}</td>
                    <td class="props-val">${val}</td>
                </tr>
            `;
        }
    }

    container.innerHTML = `
        <div class="node-card">
            <div class="node-card-header">
                <div>
                    <h3 class="node-title">${node.label}</h3>
                    <span class="node-type-badge">${node.type}</span>
                </div>
            </div>

            <table class="props-table">
                <tbody>
                    ${propsRows || '<tr><td colspan="2">No detailed metadata available.</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

function filterGraph(searchQuery, category) {
    if (!network) return;
    const q = (searchQuery || '').toLowerCase().strip ? searchQuery.toLowerCase().strip() : searchQuery.toLowerCase();

    const filteredNodes = allVisNodes.filter(node => {
        const matchesCategory = (category === 'all') || (node.rawNode.category === category);
        const matchesSearch = !q || node.label.toLowerCase().includes(q) || JSON.stringify(node.rawNode.properties).toLowerCase().includes(q);
        return matchesCategory && matchesSearch;
    });

    const activeNodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = allVisEdges.filter(e => activeNodeIds.has(e.from) && activeNodeIds.has(e.to));

    network.setData({
        nodes: new vis.DataSet(filteredNodes),
        edges: new vis.DataSet(filteredEdges)
    });
}

let physicsEnabled = true;
function togglePhysics() {
    if (!network) return;
    physicsEnabled = !physicsEnabled;
    network.setOptions({ physics: { enabled: physicsEnabled } });
    const btn = document.getElementById('btnTogglePhysics');
    btn.style.color = physicsEnabled ? 'var(--accent-cyan)' : 'var(--text-dim)';
}
