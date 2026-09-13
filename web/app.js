let network = null;
let graphData = { nodes: [], edges: [] };
let allVisNodes = [];
let allVisEdges = [];
let activeCategory = 'all';

// Node Color Scheme & Icons
const NODE_STYLES = {
    ManagerAgent: { color: { background: '#2563eb', border: '#1d4ed8' }, shape: 'diamond', size: 28, icon: 'fa-shield-halved' },
    EndpointAgent: { color: { background: '#0284c7', border: '#0369a1' }, shape: 'dot', size: 22, icon: 'fa-server' },
    Agent: { color: { background: '#0284c7', border: '#0369a1' }, shape: 'dot', size: 22, icon: 'fa-server' },
    Workstation: { color: { background: '#0891b2', border: '#0e7490' }, shape: 'dot', size: 22, icon: 'fa-desktop' },
    Server: { color: { background: '#4f46e5', border: '#4338ca' }, shape: 'diamond', size: 26, icon: 'fa-server' },
    Device: { color: { background: '#0284c7', border: '#0369a1' }, shape: 'dot', size: 20, icon: 'fa-laptop' },
    IPAddress: { color: { background: '#059669', border: '#047857' }, shape: 'hexagon', size: 18, icon: 'fa-network-wired' },
    OperatingSystem: { color: { background: '#475569', border: '#334155' }, shape: 'square', size: 20, icon: 'fa-brands fa-linux' },
    HardwareSpec: { color: { background: '#7c3aed', border: '#6d28d9' }, shape: 'triangle', size: 18, icon: 'fa-microchip' },
    NetworkPort: { color: { background: '#0d9488', border: '#0f766e' }, shape: 'ellipse', size: 14, icon: 'fa-plug' },
    AgentGroup: { color: { background: '#db2777', border: '#be185d' }, shape: 'ellipse', size: 16, icon: 'fa-users' }
};

document.addEventListener('DOMContentLoaded', () => {
    initEvents();
    loadGraphData();
});

function initEvents() {
    document.getElementById('refreshBtn').addEventListener('click', refreshData);

    const csvFileInput = document.getElementById('csvFileInput');
    if (csvFileInput) {
        csvFileInput.addEventListener('change', handleCsvUpload);
    }


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

function handleCsvUpload(e) {
    const file = e.target.files && e.target.files[0];
    if (file) {
        processCsvFile(file);
    }
    e.target.value = '';
}

async function processCsvFile(file) {
    if (!file) return;

    const btn = document.getElementById('importCsvBtn');
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Importing...';
        btn.style.pointerEvents = 'none';
    }

    try {
        const text = await file.text();
        const res = await fetch('/api/import/csv', {
            method: 'POST',
            headers: { 'Content-Type': 'text/csv' },
            body: text
        });
        const result = await res.json();
        if (res.ok && result.status === 'success') {
            alert(`✅ Successfully imported ${result.imported_nodes} nodes and ${result.imported_relationships} relationships from CSV!`);
            await loadGraphData();
        } else {
            alert(`❌ CSV Import error: ${result.message || 'Unknown error'}`);
        }
    } catch (err) {
        console.error('CSV import failed:', err);
        alert(`❌ Failed to import CSV: ${err.message}`);
    } finally {
        if (btn) {
            btn.innerHTML = originalText;
            btn.style.pointerEvents = 'auto';
        }
    }
}


function renderDashboard(data) {
    updateMetrics(data);

    buildVisGraph(data);
}

function updateMetrics(data) {
    const nodes = data.nodes || [];
    const edges = data.edges || [];

    const agents = nodes.filter(n => n.type && (n.type.includes('Agent') || ['Workstation', 'Server', 'Device'].includes(n.type)));
    const ips = nodes.filter(n => n.type === 'IPAddress');

    document.getElementById('statAgentCount').textContent = agents.length;
    document.getElementById('statIpCount').textContent = ips.length;
    document.getElementById('statNodeCount').textContent = nodes.length;
    document.getElementById('statEdgeCount').textContent = edges.length;
}

function buildVisGraph(data) {
    const container = document.getElementById('networkGraph');

    allVisNodes = (data.nodes || []).map(node => {
        const style = NODE_STYLES[node.type] || NODE_STYLES.EndpointAgent;

        return {
            id: node.id,
            label: node.label,
            shape: style.shape,
            size: style.size,
            color: {
                background: style.color.background,
                border: style.color.border,
                highlight: { background: style.color.background, border: '#0f172a' }
            },
            font: {
                color: '#0f172a',
                face: 'Inter, -apple-system, sans-serif',
                size: 11,
                strokeWidth: 3,
                strokeColor: '#ffffff'
            },
            borderWidth: 1.5,
            shadow: {
                enabled: true,
                color: 'rgba(0, 0, 0, 0.08)',
                size: 6,
                x: 1,
                y: 2
            },
            rawNode: node
        };
    });

    allVisEdges = (data.edges || []).map(edge => ({
        from: edge.source,
        to: edge.target,
        label: edge.label || edge.relationship,
        color: { color: '#cbd5e1', highlight: '#2563eb', hover: '#3b82f6' },
        arrows: { to: { enabled: true, scaleFactor: 0.6 } },
        font: {
            color: '#64748b',
            face: 'Inter, -apple-system, sans-serif',
            size: 9,
            align: 'middle',
            strokeWidth: 2,
            strokeColor: '#ffffff'
        }
    }));

    const visData = {
        nodes: new vis.DataSet(allVisNodes),
        edges: new vis.DataSet(allVisEdges)
    };

    const options = {
        nodes: {
            shadow: { enabled: true, color: 'rgba(0, 0, 0, 0.08)', size: 6, x: 1, y: 2 }
        },
        edges: {
            smooth: { type: 'continuous' },
            hoverWidth: 1.5
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
    const q = (searchQuery || '').trim().toLowerCase();

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
    btn.style.color = physicsEnabled ? 'var(--primary)' : 'var(--text-dim)';
}
