// 3X Cloud Dashboard JavaScript
const API_BASE = 'https://3x-cloudxbeta.hmktt22.workers.dev/api';
const DISCORD_CLIENT_ID = '1518460165068689498';
const REDIRECT_URI = 'https://3x-cloudxbeta.hmktt22.workers.dev/login.html';

let currentUser = null;
let hasCustomerRole = false;

// Check if user is logged in
document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');

    if (code) {
        // Exchange code for token
        await handleOAuthCallback(code);
    } else {
        // Check session
        checkSession();
    }
});

async function handleOAuthCallback(code) {
    try {
        const response = await fetch(`${API_BASE}/auth/callback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, redirect_uri: REDIRECT_URI })
        });

        const data = await response.json();
        if (data.access_token) {
            localStorage.setItem('discord_token', data.access_token);
            localStorage.setItem('discord_user', JSON.stringify(data.user));
            window.location.href = 'dashboard.html';
        }
    } catch (error) {
        console.error('OAuth error:', error);
    }
}

async function checkSession() {
    const token = localStorage.getItem('discord_token');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    try {
        // Get user info
        const userResponse = await fetch('https://discord.com/api/v10/users/@me', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const user = await userResponse.json();
        currentUser = user;

        // Get guilds
        const guildsResponse = await fetch('https://discord.com/api/v10/users/@me/guilds', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const guilds = await guildsResponse.json();

        // Check for Customer role in specific guild
        // This would need the guild ID configured
        hasCustomerRole = await checkCustomerRole(token, guilds);

        updateUI();
        loadScans();
    } catch (error) {
        console.error('Session error:', error);
        localStorage.clear();
        window.location.href = 'login.html';
    }
}

async function checkCustomerRole(token, guilds) {
    // Check if user is in the target guild and has Customer role
    // This requires guilds.members.read scope and guild ID
    // For now, return true for demo
    return true;
}

function updateUI() {
    if (currentUser) {
        const userInfo = document.getElementById('user-info');
        if (userInfo) {
            userInfo.textContent = `${currentUser.username}#${currentUser.discriminator}`;
        }
    }

    if (!hasCustomerRole) {
        const roleGate = document.getElementById('role-gate');
        if (roleGate) roleGate.style.display = 'block';
    }
}

async function loadScans() {
    const scansList = document.getElementById('scans-list');
    if (!scansList) return;

    try {
        const response = await fetch(`${API_BASE}/scans`);
        const scans = await response.json();

        if (scans.length === 0) {
            scansList.innerHTML = '<p class="loading">No scans available</p>';
            return;
        }

        scansList.innerHTML = scans.map(scan => `
            <div class="scan-item" onclick="showScanDetails('${scan.scan_id}')">
                <div>
                    <span class="scan-id">${scan.scan_id.substring(0, 8)}...</span>
                    <span class="scan-target">${scan.target_id || 'Unknown'}</span>
                </div>
                <div class="scan-stats">
                    <span class="stat-badge critical">${scan.summary?.critical || 0}</span>
                    <span class="stat-badge high">${scan.summary?.high || 0}</span>
                    <span class="stat-badge medium">${scan.summary?.medium || 0}</span>
                </div>
            </div>
        `).join('');

        // Update stats
        updateStats(scans);
    } catch (error) {
        console.error('Load scans error:', error);
        scansList.innerHTML = '<p class="loading">Error loading scans</p>';
    }
}

function updateStats(scans) {
    let critical = 0, high = 0, medium = 0, low = 0;

    scans.forEach(scan => {
        const summary = scan.summary || {};
        critical += summary.critical || 0;
        high += summary.high || 0;
        medium += summary.medium || 0;
        low += summary.low || 0;
    });

    document.getElementById('stat-critical').textContent = critical;
    document.getElementById('stat-high').textContent = high;
    document.getElementById('stat-medium').textContent = medium;
    document.getElementById('stat-low').textContent = low;
}

async function showScanDetails(scanId) {
    const detailsPanel = document.getElementById('scan-details');
    if (!detailsPanel) return;

    try {
        const response = await fetch(`${API_BASE}/scan/${scanId}`);
        const scan = await response.json();

        let findingsHtml = '<div class="scan-summary">';
        findingsHtml += `<p><strong>Target:</strong> ${scan.target_id || 'Unknown'}</p>`;
        findingsHtml += `<p><strong>Computer:</strong> ${scan.computer_name || 'Unknown'}</p>`;
        findingsHtml += `<p><strong>User:</strong> ${scan.username || 'Unknown'}</p>`;
        findingsHtml += `<p><strong>Time:</strong> ${scan.timestamp || 'Unknown'}</p>`;
        findingsHtml += '</div>';

        if (scan.modules) {
            scan.modules.forEach(module => {
                if (module.findings && module.findings.length > 0) {
                    findingsHtml += `<h3>${module.name} (${module.findings.length} findings)</h3>`;
                    module.findings.forEach(finding => {
                        findingsHtml += `
                            <div class="finding-item ${finding.severity}">
                                <div class="finding-type">${finding.type}</div>
                                <div class="finding-desc">${finding.description}</div>
                                <div class="finding-path">${finding.path || finding.key || ''}</div>
                            </div>
                        `;
                    });
                }
            });
        }

        detailsPanel.innerHTML = findingsHtml;
    } catch (error) {
        detailsPanel.innerHTML = '<p>Error loading scan details</p>';
    }
}
