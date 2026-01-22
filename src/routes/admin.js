const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config');
const storage = require('../services/storage');
const { sendJson, sendHtml } = require('../utils/response');

// Head cache directory for prerender queue check
const HEAD_CACHE_DIR = config.headCacheDir;

/**
 * Admin login endpoint
 */
async function handleAdminLogin(req, res, body) {
  const { password } = body;

  if (!password) {
    sendJson(res, 400, { error: 'Password required' });
    return;
  }

  if (password !== config.adminPassword) {
    sendJson(res, 401, { error: 'Invalid password' });
    return;
  }

  const token = crypto.randomBytes(32).toString('hex');
  const success = await storage.createAdminToken(token);

  if (!success) {
    sendJson(res, 500, { error: 'Failed to create session' });
    return;
  }

  console.log(`Admin login successful, token: ${token.substring(0, 8)}...`);
  sendJson(res, 200, { token });
}

/**
 * Admin verify endpoint
 */
async function handleAdminVerify(req, res, token) {
  if (!token) {
    sendJson(res, 401, { valid: false });
    return;
  }
  const valid = await storage.verifyAdminToken(token);
  sendJson(res, valid ? 200 : 401, { valid });
}

/**
 * Active sessions API
 */
async function handleActiveSessions(req, res) {
  const data = await storage.getAllActiveSessions();
  sendJson(res, 200, data);
}

/**
 * Admin stats API (lightweight summary) - matches server.js format
 */
async function handleAdminStats(req, res) {
  const keyCounts = await storage.getKeyCounts();
  const redisConnected = storage.isRedisConnected();

  sendJson(res, 200, {
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: { connected: redisConnected },
    keys: keyCounts,
    activeSessions: keyCounts.sessions,
    activeServers: keyCounts.servers,
    activePlayers: keyCounts.activePlayers || 0,
    timestamp: new Date().toISOString()
  });
}

/**
 * Admin servers API (paginated server list with players)
 */
async function handleAdminServers(req, res, url) {
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 10, 50);

  const result = await storage.getPaginatedServers(page, limit);
  sendJson(res, 200, result);
}

/**
 * Search players by username or UUID (server-side)
 */
async function handlePlayerSearch(req, res, url) {
  const query = url.searchParams.get('q') || '';
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);

  if (!query || query.length < 2) {
    sendJson(res, 200, { results: [], query: '' });
    return;
  }

  const results = await storage.searchPlayers(query, limit);
  sendJson(res, 200, { results, query });
}

/**
 * Get prerender queue stats (optimized - counts only, no UUID list)
 */
async function handlePrerenderQueue(req, res) {
  // Count total cached files on disk
  let totalCachedFiles = 0;
  try {
    if (fs.existsSync(HEAD_CACHE_DIR)) {
      const files = fs.readdirSync(HEAD_CACHE_DIR);
      totalCachedFiles = files.filter(f => f.endsWith('.png')).length;
    }
  } catch (e) {
    // Ignore errors reading cache dir
  }

  if (!storage.isRedisConnected()) {
    sendJson(res, 200, { totalCachedFiles, totalPlayers: 0, error: 'Redis not connected' });
    return;
  }

  try {
    // Just get player count from stats (fast)
    const keyCounts = await storage.getKeyCounts();
    const uncached = Math.max(0, keyCounts.activePlayers - totalCachedFiles);

    sendJson(res, 200, {
      total: keyCounts.activePlayers,
      totalPlayers: keyCounts.activePlayers,
      cached: totalCachedFiles,
      totalCachedFiles,
      uncached  // Dashboard expects this field name
    });
  } catch (e) {
    console.error('Error getting prerender queue:', e.message);
    sendJson(res, 500, { error: e.message });
  }
}

/**
 * Admin dashboard HTML page - full featured version from server.js
 */
function handleAdminDashboard(req, res) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hytale Auth Server - Admin Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #e0e0e0;
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 {
      text-align: center;
      color: #00d4ff;
      margin-bottom: 30px;
      font-size: 2.5em;
      text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .stat-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }
    .stat-value {
      font-size: 3em;
      font-weight: bold;
      color: #00d4ff;
      text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
    }
    .stat-label { color: #888; margin-top: 5px; font-size: 0.9em; }
    .section {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .section h2 {
      color: #00d4ff;
      margin-bottom: 15px;
      font-size: 1.3em;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding-bottom: 10px;
    }
    .server-card {
      background: rgba(0, 212, 255, 0.1);
      border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 15px;
    }
    .server-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .server-name {
      font-weight: bold;
      color: #00d4ff;
      font-size: 1.1em;
    }
    .server-audience {
      font-family: monospace;
      font-size: 0.75em;
      color: #888;
      margin-top: 2px;
      margin-bottom: 8px;
    }
    .player-count {
      background: #00d4ff;
      color: #1a1a2e;
      padding: 3px 10px;
      border-radius: 20px;
      font-weight: bold;
      font-size: 0.85em;
    }
    .players-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    .player-tag {
      background: rgba(255, 255, 255, 0.1);
      padding: 6px 12px;
      border-radius: 15px;
      font-size: 0.85em;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 8px;
    }
    .player-tag .player-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      flex-shrink: 0;
      overflow: hidden;
      border: none;
    }
    .player-tag .player-avatar-img {
      width: 40px;
      height: 40px;
      border-radius: 50%;
    }
    .player-tag .player-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .player-tag .player-name {
      color: #fff;
      font-weight: 500;
    }
    .player-tag .uuid {
      color: #666;
      font-size: 0.7em;
      font-family: monospace;
    }
    .status-dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 8px;
    }
    .status-dot.online { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
    .status-dot.offline { background: #ff4444; }
    .ttl-badge {
      font-size: 0.7em;
      padding: 2px 6px;
      border-radius: 10px;
      margin-left: 5px;
      font-weight: normal;
    }
    .ttl-fresh { background: rgba(0, 255, 136, 0.25); color: #7fdfb0; }
    .ttl-warning { background: rgba(255, 170, 0, 0.25); color: #d4a852; }
    .ttl-critical { background: rgba(255, 68, 68, 0.25); color: #e08080; }
    .player-ttl {
      font-size: 0.65em;
      color: #888;
      margin-top: 2px;
    }
    .server-ttl {
      font-size: 0.8em;
      margin-left: 10px;
    }
    .pagination {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 15px;
      margin-top: 20px;
      padding: 15px;
    }
    .pagination button {
      background: rgba(0, 212, 255, 0.2);
      border: 1px solid rgba(0, 212, 255, 0.3);
      color: #00d4ff;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .pagination button:hover:not(:disabled) {
      background: rgba(0, 212, 255, 0.3);
    }
    .pagination button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    .pagination span {
      color: #888;
      font-size: 0.9em;
    }
    .launcher-stat {
      background: rgba(138, 43, 226, 0.1);
      border-color: rgba(138, 43, 226, 0.3);
    }
    .launcher-stat .stat-value {
      color: #b388ff;
    }
    .refresh-btn {
      background: linear-gradient(135deg, #00d4ff, #0099cc);
      border: none;
      color: #fff;
      padding: 12px 30px;
      border-radius: 25px;
      cursor: pointer;
      font-size: 1em;
      font-weight: bold;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .refresh-btn:hover {
      transform: scale(1.05);
      box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
    }
    .refresh-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .last-update { color: #666; font-size: 0.85em; margin-top: 10px; }
    .no-data { color: #666; font-style: italic; padding: 20px; text-align: center; }
    .redis-status {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    /* Login styles */
    .login-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.9);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    .login-box {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border: 1px solid rgba(0, 212, 255, 0.3);
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      max-width: 400px;
      width: 90%;
    }
    .login-box h2 {
      color: #00d4ff;
      margin-bottom: 20px;
    }
    .login-box input {
      width: 100%;
      padding: 12px;
      border-radius: 5px;
      border: 1px solid #333;
      background: #0d0d1a;
      color: #fff;
      margin-bottom: 15px;
      font-size: 1em;
    }
    .login-box button {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #00d4ff, #0099cc);
      border: none;
      border-radius: 5px;
      color: #fff;
      font-size: 1em;
      font-weight: bold;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .login-box button:hover {
      transform: scale(1.02);
    }
    .login-error {
      color: #ff6b6b;
      margin-top: 10px;
      font-size: 0.9em;
    }
    .logout-btn {
      position: fixed;
      top: 20px;
      right: 20px;
      background: rgba(255, 100, 100, 0.2);
      border: 1px solid rgba(255, 100, 100, 0.3);
      color: #ff6b6b;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 0.85em;
      z-index: 100;
    }
    .logout-btn:hover {
      background: rgba(255, 100, 100, 0.3);
    }
    .hidden { display: none !important; }
    .search-result {
      background: rgba(0, 212, 255, 0.1);
      border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 10px;
    }
    .search-result .player-info-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .search-result .player-avatar-large {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      overflow: hidden;
      border: none;
    }
    .search-result .player-details h3 {
      margin: 0;
      color: #00d4ff;
      font-size: 1.1em;
    }
    .search-result .player-details .uuid-full {
      color: #888;
      font-size: 0.8em;
      font-family: monospace;
    }
    .search-result .server-list {
      margin-top: 10px;
      padding-left: 15px;
    }
    .search-result .server-item {
      color: #aaa;
      font-size: 0.9em;
      margin: 5px 0;
    }
    .search-result .server-item .server-link {
      color: #00d4ff;
      cursor: pointer;
      text-decoration: underline;
    }
    .search-no-results {
      color: #888;
      font-style: italic;
      text-align: center;
      padding: 20px;
    }
    .search-loading {
      color: #00d4ff;
      text-align: center;
      padding: 15px;
    }
    .highlight {
      background: rgba(0, 212, 255, 0.3);
      border-color: rgba(0, 212, 255, 0.5);
    }
  </style>
</head>
<body>
  <!-- Login Overlay -->
  <div class="login-overlay" id="loginOverlay">
    <div class="login-box">
      <h2>Admin Login</h2>
      <form id="loginForm">
        <input type="password" id="loginPassword" placeholder="Enter admin password" autocomplete="current-password" required>
        <button type="submit">Login</button>
      </form>
      <div class="login-error" id="loginError"></div>
    </div>
  </div>

  <button class="logout-btn hidden" id="logoutBtn" onclick="logout()">Logout</button>

  <div class="container hidden" id="mainContent">
    <h1>Hytale Auth Server</h1>

    <div class="stats-grid">
      <div class="stat-card launcher-stat">
        <div class="stat-value" id="launcherOnline">-</div>
        <div class="stat-label">Launcher Online</div>
      </div>
      <div class="stat-card launcher-stat">
        <div class="stat-value" id="launcherPeak">-</div>
        <div class="stat-label">Launcher Peak</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="playerCount">-</div>
        <div class="stat-label">Active Players</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="serverCount">-</div>
        <div class="stat-label">Active Servers</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="sessionCount">-</div>
        <div class="stat-label">Total Sessions</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="userCount">-</div>
        <div class="stat-label">Registered Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="prerenderCached">-</div>
        <div class="stat-label">Heads Cached</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="prerenderQueue">-</div>
        <div class="stat-label">Prerender Queue</div>
      </div>
    </div>

    <div class="section">
      <h2><span class="status-dot" id="redisStatus"></span>Redis Status</h2>
      <div id="redisInfo">Loading...</div>
    </div>

    <div class="section">
      <h2>Player Search</h2>
      <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 15px;">
        <input type="text" id="playerSearch" placeholder="Search by username or UUID..." style="flex: 1; padding: 10px; border-radius: 5px; border: 1px solid #333; background: #1a1a2e; color: #fff; font-size: 1em;">
        <button class="refresh-btn" style="padding: 10px 20px;" onclick="clearSearch()">Clear</button>
      </div>
      <div id="searchResults" class="hidden"></div>
    </div>

    <div class="section">
      <h2>Active Servers</h2>
      <div id="serversList">Loading...</div>
    </div>

    <div style="text-align: center; margin-top: 20px;">
      <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
      <div class="last-update">Last update: <span id="lastUpdate">-</span></div>
    </div>
  </div>

  <script>
    let currentPage = 1;
    const pageLimit = 10;
    let adminToken = localStorage.getItem('adminToken');
    let savedPassword = localStorage.getItem('adminPassword');

    // Auth helper - adds token to fetch requests
    async function authFetch(url, options = {}) {
      if (!adminToken) throw new Error('Not authenticated');
      options.headers = options.headers || {};
      options.headers['X-Admin-Token'] = adminToken;
      const res = await fetch(url, options);
      if (res.status === 401) {
        // Token invalid, try auto-login with saved password
        if (savedPassword && await tryAutoLogin()) {
          // Retry the request with new token
          options.headers['X-Admin-Token'] = adminToken;
          return fetch(url, options);
        }
        logout();
        throw new Error('Session expired');
      }
      return res;
    }

    // Try to login with saved password
    async function tryAutoLogin() {
      if (!savedPassword) return false;
      try {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: savedPassword })
        });
        const data = await res.json();
        if (res.ok && data.token) {
          adminToken = data.token;
          localStorage.setItem('adminToken', adminToken);
          return true;
        }
      } catch (e) {}
      return false;
    }

    // Check if we're authenticated
    async function checkAuth() {
      if (!adminToken) {
        // Try auto-login with saved password
        if (savedPassword) {
          return await tryAutoLogin();
        }
        return false;
      }
      try {
        const res = await fetch('/admin/verify', {
          headers: { 'X-Admin-Token': adminToken }
        });
        const data = await res.json();
        if (data.valid === true) return true;
        // Token invalid, try auto-login
        if (savedPassword) {
          return await tryAutoLogin();
        }
        return false;
      } catch (e) {
        return false;
      }
    }

    // Login handler
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('loginPassword').value;
      const rememberMe = document.getElementById('rememberMe')?.checked ?? true;
      const errorDiv = document.getElementById('loginError');
      errorDiv.textContent = '';

      try {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();

        if (res.ok && data.token) {
          adminToken = data.token;
          localStorage.setItem('adminToken', adminToken);
          if (rememberMe) {
            savedPassword = password;
            localStorage.setItem('adminPassword', password);
          }
          showDashboard();
        } else {
          errorDiv.textContent = data.error || 'Login failed';
        }
      } catch (e) {
        errorDiv.textContent = 'Connection error';
      }
    });

    // Logout handler
    function logout() {
      adminToken = null;
      savedPassword = null;
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminPassword');
      document.getElementById('loginOverlay').classList.remove('hidden');
      document.getElementById('mainContent').classList.add('hidden');
      document.getElementById('logoutBtn').classList.add('hidden');
      document.getElementById('loginPassword').value = '';
    }

    // Show dashboard after login
    function showDashboard() {
      document.getElementById('loginOverlay').classList.add('hidden');
      document.getElementById('mainContent').classList.remove('hidden');
      document.getElementById('logoutBtn').classList.remove('hidden');
      refreshData();
    }

    // Initialize - check auth on page load
    (async () => {
      if (await checkAuth()) {
        showDashboard();
      } else {
        adminToken = null;
        localStorage.removeItem('adminToken');
      }
    })();

    // Helper function to get TTL status class and text
    function getTtlStatus(ttlSeconds) {
      const hours = ttlSeconds / 3600;
      if (hours > 5) return { class: 'ttl-fresh', text: Math.round(hours) + 'h' };
      if (hours > 1) return { class: 'ttl-warning', text: Math.round(hours * 10) / 10 + 'h' };
      if (ttlSeconds > 60) return { class: 'ttl-critical', text: Math.round(ttlSeconds / 60) + 'm' };
      return { class: 'ttl-critical', text: ttlSeconds + 's' };
    }

    async function refreshData() {
      const btn = document.querySelector('.refresh-btn');
      btn.disabled = true;
      btn.textContent = 'Loading...';

      try {
        // Fetch launcher stats
        try {
          const launcherRes = await fetch('https://api.hytalef2p.com/api/players/stats');
          const launcher = await launcherRes.json();
          document.getElementById('launcherOnline').textContent = launcher.online || 0;
          document.getElementById('launcherPeak').textContent = launcher.peak || 0;
        } catch (e) {
          document.getElementById('launcherOnline').textContent = '?';
          document.getElementById('launcherPeak').textContent = '?';
        }

        // Fetch stats (lightweight)
        const statsRes = await authFetch('/admin/stats');
        const stats = await statsRes.json();

        // Update stats
        document.getElementById('playerCount').textContent = stats.activePlayers || 0;
        document.getElementById('serverCount').textContent = stats.activeServers || 0;
        document.getElementById('sessionCount').textContent = stats.activeSessions || 0;
        document.getElementById('userCount').textContent = stats.keys?.users || 0;
        // Update Redis status
        const redisStatus = document.getElementById('redisStatus');
        const redisInfo = document.getElementById('redisInfo');
        if (stats.redis?.connected) {
          redisStatus.className = 'status-dot online';
          redisInfo.innerHTML = \`
            <div class="redis-status">
              <strong>Connected</strong> |
              Sessions: \${stats.keys?.sessions || 0} |
              Auth Grants: \${stats.keys?.authGrants || 0} |
              Users: \${stats.keys?.users || 0}
            </div>
          \`;
        } else {
          redisStatus.className = 'status-dot offline';
          redisInfo.textContent = 'Not connected - data will not persist!';
        }

        // Fetch servers (paginated)
        await loadServers(currentPage);

        // Fetch prerender queue stats
        try {
          const prerenderRes = await authFetch('/admin/prerender-queue');
          const prerender = await prerenderRes.json();
          document.getElementById('prerenderCached').textContent = prerender.totalCachedFiles || 0;
          document.getElementById('prerenderQueue').textContent = prerender.uncached || 0;
        } catch (e) {
          document.getElementById('prerenderCached').textContent = '?';
          document.getElementById('prerenderQueue').textContent = '?';
        }

        // Update timestamp
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

      } catch (e) {
        console.error('Failed to fetch stats:', e);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Refresh Data';
      }
    }

    async function loadServers(page) {
      const serversList = document.getElementById('serversList');
      serversList.innerHTML = '<div class="no-data">Loading servers...</div>';

      try {
        const res = await authFetch(\`/admin/servers?page=\${page}&limit=\${pageLimit}\`);
        const data = await res.json();

        if (data.servers && data.servers.length > 0) {
          let html = data.servers.map(server => {
            const minTtl = server.players && server.players.length > 0
              ? Math.min(...server.players.map(p => p.ttl || 0))
              : 0;
            const serverTtlStatus = getTtlStatus(minTtl);
            const serverId = 'server-' + server.audience.replace(/[^a-zA-Z0-9]/g, '');

            return \`
            <div class="server-card">
              <div class="server-header">
                <span class="server-name">
                  \${server.name || server.audience || 'Unknown Server'}
                  <span class="ttl-badge \${serverTtlStatus.class} server-ttl">\${serverTtlStatus.text}</span>
                </span>
                <span class="player-count">\${server.playerCount} player\${server.playerCount !== 1 ? 's' : ''}</span>
              </div>
              \${server.name ? \`<div class="server-audience">ID: \${server.audience}</div>\` : ''}
              \${server.players && server.players.length > 0 ? \`
                <div class="players-list" id="\${serverId}">
                  \${server.players.map(p => {
                    const ttlStatus = getTtlStatus(p.ttl || 0);
                    return \`
                    <div class="player-tag">
                      <iframe class="player-avatar" src="/avatar/\${p.uuid}/head?bg=black" loading="lazy" title="\${p.username}"></iframe>
                      <div class="player-info">
                        <span class="player-name">\${p.username} <span class="ttl-badge \${ttlStatus.class}">\${ttlStatus.text}</span></span>
                        <span class="uuid">\${p.uuid.substring(0, 8)}...</span>
                      </div>
                    </div>
                  \`}).join('')}
                </div>
              \` : ''}
            </div>
          \`}).join('');

          // Add pagination controls
          const pg = data.pagination;
          html += \`
            <div class="pagination">
              <button onclick="changePage(\${pg.page - 1})" \${!pg.hasPrev ? 'disabled' : ''}>Previous</button>
              <span>Page \${pg.page} of \${pg.totalPages} (\${pg.totalServers} servers)</span>
              <button onclick="changePage(\${pg.page + 1})" \${!pg.hasNext ? 'disabled' : ''}>Next</button>
            </div>
          \`;

          serversList.innerHTML = html;
        } else {
          serversList.innerHTML = '<div class="no-data">No active servers</div>';
        }
      } catch (e) {
        serversList.innerHTML = '<div class="no-data">Failed to load servers</div>';
      }
    }

    function changePage(page) {
      if (page < 1) return;
      currentPage = page;
      loadServers(page);
    }

    // Player search functionality (server-side)
    let searchTimeout = null;
    let lastSearchQuery = '';

    // Perform search via server-side API
    async function performSearch(query) {
      const searchResults = document.getElementById('searchResults');
      query = query.trim();
      lastSearchQuery = query.toLowerCase();

      if (!query || query.length < 2) {
        searchResults.classList.add('hidden');
        searchResults.innerHTML = '';
        // Remove highlights from server list
        document.querySelectorAll('.server-card.highlight').forEach(el => el.classList.remove('highlight'));
        document.querySelectorAll('.player-tag.highlight').forEach(el => el.classList.remove('highlight'));
        return;
      }

      searchResults.classList.remove('hidden');
      searchResults.innerHTML = '<div class="search-loading">Searching...</div>';

      try {
        const res = await authFetch(\`/admin/search?q=\${encodeURIComponent(query)}&limit=50\`);
        const data = await res.json();
        const results = data.results || [];

        if (results.length === 0) {
          searchResults.innerHTML = '<div class="search-no-results">No players found matching "' + query + '"</div>';
          return;
        }

        const html = results.map(player => {
          const ttlStatus = getTtlStatus(player.ttl || 0);
          return \`
            <div class="search-result">
              <div class="player-info-header">
                <iframe class="player-avatar-large" src="/avatar/\${player.uuid}/head?bg=black" loading="lazy"></iframe>
                <div class="player-details">
                  <h3>\${player.username} <span class="ttl-badge \${ttlStatus.class}">\${ttlStatus.text}</span></h3>
                  <div class="uuid-full">\${player.uuid}</div>
                </div>
              </div>
              <div class="server-list">
                <strong>Playing on:</strong>
                \${player.servers.map(s => \`
                  <div class="server-item">
                    <span class="server-link" onclick="scrollToServer('\${s.audience}')">\${s.name}</span>
                  </div>
                \`).join('')}
              </div>
            </div>
          \`;
        }).join('');

        searchResults.innerHTML = html;

        // Highlight matching players in server list
        highlightMatchingPlayers(lastSearchQuery);
      } catch (e) {
        searchResults.innerHTML = '<div class="search-no-results">Search failed: ' + e.message + '</div>';
      }
    }

    // Highlight players in the server list that match search
    function highlightMatchingPlayers(query) {
      document.querySelectorAll('.server-card.highlight').forEach(el => el.classList.remove('highlight'));
      document.querySelectorAll('.player-tag.highlight').forEach(el => el.classList.remove('highlight'));

      if (!query) return;

      document.querySelectorAll('.player-tag').forEach(tag => {
        const name = tag.querySelector('.player-name')?.textContent?.toLowerCase() || '';
        const uuid = tag.querySelector('.uuid')?.textContent?.toLowerCase() || '';
        if (name.includes(query) || uuid.includes(query)) {
          tag.classList.add('highlight');
          tag.closest('.server-card')?.classList.add('highlight');
        }
      });
    }

    // Scroll to server in list
    function scrollToServer(audience) {
      const serverId = 'server-' + audience.replace(/[^a-zA-Z0-9]/g, '');
      const serverEl = document.getElementById(serverId);
      if (serverEl) {
        const card = serverEl.closest('.server-card');
        if (card) {
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
          card.style.animation = 'pulse 0.5s ease-out';
          setTimeout(() => card.style.animation = '', 500);
        }
      }
    }

    // Clear search
    function clearSearch() {
      document.getElementById('playerSearch').value = '';
      performSearch('');
    }

    // Debounced search input handler
    document.getElementById('playerSearch').addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => performSearch(e.target.value), 300);
    });

    // Re-apply highlights after server list reload
    const originalLoadServers = loadServers;
    loadServers = async function(page) {
      await originalLoadServers(page);
      if (lastSearchQuery) {
        highlightMatchingPlayers(lastSearchQuery);
      }
    };

    // Initial load
    refreshData();

    // Auto-refresh every 60 seconds
    setInterval(refreshData, 60000);
  </script>
</body>
</html>`;

  sendHtml(res, 200, html);
}

module.exports = {
  handleAdminLogin,
  handleAdminVerify,
  handleActiveSessions,
  handleAdminStats,
  handleAdminServers,
  handlePlayerSearch,
  handlePrerenderQueue,
  handleAdminDashboard,
};
