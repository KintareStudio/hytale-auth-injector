const fs = require('fs');
const path = require('path');
const config = require('../config');
const storage = require('../services/storage');
const assets = require('../services/assets');
const { sendJson, sendHtml, sendBinary } = require('../utils/response');

// Head image cache directory
const HEAD_CACHE_DIR = config.headCacheDir;

/**
 * Initialize head cache directory
 */
function initHeadCache() {
  try {
    if (!fs.existsSync(HEAD_CACHE_DIR)) {
      fs.mkdirSync(HEAD_CACHE_DIR, { recursive: true });
      console.log(`Created head cache directory: ${HEAD_CACHE_DIR}`);
    }
  } catch (err) {
    console.error('Error initializing head cache:', err.message);
  }
}

/**
 * Get cached head image from disk
 */
function getHeadCacheFromDisk(cacheKey) {
  try {
    const filePath = path.join(HEAD_CACHE_DIR, `${cacheKey}.png`);
    if (!fs.existsSync(filePath)) return null;

    const stats = fs.statSync(filePath);
    const age = Date.now() - stats.mtimeMs;

    if (age > config.headCacheTtl) {
      fs.unlinkSync(filePath);
      return null;
    }

    return {
      data: fs.readFileSync(filePath),
      mtime: stats.mtime
    };
  } catch (err) {
    return null;
  }
}

/**
 * Save head image to disk
 */
function saveHeadCacheToDisk(cacheKey, data) {
  try {
    const filePath = path.join(HEAD_CACHE_DIR, `${cacheKey}.png`);
    fs.writeFileSync(filePath, data);
  } catch (err) {
    console.error('Error saving head cache to disk:', err.message);
  }
}

/**
 * Delete head cache files for a user
 */
function deleteHeadCacheFromDisk(uuid) {
  try {
    const files = fs.readdirSync(HEAD_CACHE_DIR);
    for (const file of files) {
      if (file.startsWith(uuid + '_')) {
        fs.unlinkSync(path.join(HEAD_CACHE_DIR, file));
      }
    }
  } catch (err) {
    console.error('Error deleting head cache from disk:', err.message);
  }
}

/**
 * Invalidate head cache for a user
 */
function invalidateHeadCache(uuid) {
  deleteHeadCacheFromDisk(uuid);
}

/**
 * Handle avatar routes
 */
async function handleAvatarRoutes(req, res, urlPath, body = {}) {
  const pathParts = urlPath.split('/').filter(p => p);

  if (pathParts.length < 2) {
    sendJson(res, 400, { error: 'UUID required' });
    return;
  }

  const uuid = pathParts[1];
  const action = pathParts[2];

  if (action === 'model') {
    await handleAvatarModel(req, res, uuid);
  } else if (action === 'preview') {
    await handleAvatarPreview(req, res, uuid, body);
  } else if (action === 'head') {
    await serveHeadEmbed(req, res, uuid);
  } else if (action === 'head-cache' && req.method === 'POST') {
    handleHeadImageCache(req, res, uuid);
  } else {
    serveAvatarViewer(req, res, uuid);
  }
}

/**
 * Handle avatar model data request
 */
async function handleAvatarModel(req, res, uuid) {
  const userData = await storage.getUserData(uuid);
  const userSkin = userData.skin || null;

  if (!userSkin) {
    sendJson(res, 404, { error: 'User skin not found', uuid });
    return;
  }

  const configs = assets.loadCosmeticConfigs();
  const gradientSets = assets.loadGradientSets();
  const eyeColors = assets.loadEyeColors();

  if (!configs) {
    sendJson(res, 500, { error: 'Could not load cosmetic configs' });
    return;
  }

  // Resolve all skin parts to their model/texture paths
  const resolvedParts = {};
  const categories = [
    'haircut', 'pants', 'overtop', 'undertop', 'shoes',
    'headAccessory', 'faceAccessory', 'earAccessory',
    'eyebrows', 'eyes', 'face', 'facialHair', 'gloves',
    'cape', 'overpants', 'mouth', 'ears', 'underwear'
  ];

  for (const category of categories) {
    if (userSkin[category]) {
      const resolved = assets.resolveSkinPart(category, userSkin[category], configs, gradientSets);
      if (resolved) {
        resolvedParts[category] = resolved;
      }
    }
  }

  // Handle eye color separately (it's stored in 'eyeColor' field)
  if (userSkin.eyeColor && eyeColors) {
    const eyeColorData = eyeColors[userSkin.eyeColor];
    if (eyeColorData && resolvedParts.eyes) {
      // Override the base color for eyes with the eye color
      resolvedParts.eyes.baseColor = eyeColorData.BaseColor;

      // Also resolve the gradient texture from Eyes_Gradient set
      if (resolvedParts.eyes.gradientSet && gradientSets) {
        const eyeGradientSet = gradientSets.find(g => g.Id === resolvedParts.eyes.gradientSet);
        if (eyeGradientSet && eyeGradientSet.Gradients && eyeGradientSet.Gradients[userSkin.eyeColor]) {
          resolvedParts.eyes.gradientTexture = eyeGradientSet.Gradients[userSkin.eyeColor].Texture;
        }
      }
    }
  }

  // Parse bodyCharacteristic for body type and skin tone
  // Format: "BodyType.SkinToneId" e.g., "Muscular.22"
  let bodyType = 'Regular';
  let skinTone = '01'; // Default to light peach
  let skinToneFromBody = false;

  if (userSkin.bodyCharacteristic) {
    const bodyParts = userSkin.bodyCharacteristic.split('.');
    bodyType = bodyParts[0] || 'Regular';
    if (bodyParts.length > 1 && bodyParts[1]) {
      // Pad single digit to two digits (e.g., "22" stays "22", "5" becomes "05")
      skinTone = bodyParts[1].padStart(2, '0');
      skinToneFromBody = true;
    }
  }

  // Use explicit skinTone only if bodyCharacteristic didn't have one
  // Format can be "XX" or "Default.XX" - extract the tone number
  if (!skinToneFromBody && userSkin.skinTone) {
    const toneParts = userSkin.skinTone.split('.');
    // If format is "Default.XX", take the second part; otherwise use as-is
    const toneValue = toneParts.length > 1 ? toneParts[1] : toneParts[0];
    if (toneValue && toneValue !== 'Default') {
      skinTone = toneValue.padStart(2, '0');
    }
  }

  // Set no-cache headers to prevent browser caching of user skin data
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  sendJson(res, 200, {
    uuid,
    skinTone,
    bodyType,
    parts: resolvedParts,
    raw: userSkin
  });
}

/**
 * Handle avatar preview with custom skin data (POST)
 */
async function handleAvatarPreview(req, res, uuid, customSkin = {}) {
  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed, use POST' });
    return;
  }

  const configs = assets.loadCosmeticConfigs();
  const gradientSets = assets.loadGradientSets();
  const eyeColors = assets.loadEyeColors();

  if (!configs) {
    sendJson(res, 500, { error: 'Could not load cosmetic configs' });
    return;
  }

  // Resolve all skin parts to their model/texture paths
  const resolvedParts = {};
  const categories = [
    'haircut', 'pants', 'overtop', 'undertop', 'shoes',
    'headAccessory', 'faceAccessory', 'earAccessory',
    'eyebrows', 'eyes', 'face', 'facialHair', 'gloves',
    'cape', 'overpants', 'mouth', 'ears', 'underwear'
  ];

  for (const category of categories) {
    if (customSkin[category]) {
      const resolved = assets.resolveSkinPart(category, customSkin[category], configs, gradientSets);
      if (resolved) {
        resolvedParts[category] = resolved;
      }
    }
  }

  // Handle eye color separately
  if (customSkin.eyeColor && eyeColors) {
    const eyeColorData = eyeColors[customSkin.eyeColor];
    if (eyeColorData && resolvedParts.eyes) {
      resolvedParts.eyes.baseColor = eyeColorData.BaseColor;

      if (resolvedParts.eyes.gradientSet && gradientSets) {
        const eyeGradientSet = gradientSets.find(g => g.Id === resolvedParts.eyes.gradientSet);
        if (eyeGradientSet && eyeGradientSet.Gradients && eyeGradientSet.Gradients[customSkin.eyeColor]) {
          resolvedParts.eyes.gradientTexture = eyeGradientSet.Gradients[customSkin.eyeColor].Texture;
        }
      }
    }
  }

  // Parse bodyCharacteristic for body type and skin tone
  let bodyType = 'Regular';
  let skinTone = '01';
  let skinToneFromBody = false;

  if (customSkin.bodyCharacteristic) {
    const bodyParts = customSkin.bodyCharacteristic.split('.');
    bodyType = bodyParts[0] || 'Regular';
    if (bodyParts.length > 1 && bodyParts[1]) {
      skinTone = bodyParts[1].padStart(2, '0');
      skinToneFromBody = true;
    }
  }

  // Use explicit skinTone only if bodyCharacteristic didn't have one
  // Format can be "XX" or "Default.XX" - extract the tone number
  if (!skinToneFromBody && customSkin.skinTone) {
    const toneParts = customSkin.skinTone.split('.');
    const toneValue = toneParts.length > 1 ? toneParts[1] : toneParts[0];
    if (toneValue && toneValue !== 'Default') {
      skinTone = toneValue.padStart(2, '0');
    }
  }

  sendJson(res, 200, {
    uuid,
    skinTone,
    bodyType,
    parts: resolvedParts,
    raw: customSkin
  });
}

/**
 * Serve embeddable head viewer
 */
async function serveHeadEmbed(req, res, uuid) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const bgParam = url.searchParams.get('bg') || 'black';
  const noCache = url.searchParams.get('nocache') === '1';
  const cacheKey = `${uuid}_${bgParam}`;

  if (!noCache) {
    const cached = getHeadCacheFromDisk(cacheKey);
    if (cached) {
      const lastModified = cached.mtime.toUTCString();
      const etag = `"${cacheKey}-${cached.mtime.getTime()}"`;

      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304);
        res.end();
        return;
      }

      const ifModifiedSince = req.headers['if-modified-since'];
      if (ifModifiedSince && new Date(ifModifiedSince) >= cached.mtime) {
        res.writeHead(304);
        res.end();
        return;
      }

      sendBinary(res, 200, cached.data, 'image/png', {
        'Last-Modified': lastModified,
        'ETag': etag,
        'Cache-Control': 'public, max-age=3600'
      });
      return;
    }
  }

  // Return HTML page that renders and caches the head
  const html = generateHeadEmbedHtml(uuid, bgParam);
  sendHtml(res, 200, html);
}

/**
 * Handle head image cache POST
 */
function handleHeadImageCache(req, res, uuid, url) {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const bgParam = url?.searchParams?.get('bg') || 'black';
    const cacheKey = `${uuid}_${bgParam}`;
    const data = Buffer.concat(chunks);

    if (data.length > 0) {
      saveHeadCacheToDisk(cacheKey, data);
      console.log(`Cached head image for ${uuid} (${bgParam}): ${data.length} bytes`);
    }

    res.writeHead(204);
    res.end();
  });
}

/**
 * Serve avatar viewer HTML page
 */
function serveAvatarViewer(req, res, uuid) {
  const viewerPath = path.join(__dirname, '../../views/avatar-viewer.html');

  if (fs.existsSync(viewerPath)) {
    let html = fs.readFileSync(viewerPath, 'utf8');
    html = html.replace(/\{\{UUID\}\}/g, uuid);
    sendHtml(res, 200, html);
    return;
  }

  // Fallback to inline viewer
  const html = generateAvatarViewerHtml(uuid);
  sendHtml(res, 200, html);
}

/**
 * Handle customizer route
 */
function handleCustomizerRoute(req, res, urlPath) {
  const parts = urlPath.split('/').filter(p => p);
  const uuid = parts[1] || 'preview';

  // Try views/ first, then assets/
  const viewsPaths = [
    path.join(__dirname, '../../views/customizer.html'),
    path.join(__dirname, '../../assets/customizer.html')
  ];

  for (const viewerPath of viewsPaths) {
    if (fs.existsSync(viewerPath)) {
      let html = fs.readFileSync(viewerPath, 'utf8');
      html = html.replace(/\{\{UUID\}\}/g, uuid);
      sendHtml(res, 200, html);
      return;
    }
  }

  // Simple fallback
  sendHtml(res, 200, `<!DOCTYPE html><html><body><h1>Character Customizer</h1><p>UUID: ${uuid}</p></body></html>`);
}

/**
 * Generate head embed HTML - uses HytaleAvatarViewer from /assets/avatar.js
 */
function generateHeadEmbedHtml(uuid, bgParam = 'transparent') {
  // Parse background parameter
  let cssBg = 'transparent';
  let threeColor = '0x000000';
  let threeAlpha = '0'; // 0 = transparent

  if (bgParam === 'transparent') {
    cssBg = 'transparent';
    threeAlpha = '0';
  } else if (bgParam === 'white') {
    cssBg = '#ffffff';
    threeColor = '0xffffff';
    threeAlpha = '1';
  } else if (bgParam === 'black') {
    cssBg = '#000000';
    threeColor = '0x000000';
    threeAlpha = '1';
  } else if (bgParam.startsWith('#')) {
    // Custom hex color
    cssBg = bgParam;
    threeColor = '0x' + bgParam.slice(1);
    threeAlpha = '1';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Head - ${uuid}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; overflow: hidden; background: ${cssBg}; }
    #canvas-container { width: 100%; height: 100%; }
    canvas { display: block; width: 100%; height: 100%; }
  </style>
</head>
<body>
  <div id="canvas-container"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="/assets/avatar.js"></script>
  <script>
    const UUID = '${uuid}';
    const BG_COLOR = ${threeColor};
    const BG_ALPHA = ${threeAlpha};

    async function init() {
      const container = document.getElementById('canvas-container');

      const viewer = new HytaleAvatarViewer(container, {
        autoRotate: false,
        showGrid: false,
        backgroundColor: BG_COLOR,
        alpha: true  // Enable transparency support
      });

      viewer.init();

      // Set background based on parameters
      viewer.renderer.setClearColor(BG_COLOR, BG_ALPHA);
      if (BG_ALPHA === 0) {
        viewer.scene.background = null;
      } else {
        viewer.scene.background = new THREE.Color(BG_COLOR);
      }

      try {
        await viewer.loadAvatar(UUID);

        // Camera position for head view (facing camera)
        // Pos: (0, 1.1, -1.0), LookAt Y: 1.0, FOV: 40
        viewer.camera.position.set(0, 1.1, -1.0);
        viewer.camera.lookAt(0, 1.0, 0);
        viewer.camera.fov = 40;
        viewer.camera.updateProjectionMatrix();

        // Disable animation for static head
        viewer.animationEnabled = false;
        viewer.autoRotate = false;
        await viewer.setAnimation(null);

        // Render once
        viewer.renderer.render(viewer.scene, viewer.camera);

        // Cache the rendered image on the server
        cacheRenderedImage(viewer.renderer.domElement);
      } catch (err) {
        console.error('Head embed error:', err);
      }
    }

    // Send rendered image to server for caching
    async function cacheRenderedImage(canvas) {
      try {
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        await fetch('/avatar/' + UUID + '/head-cache?bg=${bgParam}', {
          method: 'POST',
          body: blob,
          headers: { 'Content-Type': 'image/png' }
        });
      } catch (err) {
        console.log('Cache upload failed (non-critical):', err);
      }
    }

    init();
  </script>
</body>
</html>`;
}

/**
 * Generate avatar viewer HTML - uses HytaleAvatarViewer from /assets/avatar.js
 */
function generateAvatarViewerHtml(uuid) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Avatar Viewer - ${uuid}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      color: #fff;
    }
    .container { display: flex; flex-direction: column; align-items: center; padding: 20px; }
    h1 { margin-bottom: 10px; font-size: 1.5rem; }
    .uuid { font-family: monospace; background: rgba(255,255,255,0.1); padding: 5px 10px; border-radius: 4px; font-size: 0.9rem; margin-bottom: 20px; }
    #canvas-container { width: 100%; max-width: 600px; aspect-ratio: 1; background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; position: relative; }
    #loading { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
    .spinner { width: 40px; height: 40px; border: 3px solid rgba(255,255,255,0.2); border-top-color: #fff; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 10px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    #error { color: #ff6b6b; padding: 20px; text-align: center; display: none; }
    .controls { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; }
    button { background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #fff; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
    button:hover { background: rgba(255,255,255,0.2); }
    button.active { background: rgba(100,149,237,0.4); border-color: rgba(100,149,237,0.6); }
    .info { margin-top: 20px; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; max-width: 600px; width: 100%; }
    .info h3 { margin-bottom: 10px; font-size: 1rem; }
    .parts-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; font-size: 0.85rem; }
    .part-item { background: rgba(255,255,255,0.05); padding: 5px 10px; border-radius: 4px; }
    .part-name { color: #888; font-size: 0.75rem; }
    .status { position: absolute; bottom: 10px; left: 10px; font-size: 0.7rem; color: rgba(255,255,255,0.5); }
  </style>
</head>
<body>
  <div class="container" id="main-container">
    <h1>Hytale Avatar Viewer</h1>
    <div class="uuid">${uuid}</div>
    <div id="canvas-container">
      <div id="loading"><div class="spinner"></div><div id="loading-text">Loading avatar...</div></div>
      <div id="error"></div>
      <div class="status" id="status"></div>
    </div>
    <div class="controls">
      <button id="rotate-left">Rotate Left</button>
      <button id="rotate-right">Rotate Right</button>
      <button id="reset">Reset View</button>
      <button id="toggle-wireframe">Wireframe</button>
      <button id="toggle-autorotate" class="active">Auto-Rotate</button>
      <select id="animation-select" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #fff; padding: 10px; border-radius: 5px; cursor: pointer;">
        <option value="">No Animation</option>
        <option value="Default/Idle" selected>Idle</option>
        <option value="Default/Walk">Walk</option>
        <option value="Default/Run">Run</option>
        <option value="Default/Sprint">Sprint</option>
        <option value="Default/Jump">Jump</option>
        <option value="Default/Fall">Fall</option>
        <option value="Default/Crouch">Crouch</option>
        <option value="Emote/Wave">Wave</option>
        <option value="Emote/Dab_Left">Dab Left</option>
        <option value="Emote/Dab_Right">Dab Right</option>
        <option value="Taunt/Laugh">Laugh</option>
        <option value="Taunt/Chicken">Chicken</option>
        <option value="Taunt/Punch">Punch</option>
        <option value="Poses/Sword">Sword Pose</option>
        <option value="Poses/Staff">Staff Pose</option>
        <option value="Poses/Ninja">Ninja Pose</option>
        <option value="Climb/Climb_Idle">Climb Idle</option>
        <option value="Swim/Swim">Swim</option>
        <option value="Glide/Glide">Glide</option>
        <option value="Roll/Roll">Roll</option>
      </select>
    </div>
    <div class="info" id="skin-info" style="display: none;">
      <h3>Equipped Items</h3>
      <div class="parts-list" id="parts-list"></div>
    </div>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="/assets/avatar.js"></script>
  <script>
    const UUID = '${uuid}';
    let viewer = null;

    function setLoadingText(text) { document.getElementById('loading-text').textContent = text; }
    function updateStatus(text) { document.getElementById('status').textContent = text; }

    function displaySkinInfo(data) {
      const infoEl = document.getElementById('skin-info');
      const listEl = document.getElementById('parts-list');
      if (!data.parts || Object.keys(data.parts).length === 0) return;
      infoEl.style.display = 'block';
      listEl.innerHTML = '';
      for (const [category, part] of Object.entries(data.parts)) {
        const item = document.createElement('div');
        item.className = 'part-item';
        item.innerHTML = '<div class="part-name">' + category + '</div><div>' + (part.id || category) + (part.colorId ? '.' + part.colorId : '') + '</div>';
        listEl.appendChild(item);
      }
    }

    async function init() {
      try {
        const container = document.getElementById('canvas-container');

        viewer = new HytaleAvatarViewer(container, {
          autoRotate: true,
          showGrid: true,
          backgroundColor: 0x1a1a2e,
          onLoadProgress: setLoadingText,
          onLoadComplete: (data) => {
            displaySkinInfo(data);
            document.getElementById('loading').style.display = 'none';
            updateStatus('Ready - Drag to rotate');
          },
          onError: (err) => {
            document.getElementById('loading').style.display = 'none';
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = err.message;
          }
        });

        viewer.init();
        await viewer.loadAvatar(UUID);

        // Setup controls
        document.getElementById('rotate-left').onclick = () => viewer.rotate(-0.5);
        document.getElementById('rotate-right').onclick = () => viewer.rotate(0.5);
        document.getElementById('reset').onclick = () => viewer.resetView();

        document.getElementById('toggle-wireframe').onclick = function(e) {
          viewer.setWireframe(!viewer.wireframeMode);
          e.target.classList.toggle('active', viewer.wireframeMode);
        };

        document.getElementById('toggle-autorotate').onclick = function(e) {
          viewer.setAutoRotate(!viewer.autoRotate);
          e.target.classList.toggle('active', viewer.autoRotate);
        };

        document.getElementById('animation-select').addEventListener('change', async function(e) {
          await viewer.setAnimation(e.target.value || null);
        });

      } catch (err) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error').style.display = 'block';
        document.getElementById('error').textContent = err.message;
        console.error('Error:', err);
      }
    }

    init();
  </script>
</body>
</html>`;
}

/**
 * Test page for head embed
 */
async function handleTestHeadPage(req, res) {
  // Use static test UUID with known skin data
  const testUuid = '03fbfdef-9c4a-4eef-bd10-63fa96427133';
  const testUsername = 'TestPlayer';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Head Embed Test</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      padding: 40px;
      color: #e0e0e0;
    }
    h1 { color: #00d4ff; margin-bottom: 30px; font-size: 1.8em; }
    h2 { color: #888; margin: 30px 0 15px; font-size: 1.1em; }
    .container { max-width: 800px; margin: 0 auto; }
    .section {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .players-list { display: flex; flex-wrap: wrap; gap: 10px; }
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
    .player-tag .player-info { display: flex; flex-direction: column; gap: 2px; }
    .player-tag .player-name { color: #fff; font-weight: 500; }
    .player-tag .uuid { color: #666; font-size: 0.7em; font-family: monospace; }
    .ttl-badge { font-size: 0.7em; padding: 2px 6px; border-radius: 3px; margin-left: 5px; }
    .ttl-fresh { background: rgba(0, 255, 136, 0.25); color: #7fdfb0; }
    .player-tag-large {
      background: rgba(255, 255, 255, 0.1);
      padding: 12px 20px;
      border-radius: 20px;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 15px;
    }
    .player-tag-large .player-avatar {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: rgba(0, 0, 0, 0.3);
      flex-shrink: 0;
      overflow: hidden;
      border: none;
    }
    .player-tag-large .player-info { display: flex; flex-direction: column; gap: 4px; }
    .player-tag-large .player-name { color: #fff; font-weight: 600; font-size: 1.2em; }
    .player-tag-large .uuid { color: #666; font-size: 0.8em; font-family: monospace; }
    .iframe-preview { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
    .iframe-box { text-align: center; }
    .iframe-box label { display: block; margin-bottom: 10px; color: #888; font-size: 0.9em; }
    .iframe-box iframe { border: 1px dashed rgba(255,255,255,0.2); background: rgba(0,0,0,0.3); }
  </style>
</head>
<body>
  <div class="container">
    <h1>Head Embed Test</h1>
    <div class="section">
      <h2>Background variants (64x64)</h2>
      <p style="color: #888; margin-bottom: 15px; font-size: 0.9em;">Use ?bg=transparent|white|black|#hexcolor</p>
      <div class="iframe-preview">
        <div class="iframe-box">
          <label>?bg=transparent (default)</label>
          <iframe src="/avatar/${testUuid}/head?bg=transparent" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=white</label>
          <iframe src="/avatar/${testUuid}/head?bg=white" width="64" height="64" frameborder="0" style="background: #333;"></iframe>
        </div>
        <div class="iframe-box">
          <label>?bg=black</label>
          <iframe src="/avatar/${testUuid}/head?bg=black" width="64" height="64" frameborder="0"></iframe>
        </div>
      </div>
    </div>
    <div class="section">
      <h2>Size variants (transparent bg)</h2>
      <div class="iframe-preview">
        <div class="iframe-box">
          <label>128x128</label>
          <iframe src="/avatar/${testUuid}/head" width="128" height="128" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>64x64</label>
          <iframe src="/avatar/${testUuid}/head" width="64" height="64" frameborder="0"></iframe>
        </div>
        <div class="iframe-box">
          <label>40x40 (admin badge)</label>
          <iframe src="/avatar/${testUuid}/head" width="40" height="40" frameborder="0"></iframe>
        </div>
      </div>
    </div>
    <div class="section">
      <h2>Player badge (admin style - 40px avatar)</h2>
      <div class="players-list">
        <div class="player-tag">
          <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="${testUsername}"></iframe>
          <div class="player-info">
            <span class="player-name">${testUsername} <span class="ttl-badge ttl-fresh">9h 45m</span></span>
            <span class="uuid">${testUuid.substring(0, 8)}...</span>
          </div>
        </div>
      </div>
    </div>
    <div class="section">
      <h2>Large player badge (64px avatar)</h2>
      <div class="player-tag-large">
        <iframe class="player-avatar" src="/avatar/${testUuid}/head" loading="lazy" title="${testUsername}"></iframe>
        <div class="player-info">
          <span class="player-name">${testUsername}</span>
          <span class="uuid">${testUuid}</span>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

  sendHtml(res, 200, html);
}

// Initialize cache on module load
initHeadCache();

module.exports = {
  handleAvatarRoutes,
  handleAvatarModel,
  handleAvatarPreview,
  handleCustomizerRoute,
  handleTestHeadPage,
  invalidateHeadCache,
  initHeadCache,
};
