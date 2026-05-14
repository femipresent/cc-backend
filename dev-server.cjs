require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');

const root = __dirname;
const basePort = Number(process.env.PORT || 8000);
const maxPort = Number(process.env.PORT_FALLBACK_MAX || (basePort + 10));
const ordersFile = path.join(root, 'orders.json');
const usersFile = path.join(root, 'users.json');
const authSessionSecret = process.env.AUTH_SESSION_SECRET || 'CHANGE_ME_SESSION_SECRET';


const crypto = require('crypto');

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function sign(data) {
  return base64url(crypto.createHmac('sha256', authSessionSecret).update(data).digest());
}

function hashPassword(password, salt) {
  return crypto.createHmac('sha256', salt).update(password).digest('hex');
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(';').forEach(part => {
    const [k, ...rest] = part.trim().split('=');
    if (!k) return;
    out[k] = decodeURIComponent(rest.join('=') || '');
  });
  return out;
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.session;
  if (!token) return null;
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return null;
  const expected = sign(payloadB64);
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payloadJson = Buffer.from(payloadB64, 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson);
    if (!payload || !payload.userId || !payload.exp) return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

const types = {

  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
};

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}


function loadUsers() {
  if (!fs.existsSync(usersFile)) return [];
  try {
    return JSON.parse(fs.readFileSync(usersFile, 'utf8') || '[]');
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function makeSessionToken(userId) {
  const payload = { userId, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 }; // 7 days
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadJson, 'utf8').toString('base64');
  const sig = sign(payloadB64);
  return `${payloadB64}.${sig}`;
}

async function saveOrder(req, res) {
  try {

    const rawBody = await readBody(req);
    const order = JSON.parse(rawBody || '{}');
    const now = new Date().toISOString();
    const session = getSession(req);
    const userId = session?.userId || null;
    const savedOrder = {

      id: order.reference || `CC-${Date.now().toString(36).toUpperCase()}`,
      createdAt: now,
      userId,
      ...order,
    };


    let orders = [];
    if (fs.existsSync(ordersFile)) {
      orders = JSON.parse(fs.readFileSync(ordersFile, 'utf8') || '[]');
    }

    orders.push(savedOrder);
    fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
    console.log(`NEW ORDER: ${savedOrder.reference} - ${savedOrder.product} - ₦${savedOrder.total}`);
    sendJson(res, 201, { ok: true, order: savedOrder });
  } catch (error) {
    sendJson(res, 400, { ok: false, error: 'Could not save order' });
  }
}

function jsonBad(res, status, message) {
  sendJson(res, status, { ok: false, error: message });
}


function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session) {
    jsonBad(res, 401, 'Not logged in');
    return null;
  }

  const users = loadUsers();
  const user = users.find(u => u.id === session.userId) || null;
  if (!user) {
    jsonBad(res, 401, 'Invalid session');
    return null;
  }

  if (!process.env.ADMIN_EMAIL && !process.env.ADMIN_USER_ID) {
    jsonBad(res, 403, 'Admin not configured');
    return null;
  }

  if (!isAdminUser(user)) {
    jsonBad(res, 403, 'Forbidden');
    return null;
  }
  return user;
}

function ordersLoad() {
  if (!fs.existsSync(ordersFile)) return [];
  try {
    return JSON.parse(fs.readFileSync(ordersFile, 'utf8') || '[]');
  } catch {
    return [];
  }
}

function ordersSave(orders) {
  fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
}

function normalizeStatus(st) {
  return String(st || '').toLowerCase();
}

function isAdminUser(user) {
  if (!user) return false;
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminUserId = process.env.ADMIN_USER_ID;
  return (adminEmail && user.email && user.email.toLowerCase() === String(adminEmail).toLowerCase()) ||
         (adminUserId && user.id === adminUserId);
}

function createServer() {
  return http.createServer((req, res) => {
  if (req.method === 'GET' && req.url.split('?')[0] === '/api/orders/admin/summary') {
    const admin = requireAdmin(req, res);
    if (!admin) return;

    const orders = ordersLoad();
    const summary = {
      totalOrders: orders.length,
      totalPending: 0,
      totalProcessing: 0,
      totalShipped: 0,
      totalDelivered: 0,
      reviewsCount: 0,
      avgOrderValue: 0,
    };

    let totalValue = 0;
    let valueCount = 0;

    for (const o of orders) {
      const st = normalizeStatus(o.status);
      if (!st || ['pending','review','unprocessed'].includes(st)) summary.totalPending++;
      else if (st === 'processing') summary.totalProcessing++;
      else if (['shipped','ship','in transit'].includes(st)) summary.totalShipped++;
      else if (['delivered','complete','completed'].includes(st)) summary.totalDelivered++;
      
      if (o.adminReview) {
        summary.reviewsCount++;
      }

      const val = o.total ?? o.unitPrice;
      const num = Number(val);
      if (Number.isFinite(num)) {
        totalValue += num;
        valueCount++;
      }
    }

    summary.avgOrderValue = valueCount ? (totalValue / valueCount) : 0;

    return sendJson(res, 200, { ok: true, summary });
  }

  if (req.method === 'GET' && req.url.split('?')[0] === '/api/orders/admin') {
    const admin = requireAdmin(req, res);
    if (!admin) return;

    const orders = ordersLoad();
    orders.sort((a,b) => {
      const da = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const db = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return db - da;
    });

    return sendJson(res, 200, { ok: true, orders });
  }

  if (req.method === 'POST' && req.url.split('?')[0].startsWith('/api/orders/') && req.url.split('?')[0].endsWith('/admin/status')) {
    const admin = requireAdmin(req, res);
    if (!admin) return;

    const urlPath = req.url.split('?')[0];
    const parts = urlPath.split('/');
    // ['', 'api', 'orders', ':id', 'admin', 'status']
    const orderId = parts[3];

    let orders = ordersLoad();
    const idx = orders.findIndex(o => String(o.id) === String(orderId) || String(o.reference) === String(orderId));
    if (idx < 0) return jsonBad(res, 404, 'Order not found');

    (async () => {
      try {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody || '{}');

        const now = new Date().toISOString();
        orders[idx] = {
          ...orders[idx],
          status: body.status ?? orders[idx].status,
          adminReview: body.adminReview ?? orders[idx].adminReview,
          adminNotes: body.adminNotes ?? orders[idx].adminNotes,
          updatedAt: now,
        };

        ordersSave(orders);
        return sendJson(res, 200, { ok: true, order: orders[idx] });
      } catch {
        return jsonBad(res, 400, 'Could not update');
      }
    })();

    return;
  }

  if (req.method === 'POST' && req.url.split('?')[0] === '/api/auth/signup') {
    (async () => {
      try {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody || '{}');
        const { email, password, name, phone, address, profilePic } = body;
        if (!email || !password) return jsonBad(res, 400, 'Email and password required');
        const users = loadUsers();
        if (users.some(u => u.email.toLowerCase() === String(email).toLowerCase())) {
          return jsonBad(res, 409, 'User already exists');
        }
        const id = 'u_' + crypto.randomBytes(16).toString('hex');
        const salt = crypto.randomBytes(16).toString('hex');
        const pwHash = hashPassword(String(password), salt);
        const user = {
          id,
          email: String(email),
          name: name ? String(name) : '',
          phone: phone ? String(phone) : '',
          address: address ? String(address) : '',
          profilePic: typeof profilePic === 'string' ? profilePic : '',
          salt,
          pwHash,
          createdAt: new Date().toISOString(),
        };
        users.push(user);
        saveUsers(users);
        console.log(`NEW SIGNUP: ${email} (${name})`);
        const sessionToken = makeSessionToken(id);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `session=${encodeURIComponent(sessionToken)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60*60*24*7}`,
        });
        res.end(JSON.stringify({ ok: true, user: { id, email: user.email, name: user.name, phone: user.phone || '', address: user.address || '', profilePic: user.profilePic }, isAdmin: isAdminUser(user) }));
      } catch {
        jsonBad(res, 400, 'Signup failed');
      }
    })();
    return;
  }

  if (req.method === 'POST' && req.url.split('?')[0] === '/api/auth/login') {
    (async () => {
      try {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody || '{}');
        const { email, password } = body;
        if (!email || !password) return jsonBad(res, 400, 'Email and password required');
        const users = loadUsers();
        const user = users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
        if (!user) return jsonBad(res, 401, 'Invalid credentials');
        const pwHash = hashPassword(String(password), user.salt);
        if (pwHash !== user.pwHash) return jsonBad(res, 401, 'Invalid credentials');
        const sessionToken = makeSessionToken(user.id);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `session=${encodeURIComponent(sessionToken)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60*60*24*7}`,
        });
        res.end(JSON.stringify({ ok: true, user: { id: user.id, email: user.email, name: user.name, profilePic: user.profilePic || '' }, isAdmin: isAdminUser(user) }));
      } catch (err) {
        console.error('Login error:', err);
        jsonBad(res, 400, err?.message || 'Login failed');
      }
    })();
    return;
  }

  if (req.method === 'POST' && req.url.split('?')[0] === '/api/auth/profile') {
    const session = getSession(req);
    if (!session) return jsonBad(res, 401, 'Not logged in');

    (async () => {
      try {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody || '{}');
        const { name, phone, address, profilePic } = body;
        const users = loadUsers();
        const idx = users.findIndex(u => u.id === session.userId);
        if (idx < 0) return jsonBad(res, 401, 'Invalid session');

        if (typeof name === 'string') users[idx].name = String(name).trim();
        if (typeof profilePic === 'string') users[idx].profilePic = profilePic;
        if (typeof phone === 'string') users[idx].phone = String(phone).trim();
        if (typeof address === 'string') users[idx].address = String(address).trim();
        saveUsers(users);

        const user = users[idx];
        return sendJson(res, 200, {
          ok: true,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            phone: user.phone || '',
            address: user.address || '',
            profilePic: user.profilePic || '',
          },
          isAdmin: isAdminUser(user),
        });
      } catch (err) {
        console.error('Profile update error:', err);
        return jsonBad(res, 400, 'Could not update profile');
      }
    })();
    return;
  }

  if (req.method === 'GET' && req.url.split('?')[0] === '/api/auth/me') {
    const session = getSession(req);
    if (!session) return sendJson(res, 200, { ok: true, user: null, isAdmin: false });
    const users = loadUsers();
    const user = users.find(u => u.id === session.userId) || null;
    return sendJson(res, 200, {
      ok: true,
      user: user ? { id: user.id, email: user.email, name: user.name, profilePic: user.profilePic || '' } : null,
      isAdmin: user ? isAdminUser(user) : false,
    });
  }

  if ((req.method === 'POST' || req.method === 'GET') && req.url.split('?')[0] === '/api/auth/logout') {
    // Accept both POST and GET to avoid frontend/network/proxy mismatches.
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Set-Cookie': 'session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0',
    });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (req.method === 'GET' && req.url.split('?')[0] === '/api/orders/me') {
    const session = getSession(req);
    if (!session) return jsonBad(res, 401, 'Not logged in');
    const ordersFilePath = ordersFile;
    let orders = [];
    if (fs.existsSync(ordersFilePath)) {
      orders = JSON.parse(fs.readFileSync(ordersFilePath, 'utf8') || '[]');
    }
    const mine = orders.filter(o => o.userId === session.userId);
    return sendJson(res, 200, { ok: true, orders: mine });
  }

  // (Public orders read is available below; keep routing order clean.)
  if (req.method === 'GET' && req.url.split('?')[0].startsWith('/api/orders/track/')) {
    const urlPath = req.url.split('?')[0];
    const reference = urlPath.split('/api/orders/track/')[1];
    if (!reference) return jsonBad(res, 400, 'Reference required');

    const orders = ordersLoad();
    const order = orders.find(o => String(o.reference) === String(reference) || String(o.id) === String(reference));
    if (!order) return jsonBad(res, 404, 'Order not found');

    return sendJson(res, 200, { ok: true, status: order.status || 'Pending' });
  }

  if (req.method === 'GET' && req.url.split('?')[0] === '/api/orders') {
    let orders = [];
    if (fs.existsSync(ordersFile)) {
      orders = JSON.parse(fs.readFileSync(ordersFile, 'utf8') || '[]');
    }
    sendJson(res, 200, { ok: true, orders });
    return;
  }

  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  const requested = urlPath === '/' ? '/index.html' : urlPath;
  const filePath = path.normalize(path.join(root, requested));

  if (!filePath.startsWith(root)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    res.writeHead(200, {
      'Content-Type': types[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
    });
    res.end(data);
  });
  });
}

function bindServer(portToTry) {
  const server = createServer();
  server.once('error', err => {
    if (err.code === 'EADDRINUSE' && portToTry < maxPort) {
      const nextPort = portToTry + 1;
      console.warn(`Port ${portToTry} is in use. Trying ${nextPort}...`);
      bindServer(nextPort);
      return;
    }

    console.error('Server startup error:', err);
    process.exit(1);
  });

  server.listen(portToTry, () => {
  console.log(`Crossed Classic running on port ${portToTry}`);
 }); 
}

bindServer(basePort);
