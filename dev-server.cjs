require('dotenv').config();

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const staticRoot = path.resolve(root, '..', 'crossed classic');

const PORT = Number(process.env.PORT || 8000);
const isProduction = process.env.NODE_ENV === 'production';
const frontendOrigin = String(process.env.FRONTEND_ORIGIN || '').trim();

const usersFile = path.join(root, 'users.json');
const ordersFile = path.join(root, 'orders.json');

const authSessionSecret =
  process.env.AUTH_SESSION_SECRET || 'CHANGE_ME_SESSION_SECRET';

/* =========================
   HELPERS
========================= */

function base64url(input) {
  return Buffer
    .from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function sign(data) {
  return base64url(
    crypto
      .createHmac('sha256', authSessionSecret)
      .update(data)
      .digest()
  );
}

function hashPassword(password, salt) {
  return crypto
    .createHmac('sha256', salt)
    .update(password)
    .digest('hex');
}

function normalizeEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase();
}

function getAdminEmail() {
  return normalizeEmail(process.env.ADMIN_EMAIL);
}

function isAdminUser(user) {
  const adminEmail = getAdminEmail();
  return Boolean(user && adminEmail && normalizeEmail(user.email) === adminEmail);
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

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
  });

  res.end(JSON.stringify(payload));
}

function jsonBad(res, status, message) {
  sendJson(res, status, {
    ok: false,
    error: message,
  });
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  
  // Define allowed origins
  const allowedOrigins = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'https://crossedclassic-ng-q1uy.vercel.app',
    'https://crossedclassic-ng.vercel.app',
    'https://crossedclassic-ng-git-main-femi-og.vercel.app',
    frontendOrigin
  ].filter(Boolean);

  // Check if origin is allowed
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (origin && !frontendOrigin) {
    // Allow any origin in development
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400'); // Cache preflight for 24 hours
}

function sessionCookie(token, maxAge) {
  const sameSite = isProduction ? 'SameSite=None; Secure' : 'SameSite=Lax';
  return `session=${encodeURIComponent(token)}; HttpOnly; Path=/; ${sameSite}; Max-Age=${maxAge}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', chunk => {
      body += chunk;

      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Body too large'));
      }
    });

    req.on('end', () => resolve(body));

    req.on('error', reject);
  });
}

/* =========================
   USERS
========================= */

function loadUsers() {
  if (!fs.existsSync(usersFile)) {
    return [];
  }

  try {
    return JSON.parse(
      fs.readFileSync(usersFile, 'utf8') || '[]'
    );
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(
    usersFile,
    JSON.stringify(users, null, 2)
  );

  try {
    const staticUsersFile = path.join(staticRoot, 'users.json');
    fs.writeFileSync(staticUsersFile, JSON.stringify(users, null, 2));
  } catch (err) {
    // Non-fatal: continue if unable to write to static copy
  }
}

function loadOrders() {
  if (!fs.existsSync(ordersFile)) return [];
  try { return JSON.parse(fs.readFileSync(ordersFile, 'utf8') || '[]'); } catch { return []; }
}

function saveOrders(orders) {
  try {
    fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
  } catch (err) {
    // ignore
  }
}

/* =========================
   SESSION
========================= */

function makeSessionToken(userId) {
  const payload = {
    userId,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
  };

  const payloadJson = JSON.stringify(payload);

  const payloadB64 = Buffer
    .from(payloadJson, 'utf8')
    .toString('base64');

  const sig = sign(payloadB64);

  return `${payloadB64}.${sig}`;
}

function getSession(req) {
  try {
    const cookies = parseCookies(req.headers.cookie);

    const token = cookies.session;

    if (!token) return null;

    const [payloadB64, sig] = token.split('.');

    if (!payloadB64 || !sig) return null;

    const expected = sign(payloadB64);

    if (sig !== expected) return null;

    const payloadJson = Buffer
      .from(payloadB64, 'base64')
      .toString('utf8');

    const payload = JSON.parse(payloadJson);

    if (!payload.userId || !payload.exp) {
      return null;
    }

    if (Date.now() > payload.exp) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}

/* =========================
   STATIC FILE TYPES
========================= */

const types = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

/* =========================
   SERVER
========================= */

const server = http.createServer(async (req, res) => {

  setCorsHeaders(req, res);

  /* =========================
     OPTIONS (CORS Preflight)
  ========================= */

  if (req.method === 'OPTIONS') {
    // Set CORS headers for the preflight response
    const origin = req.headers.origin;
    const allowedOrigins = [
      'http://localhost:8000',
      'http://127.0.0.1:8000',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'https://crossedclassic-ng-q1uy.vercel.app',
      'https://crossedclassic-ng.vercel.app',
      'https://crossedclassic-ng-git-main-femi-og.vercel.app',
      frontendOrigin
    ].filter(Boolean);
    
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Requested-With');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    res.writeHead(204);
    res.end();
    return;
  }

  /* =========================
     SIGNUP
  ========================= */

  if (
    req.method === 'POST' &&
    req.url === '/api/auth/signup'
  ) {

    try {

      const rawBody = await readBody(req);

      const body = JSON.parse(rawBody || '{}');

      const email = normalizeEmail(body.email);
      const password = String(body.password || '').trim();

      const name = String(body.name || '').trim();
      const phone = String(body.phone || '').trim();
      const address = String(body.address || '').trim();

      if (!email || !password) {
        return jsonBad(
          res,
          400,
          'Email and password required'
        );
      }

      const users = loadUsers();

      const existing = users.find(
        u => normalizeEmail(u.email) === email
      );

      if (existing) {
        return jsonBad(
          res,
          409,
          'User already exists'
        );
      }

      const salt =
        crypto.randomBytes(16).toString('hex');

      const pwHash =
        hashPassword(password, salt);

      const user = {
        id: 'u_' + crypto.randomBytes(16).toString('hex'),
        email,
        name,
        phone: phone || '',
        address: address || '',
        profilePic: '',
        salt,
        pwHash,
        createdAt: new Date().toISOString(),
      };

      users.push(user);

      saveUsers(users);

      console.log('NEW USER:', email);

      const sessionToken =
        makeSessionToken(user.id);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': sessionCookie(sessionToken, 60 * 60 * 24 * 7),
      });

      res.end(JSON.stringify({
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      }));

    } catch (err) {

      console.error('SIGNUP ERROR:', err);

      jsonBad(res, 400, 'Signup failed');
    }

    return;
  }

  /* 
     Login
   */

  if (
    req.method === 'POST' &&
    req.url === '/api/auth/login'
  ) {

    try {

      const rawBody = await readBody(req);

      const body = JSON.parse(rawBody || '{}');

      const email =
        normalizeEmail(body.email);

      const password =
        String(body.password || '').trim();

      console.log('LOGIN ATTEMPT:', {
        email,
      });

      if (!email || !password) {
        return jsonBad(
          res,
          400,
          'Email and password required'
        );
      }

      const users = loadUsers();

      const user = users.find(
        u => normalizeEmail(u.email) === email
      );

      console.log(
        'FOUND USER:',
        !!user
      );

      if (!user) {
        return jsonBad(
          res,
          401,
          'Invalid credentials'
        );
      }

      const generatedHash =
        hashPassword(password, user.salt);

      console.log(
        'PASSWORD MATCH:',
        generatedHash === user.pwHash
      );

      if (generatedHash !== user.pwHash) {
        return jsonBad(
          res,
          401,
          'Invalid credentials'
        );
      }

      const sessionToken =
        makeSessionToken(user.id);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': sessionCookie(sessionToken, 60 * 60 * 24 * 7),
      });

      res.end(JSON.stringify({
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      }));

    } catch (err) {

      console.error('LOGIN ERROR:', err);

      jsonBad(res, 400, 'Login failed');
    }

    return;
  }

  /* 
     Current User
   */

  if (
    req.method === 'GET' &&
    req.url === '/api/auth/me'
  ) {

    const session = getSession(req);

    if (!session) {
      return sendJson(res, 200, {
        ok: true,
        user: null,
      });
    }

    const users = loadUsers();

    const user = users.find(
      u => u.id === session.userId
    );

    return sendJson(res, 200, {
      ok: true,
      user: user
        ? {
            id: user.id,
            email: user.email,
            name: user.name,
            phone: user.phone || '',
            address: user.address || '',
            profilePic: user.profilePic || '',
          }
        : null,
      isAdmin: isAdminUser(user),
    });
  }

  /* 
     Logout
  */

  if (
    req.method === 'POST' &&
    req.url === '/api/auth/logout'
  ) {

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': sessionCookie('', 0),
    });

    res.end(JSON.stringify({
      ok: true,
    }));

    return;
  }

  /*
     Update profile
  */
  if (
    req.method === 'POST' &&
    req.url === '/api/auth/profile'
  ) {
    try {
      const session = getSession(req);
      if (!session) return jsonBad(res, 401, 'Not authenticated');

      const rawBody = await readBody(req);
      const body = JSON.parse(rawBody || '{}');

      const users = loadUsers();
      const user = users.find(u => u.id === session.userId);
      if (!user) return jsonBad(res, 404, 'User not found');

      user.name = String(body.name || user.name || '');
      user.phone = String(body.phone || user.phone || '');
      user.address = String(body.address || user.address || '');
      if (body.profilePic) user.profilePic = String(body.profilePic);

      saveUsers(users);

      return sendJson(res, 200, { ok: true });
    } catch (err) {
      console.error('PROFILE SAVE ERROR:', err);
      return jsonBad(res, 400, 'Could not save profile');
    }
  }

  /*
     Orders endpoint
  */
  if (
    req.method === 'POST' &&
    req.url === '/api/orders'
  ) {
    try {
      const session = getSession(req);
      const users = loadUsers();
      const user = session ? users.find(u => u.id === session.userId) : null;

      const rawBody = await readBody(req);
      const body = JSON.parse(rawBody || '{}');

      const { reference, items, total, delivery } = body;
      if (!reference || !Array.isArray(items) || typeof total !== 'number') {
        return jsonBad(res, 400, 'Invalid order');
      }

      const order = {
        id: 'o_' + crypto.randomBytes(12).toString('hex'),
        reference,
        items,
        total,
        delivery: delivery || {},
        userId: user ? user.id : undefined,
        userEmail: user ? user.email : undefined,
        createdAt: new Date().toISOString(),
      };

      const orders = loadOrders();
      orders.push(order);
      saveOrders(orders);

      try {
        const staticOrdersFile = path.join(staticRoot, 'orders.json');
        fs.writeFileSync(staticOrdersFile, JSON.stringify(orders, null, 2));
      } catch (err) {}

      return sendJson(res, 200, { ok: true, order });
    } catch (err) {
      console.error('ORDER SAVE ERROR:', err);
      return jsonBad(res, 400, 'Could not save order');
    }
  }

  /* 
     Track Order
  */
  if (req.method === 'GET' && req.url === '/api/orders/my') {
    try {
      const session = getSession(req);
      if (!session) return jsonBad(res, 401, 'Not authenticated');

      const orders = loadOrders();
      const myOrders = orders.filter(
        o => String(o.userId || '') === String(session.userId)
      );

      return sendJson(res, 200, {
        ok: true,
        orders: myOrders,
      });
    } catch (err) {
      console.error('MY ORDERS ERROR:', err);
      return jsonBad(res, 400, 'Could not fetch orders');
    }
  }

  const trackMatch = req.url.match(/^\/api\/orders\/track\/(.+)$/);
  if (req.method === 'GET' && trackMatch) {
    try {
      const reference = decodeURIComponent(trackMatch[1]);
      const orders = loadOrders();
      const order = orders.find(o => o.reference === reference);

      if (!order) {
        return jsonBad(res, 404, 'Order not found');
      }

      return sendJson(res, 200, {
        ok: true,
        status: order.status || 'Confirmed',
        order: {
          reference: order.reference,
          status: order.status || 'Confirmed',
          items: order.items,
          total: order.total,
          delivery: order.delivery,
          createdAt: order.createdAt,
        },
      });
    } catch (err) {
      console.error('TRACK ERROR:', err);
      return jsonBad(res, 400, 'Could not fetch order');
    }
  }

  /*
     Admin endpoints: list orders and update status/notes
   */
  if (req.method === 'GET' && req.url === '/api/orders/admin') {
    try {
      const session = getSession(req);
      if (!session) return jsonBad(res, 401, 'Not authenticated');

      const users = loadUsers();
      const user = users.find(u => u.id === session.userId);
      const isAdmin = isAdminUser(user);
      if (!isAdmin) return jsonBad(res, 403, 'Forbidden');

      const orders = loadOrders();
      return sendJson(res, 200, { ok: true, orders });
    } catch (err) {
      console.error('ADMIN LIST ERROR:', err);
      return jsonBad(res, 400, 'Could not load orders');
    }
  }

  const adminUpdateMatch = req.url.match(/^\/api\/orders\/(.+)\/admin\/status$/);
  if (req.method === 'POST' && adminUpdateMatch) {
    try {
      const session = getSession(req);
      if (!session) return jsonBad(res, 401, 'Not authenticated');

      const users = loadUsers();
      const user = users.find(u => u.id === session.userId);
      const isAdmin = isAdminUser(user);
      if (!isAdmin) return jsonBad(res, 403, 'Forbidden');

      const rawBody = await readBody(req);
      const body = JSON.parse(rawBody || '{}');
      const status = String(body.status || '').trim();
      const adminReview = String(body.adminReview || body.adminNotes || '').trim();

      const ref = decodeURIComponent(adminUpdateMatch[1]);
      const orders = loadOrders();
      const idx = orders.findIndex(o => String(o.reference) === String(ref) || String(o.id) === String(ref));
      if (idx === -1) return jsonBad(res, 404, 'Order not found');

      orders[idx].status = status;
      if (adminReview) orders[idx].adminReview = adminReview;
      orders[idx].updatedAt = new Date().toISOString();

      saveOrders(orders);
      try { fs.writeFileSync(path.join(staticRoot, 'orders.json'), JSON.stringify(orders, null, 2)); } catch (e) {}

      return sendJson(res, 200, { ok: true, order: orders[idx] });
    } catch (err) {
      console.error('ADMIN UPDATE ERROR:', err);
      return jsonBad(res, 400, 'Could not update order');
    }
  }

  if (req.method === 'GET' && req.url === '/api/orders/admin/summary') {
    try {
      const session = getSession(req);
      if (!session) return jsonBad(res, 401, 'Not authenticated');

      const users = loadUsers();
      const user = users.find(u => u.id === session.userId);
      if (!isAdminUser(user)) return jsonBad(res, 403, 'Forbidden');

      const orders = loadOrders();
      const countByStatus = status => orders.filter(order => {
        const current = String(order.status || '').trim().toLowerCase();
        if (status === 'pending') return !current || ['pending', 'review', 'unprocessed', 'confirmed'].includes(current);
        if (status === 'shipped') return ['shipped', 'ship', 'in transit'].includes(current);
        if (status === 'delivered') return ['delivered', 'complete', 'completed'].includes(current);
        return current === status;
      }).length;

      const totalRevenue = orders.reduce((sum, order) => sum + Number(order.total || 0), 0);
      const reviewsCount = orders.filter(order => String(order.adminReview || order.adminNotes || '').trim()).length;

      return sendJson(res, 200, {
        ok: true,
        summary: {
          totalOrders: orders.length,
          totalRevenue,
          totalPending: countByStatus('pending'),
          totalProcessing: countByStatus('processing'),
          totalShipped: countByStatus('shipped'),
          totalDelivered: countByStatus('delivered'),
          reviewsCount,
          avgOrderValue: orders.length ? totalRevenue / orders.length : 0,
        },
      });
    } catch (err) {
      console.error('ADMIN SUMMARY ERROR:', err);
      return jsonBad(res, 400, 'Could not load summary');
    }
  }

  /* 
     Static Files
   */

  const urlPath =
    decodeURIComponent(req.url.split('?')[0]);

  const requested =
    urlPath === '/'
      ? '/index.html'
      : urlPath;

  let filePath = path.join(
    staticRoot,
    requested
  );

  if (!fs.existsSync(filePath)) {
    filePath = path.join(root, requested);
  }

  fs.readFile(filePath, (err, data) => {

    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    res.writeHead(200, {
      'Content-Type':
        types[path.extname(filePath).toLowerCase()]
        || 'application/octet-stream',
    });

    res.end(data);
  });

});

/* 
   Start
 */

server.listen(PORT, () => {
  console.log(
    `Crossed Classic running on port ${PORT}`
  );
});