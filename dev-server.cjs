require('dotenv').config();

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* =========================
   PATHS
========================= */

const root = __dirname;

// safer folder name handling
const staticRoot = path.join(root, '..', 'crossed classic');

console.log('ROOT:', root);
console.log('STATIC ROOT:', staticRoot);
console.log('STATIC EXISTS:', fs.existsSync(staticRoot));

/* =========================
   CONFIG
========================= */

const PORT = Number(process.env.PORT || 8000);

const isProduction =
  process.env.NODE_ENV === 'production';

const frontendOrigin =
  String(process.env.FRONTEND_ORIGIN || '').trim();

const adminEmail =
  String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

const usersFile =
  path.join(root, 'users.json');

const ordersFile =
  path.join(root, 'orders.json');

const authSessionSecret =
  process.env.AUTH_SESSION_SECRET ||
  'CHANGE_ME_SESSION_SECRET';

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

function parseCookies(cookieHeader) {
  const out = {};

  if (!cookieHeader) return out;

  cookieHeader
    .split(';')
    .forEach(part => {
      const [k, ...rest] =
        part.trim().split('=');

      if (!k) return;

      out[k] =
        decodeURIComponent(
          rest.join('=') || ''
        );
    });

  return out;
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type':
      'application/json; charset=utf-8',
  });

  res.end(JSON.stringify(payload));
}

function jsonBad(res, status, message) {
  sendJson(res, status, {
    ok: false,
    error: message,
  });
}

/* =========================
   CORS
========================= */

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;

  const allowedOrigins = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',

    'https://crossedclassic-ng-q1uy.vercel.app',
    'https://crossedclassic-ng.vercel.app',
    'https://crossedclassic-ng-git-main-femi-og.vercel.app',
  ];

  if (frontendOrigin) {
    allowedOrigins.push(frontendOrigin);
  }

  if (
    origin &&
    allowedOrigins.includes(origin)
  ) {
    res.setHeader(
      'Access-Control-Allow-Origin',
      origin
    );
  }

  res.setHeader('Vary', 'Origin');

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  res.setHeader(
    'Access-Control-Allow-Credentials',
    'true'
  );

  res.setHeader(
    'Access-Control-Max-Age',
    '86400'
  );
}

function sessionCookie(token, maxAge) {
  const sameSite = isProduction
    ? 'SameSite=None; Secure'
    : 'SameSite=Lax';

  return (
    `session=${encodeURIComponent(token)}; ` +
    `HttpOnly; Path=/; ${sameSite}; Max-Age=${maxAge}`
  );
}

function readBody(req) {
  return new Promise((resolve, reject) => {

    let body = '';

    req.on('data', chunk => {
      body += chunk;

      if (body.length > 1_000_000) {
        req.destroy();
        reject(
          new Error('Body too large')
        );
      }
    });

    req.on('end', () => {
      resolve(body);
    });

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
      fs.readFileSync(
        usersFile,
        'utf8'
      ) || '[]'
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

    const staticUsersFile =
      path.join(
        staticRoot,
        'users.json'
      );

    fs.writeFileSync(
      staticUsersFile,
      JSON.stringify(users, null, 2)
    );

  } catch (err) {
    console.error(
      'STATIC USER SAVE ERROR:',
      err
    );
  }
}

function loadOrders() {

  if (!fs.existsSync(ordersFile)) {
    return [];
  }

  try {
    return JSON.parse(
      fs.readFileSync(
        ordersFile,
        'utf8'
      ) || '[]'
    );
  } catch {
    return [];
  }
}

function saveOrders(orders) {

  fs.writeFileSync(
    ordersFile,
    JSON.stringify(orders, null, 2)
  );

  try {

    const staticOrdersFile =
      path.join(
        staticRoot,
        'orders.json'
      );

    fs.writeFileSync(
      staticOrdersFile,
      JSON.stringify(orders, null, 2)
    );

  } catch (err) {
    console.error(
      'STATIC ORDER SAVE ERROR:',
      err
    );
  }
}

/* =========================
   SESSION
========================= */

function makeSessionToken(userId) {

  const payload = {
    userId,
    exp:
      Date.now() +
      1000 * 60 * 60 * 24 * 7,
  };

  const payloadJson =
    JSON.stringify(payload);

  const payloadB64 =
    Buffer
      .from(payloadJson, 'utf8')
      .toString('base64');

  const sig = sign(payloadB64);

  return `${payloadB64}.${sig}`;
}

function getSession(req) {

  try {

    const cookies =
      parseCookies(req.headers.cookie);

    const token =
      cookies.session;

    if (!token) {
      return null;
    }

    const [payloadB64, sig] =
      token.split('.');

    if (!payloadB64 || !sig) {
      return null;
    }

    const expected =
      sign(payloadB64);

    if (sig !== expected) {
      return null;
    }

    const payloadJson =
      Buffer
        .from(payloadB64, 'base64')
        .toString('utf8');

    const payload =
      JSON.parse(payloadJson);

    if (
      !payload.userId ||
      !payload.exp
    ) {
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
   STATIC TYPES
========================= */

const types = {
  '.html':
    'text/html; charset=utf-8',

  '.css':
    'text/css; charset=utf-8',

  '.js':
    'text/javascript; charset=utf-8',

  '.png':
    'image/png',

  '.jpg':
    'image/jpeg',

  '.jpeg':
    'image/jpeg',

  '.svg':
    'image/svg+xml',
};

/* =========================
   SERVER
========================= */

const server =
  http.createServer(
    async (req, res) => {

      setCorsHeaders(req, res);

      /* =========================
         OPTIONS
      ========================= */

      if (req.method === 'OPTIONS') {
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

          const rawBody =
            await readBody(req);

          const body =
            JSON.parse(rawBody || '{}');

          const email =
            normalizeEmail(body.email);

          const password =
            String(
              body.password || ''
            ).trim();

          const name =
            String(
              body.name || ''
            ).trim();

          if (!email) {
            return jsonBad(
              res,
              400,
              'Email is required'
            );
          }

          if (!password) {
            return jsonBad(
              res,
              400,
              'Password is required'
            );
          }

          const users =
            loadUsers();

          const existing =
            users.find(
              u =>
                normalizeEmail(u.email)
                === email
            );

          if (existing) {
            return jsonBad(
              res,
              409,
              'User already exists'
            );
          }

          const salt =
            crypto
              .randomBytes(16)
              .toString('hex');

          const pwHash =
            hashPassword(
              password,
              salt
            );

          const user = {
            id:
              'u_' +
              crypto
                .randomBytes(16)
                .toString('hex'),

            email,
            name,
            salt,
            pwHash,

            createdAt:
              new Date()
                .toISOString(),
          };

          users.push(user);

          saveUsers(users);

          const sessionToken =
            makeSessionToken(user.id);

          const isAdmin =
            adminEmail &&
            normalizeEmail(user.email) ===
            adminEmail;

          res.writeHead(200, {
            'Content-Type':
              'application/json',

            'Set-Cookie':
              sessionCookie(
                sessionToken,
                60 * 60 * 24 * 7
              ),
          });

          res.end(
            JSON.stringify({
              ok: true,
              isAdmin: isAdmin,
              user: {
                id: user.id,
                email: user.email,
                name: user.name,
                isAdmin: isAdmin,
              },
            })
          );

        } catch (err) {

          console.error(
            'SIGNUP ERROR:',
            err
          );

          jsonBad(
            res,
            500,
            'Internal server error'
          );
        }

        return;
      }

      /* =========================
         LOGIN
      ========================= */

      if (
        req.method === 'POST' &&
        req.url === '/api/auth/login'
      ) {

        try {

          const rawBody =
            await readBody(req);

          const body =
            JSON.parse(rawBody || '{}');

          const email =
            normalizeEmail(body.email);

          const password =
            String(
              body.password || ''
            ).trim();

          if (!email) {
            return jsonBad(
              res,
              400,
              'Email is required'
            );
          }

          if (!password) {
            return jsonBad(
              res,
              400,
              'Password is required'
            );
          }

          const users =
            loadUsers();

          const user =
            users.find(
              u =>
                normalizeEmail(u.email)
                === email
            );

          if (!user) {
            return jsonBad(
              res,
              401,
              'Invalid credentials'
            );
          }

          const generatedHash =
            hashPassword(
              password,
              user.salt
            );

          if (
            generatedHash !==
            user.pwHash
          ) {
            return jsonBad(
              res,
              401,
              'Invalid credentials'
            );
          }

          const isAdmin =
            adminEmail &&
            normalizeEmail(user.email) ===
            adminEmail;

          const sessionToken =
            makeSessionToken(user.id);

          res.writeHead(200, {
            'Content-Type':
              'application/json',

            'Set-Cookie':
              sessionCookie(
                sessionToken,
                60 * 60 * 24 * 7
              ),
          });

          res.end(
            JSON.stringify({
              ok: true,
              isAdmin: isAdmin,
              user: {
                id: user.id,
                email: user.email,
                name: user.name,
                isAdmin: isAdmin,
              },
            })
          );

        } catch (err) {

          console.error(
            'LOGIN ERROR:',
            err
          );

          jsonBad(
            res,
            500,
            'Internal server error'
          );
        }

        return;
      }

      /* =========================
         CURRENT USER
      ========================= */

      if (
        req.method === 'GET' &&
        req.url === '/api/auth/me'
      ) {

        const session =
          getSession(req);

        if (!session) {

          return sendJson(
            res,
            200,
            {
              ok: true,
              user: null,
            }
          );
        }

        const users =
          loadUsers();

        const user =
          users.find(
            u =>
              u.id ===
              session.userId
          );

        const isAdmin =
          user &&
          adminEmail &&
          normalizeEmail(user.email) ===
          adminEmail;

        return sendJson(
          res,
          200,
          {
            ok: true,
            isAdmin: isAdmin || false,

            user:
              user
                ? {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    isAdmin: isAdmin,
                  }
                : null,
          }
        );
      }

      /* =========================
         LOGOUT
      ========================= */

      if (
        req.method === 'POST' &&
        req.url === '/api/auth/logout'
      ) {

        res.writeHead(200, {
          'Content-Type':
            'application/json',

          'Set-Cookie':
            sessionCookie('', 0),
        });

        res.end(
          JSON.stringify({
            ok: true,
          })
        );

        return;
      }

      /* =========================
         STATIC FILES
      ========================= */

      const urlPath =
        decodeURIComponent(
          req.url.split('?')[0]
        );

      const requested =
        urlPath === '/'
          ? '/index.html'
          : urlPath;

      let filePath =
        path.join(
          staticRoot,
          requested
        );

      if (
        !fs.existsSync(filePath)
      ) {
        filePath =
          path.join(
            root,
            requested
          );
      }

      fs.readFile(
        filePath,
        (err, data) => {

          if (err) {
            res.writeHead(404);
            res.end('Not found');
            return;
          }

          res.writeHead(200, {
            'Content-Type':
              types[
                path
                  .extname(filePath)
                  .toLowerCase()
              ] ||
              'application/octet-stream',
          });

          res.end(data);
        }
      );
    }
  );

/* =========================
   START SERVER
========================= */

server.listen(PORT, () => {
  console.log(
    `Crossed Classic running on port ${PORT}`
  );
});