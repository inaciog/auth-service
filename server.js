/**
 * Unified Auth Service
 * 
 * Central authentication for all personal apps.
 * Sets a shared cookie that all apps can verify.
 * 
 * @author Inacio Bo
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const COOKIE_NAME = 'auth_session';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '.fly.dev'; // Shared across all .fly.dev subdomains
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'i486983nacio:!';

// In-memory user permissions (for future extension)
const userPermissions = new Map();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// CORS headers for cross-app communication
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ============================================================================
// Auth Middleware (for use in other apps)
// ============================================================================

function verifyAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME] || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      loginUrl: `https://auth.${COOKIE_DOMAIN.replace(/^\./, '')}/login`
    });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie(COOKIE_NAME, { domain: COOKIE_DOMAIN });
    return res.status(401).json({ 
      error: 'Invalid session',
      loginUrl: `https://auth.${COOKIE_DOMAIN.replace(/^\./, '')}/login`
    });
  }
}

// ============================================================================
// Routes
// ============================================================================

/** GET / - Check auth status */
app.get('/', (req, res) => {
  // Try to get token from cookie or query param (for cross-domain auth)
  let token = req.cookies[COOKIE_NAME] || req.query.token;
  
  if (!token) {
    return res.redirect('/login');
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Auth Service</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #000;
            color: #fff;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
          }
          .card {
            background: #1c1c1e;
            padding: 40px;
            border-radius: 16px;
            text-align: center;
            max-width: 400px;
          }
          h1 { margin-top: 0; }
          .status {
            color: #30d158;
            font-size: 48px;
            margin: 20px 0;
          }
          .apps {
            margin-top: 30px;
          }
          .app-link {
            display: block;
            padding: 12px 20px;
            background: #0a84ff;
            color: white;
            text-decoration: none;
            border-radius: 10px;
            margin: 10px 0;
          }
          .logout {
            margin-top: 20px;
            color: #ff453a;
            text-decoration: none;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="status">✓</div>
          <h1>Authenticated</h1>
          <p>Welcome back, ${decoded.name || 'Inacio'}!</p>
          <div class="apps">
            <a class="app-link" href="https://reminders-app.fly.dev?token=${token}">Reminders</a>
            <a class="app-link" href="https://classquizzes.fly.dev?token=${token}">ClassQuizzes</a>
          </div>
          <a class="logout" href="/logout">Logout</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.redirect('/login');
  }
});

/** GET /login - Login page */
app.get('/login', (req, res) => {
  const returnTo = req.query.returnTo || '';
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          background: #000;
          color: #fff;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
        }
        .card {
          background: #1c1c1e;
          padding: 40px;
          border-radius: 16px;
          width: 100%;
          max-width: 320px;
        }
        h1 { margin-top: 0; text-align: center; }
        input {
          width: 100%;
          padding: 14px;
          margin: 10px 0;
          border: none;
          border-radius: 10px;
          background: #2c2c2e;
          color: #fff;
          font-size: 16px;
          box-sizing: border-box;
        }
        button {
          width: 100%;
          padding: 14px;
          margin-top: 10px;
          border: none;
          border-radius: 10px;
          background: #0a84ff;
          color: #fff;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
        }
        .error {
          color: #ff453a;
          text-align: center;
          margin-top: 10px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔐 Login</h1>
        <form id="loginForm">
          <input type="password" id="password" placeholder="Enter password" autofocus>
          <input type="hidden" id="returnTo" value="${returnTo}">
          <button type="submit">Sign In</button>
        </form>
        <div class="error" id="error"></div>
      </div>
      <script>
        document.getElementById('loginForm').onsubmit = async (e) => {
          e.preventDefault();
          const password = document.getElementById('password').value;
          const returnTo = document.getElementById('returnTo').value;
          
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, returnTo })
          });
          
          const data = await res.json();
          
          if (data.success) {
            window.location.href = data.redirect || '/';
          } else {
            document.getElementById('error').textContent = 'Invalid password';
          }
        };
      </script>
    </body>
    </html>
  `);
});

/** POST /api/login - Authenticate */
app.post('/api/login', (req, res) => {
  const { password, returnTo } = req.body;
  
  if (password !== MASTER_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  // Create JWT token
  const token = jwt.sign({
    id: 'inacio',
    name: 'Inacio',
    role: 'owner',
    iat: Date.now()
  }, JWT_SECRET, { expiresIn: '30d' });
  
  // Set cookie (shared across subdomains)
  res.cookie(COOKIE_NAME, token, {
    domain: COOKIE_DOMAIN,
    httpOnly: true,
    secure: true,
    sameSite: 'none',  // Required for cross-subdomain sharing
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });
  
  res.json({ 
    success: true, 
    redirect: returnTo || '/',
    token: token  // Also return token for apps that need it
  });
});

/** GET /logout - Clear session */
app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { domain: COOKIE_DOMAIN, sameSite: 'none', secure: true });
  res.redirect('/login');
});

/** GET /api/verify - Verify token (for other apps to call) */
app.get('/api/verify', (req, res) => {
  const token = req.cookies[COOKIE_NAME] || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ valid: false });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ 
      valid: true, 
      user: decoded,
      permissions: userPermissions.get(decoded.id) || ['read', 'write']
    });
  } catch (err) {
    res.status(401).json({ valid: false });
  }
});

/** POST /api/grant - Grant permissions to a user (owner only) */
app.post('/api/grant', verifyAuth, (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only owner can grant permissions' });
  }
  
  const { userId, permissions } = req.body;
  userPermissions.set(userId, permissions);
  
  res.json({ success: true });
});

// ============================================================================
// Start Server
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Auth service on port ${PORT}`);
});

// Export middleware for use in other apps
module.exports = { verifyAuth, COOKIE_NAME, JWT_SECRET };
