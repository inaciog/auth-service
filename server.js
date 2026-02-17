/**
 * Unified Auth Service - Simplified
 * 
 * Simple token-based auth. No cookies, no localStorage.
 * Token passed via URL parameter only.
 * 
 * Flow:
 * 1. User goes to app (e.g., dashboard)
 * 2. App checks for ?token=xxx in URL
 * 3. If no token, redirect to /login?returnTo=app-url
 * 4. User enters password
 * 5. Auth service redirects back with ?token=xxx
 * 6. App extracts token and uses it for API calls
 * 
 * @author Inacio Bo
 */

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'i486983nacio:!';

// In-memory user permissions
const userPermissions = new Map();

app.use(express.json());

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ============================================================================
// Login Page
// ============================================================================

app.get('/login', (req, res) => {
  const returnTo = req.query.returnTo || 'https://inacio-dashboard.fly.dev';
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          background: #000;
          color: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
        }
        .card {
          background: #1c1c1e;
          padding: 40px;
          border-radius: 16px;
          width: 100%;
          max-width: 320px;
          text-align: center;
        }
        h1 { margin-bottom: 20px; }
        input {
          width: 100%;
          padding: 14px;
          margin: 10px 0;
          border: none;
          border-radius: 10px;
          background: #2c2c2e;
          color: #fff;
          font-size: 16px;
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
        .error { color: #ff453a; margin-top: 10px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔐 Login</h1>
        <form id="loginForm">
          <input type="password" id="password" placeholder="Enter password" autofocus>
          <button type="submit">Sign In</button>
        </form>
        <div class="error" id="error"></div>
      </div>
      <script>
        const returnTo = '${returnTo}';
        
        document.getElementById('loginForm').onsubmit = async (e) => {
          e.preventDefault();
          const password = document.getElementById('password').value;
          
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
          });
          
          const data = await res.json();
          
          if (data.token) {
            // Redirect back to app with token
            const separator = returnTo.includes('?') ? '&' : '?';
            window.location.href = returnTo + separator + 'token=' + encodeURIComponent(data.token);
          } else {
            document.getElementById('error').textContent = 'Invalid password';
          }
        };
      </script>
    </body>
    </html>
  `);
});

// ============================================================================
// API
// ============================================================================

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  
  if (password !== MASTER_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  const token = jwt.sign({
    id: 'inacio',
    name: 'Inacio',
    role: 'owner',
    iat: Date.now()
  }, JWT_SECRET, { expiresIn: '30d' });
  
  res.json({ token });
});

app.get('/api/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  
  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ 
      valid: true, 
      user: decoded,
      permissions: userPermissions.get(decoded.id) || ['read', 'write']
    });
  } catch (err) {
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
});

// ============================================================================
// Start
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Auth service on port ${PORT}`);
});

// Export for other apps
module.exports = { JWT_SECRET };
