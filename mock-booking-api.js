require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = Number(process.env.PORT || 8787);
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || '15m';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || '7d';
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'replace-this-access-secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'replace-this-refresh-secret';
const CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'finnair-web';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || 'http://localhost:5500/';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';

if (ACCESS_TOKEN_SECRET === 'replace-this-access-secret' || REFRESH_TOKEN_SECRET === 'replace-this-refresh-secret') {
  console.warn('WARNING: Default JWT secrets detected. Set ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET in Railway variables.');
}

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '256kb' }));
app.use(morgan('tiny'));
app.use(cors({
  origin(origin, cb) {
    if (!origin || CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) {
      cb(null, true);
      return;
    }
    cb(new Error('CORS origin denied'));
  }
}));

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

const users = {};

// refreshToken -> username
const refreshTokenStore = new Map();
const discordStateStore = new Map();

function issueAccessToken(username) {
  return jwt.sign({ sub: username, scope: 'bookings avios profile' }, ACCESS_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: ACCESS_TOKEN_TTL,
    issuer: 'finnair-api'
  });
}

function issueRefreshToken(username) {
  const token = jwt.sign({ sub: username, type: 'refresh' }, REFRESH_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: REFRESH_TOKEN_TTL,
    issuer: 'finnair-api'
  });
  refreshTokenStore.set(token, username);
  return token;
}

function issueTokenPair(username) {
  return {
    token_type: 'Bearer',
    access_token: issueAccessToken(username),
    refresh_token: issueRefreshToken(username),
    expires_in: 900,
    scope: 'bookings avios profile'
  };
}

function verifyRefreshToken(token) {
  try {
    const payload = jwt.verify(token, REFRESH_TOKEN_SECRET, { issuer: 'finnair-api' });
    const stored = refreshTokenStore.get(token);
    if (!stored || stored !== payload.sub) return null;
    return payload.sub;
  } catch (_err) {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    res.status(401).json({ error: 'invalid_token' });
    return;
  }
  const token = auth.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET, { issuer: 'finnair-api' });
    req.user = payload.sub;
    next();
  } catch (_err) {
    res.status(401).json({ error: 'invalid_token' });
  }
}

function bookingReference() {
  return 'AY' + crypto.randomBytes(2).toString('hex').toUpperCase();
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function ensureDiscordConfigured() {
  return Boolean(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_REDIRECT_URI);
}

function buildFrontendAuthRedirect(params) {
  const normalizedBase = FRONTEND_BASE_URL.endsWith('/') ? FRONTEND_BASE_URL : (FRONTEND_BASE_URL + '/');
  const url = new URL('login.html', normalizedBase);
  Object.keys(params).forEach(key => {
    if (params[key]) url.searchParams.set(key, params[key]);
  });
  return url.toString();
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'finnair-booking-api' });
});

app.get('/auth/discord/login', (req, res) => {
  if (!ensureDiscordConfigured()) {
    res.status(503).json({ error: 'discord_not_configured' });
    return;
  }

  const returnTo = String(req.query.returnTo || 'account.html');
  const state = crypto.randomBytes(16).toString('hex');
  discordStateStore.set(state, { issuedAt: Date.now(), returnTo });
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: 'identify email',
    state,
    prompt: 'consent'
  });
  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});

app.get('/auth/discord/callback', async (req, res) => {
  const code = String(req.query.code || '');
  const state = String(req.query.state || '');

  if (!ensureDiscordConfigured()) {
    res.redirect(buildFrontendAuthRedirect({ error: 'discord_not_configured' }));
    return;
  }
  const statePayload = discordStateStore.get(state);
  discordStateStore.delete(state);
  if (!code || !statePayload || (Date.now() - statePayload.issuedAt) > 10 * 60 * 1000) {
    res.redirect(buildFrontendAuthRedirect({ error: 'invalid_oauth_state' }));
    return;
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    if (!tokenResponse.ok) {
      res.redirect(buildFrontendAuthRedirect({ error: 'discord_token_exchange_failed' }));
      return;
    }

    const tokenPayload = await tokenResponse.json();
    const discordAccessToken = tokenPayload.access_token;
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: 'Bearer ' + discordAccessToken }
    });

    if (!userResponse.ok) {
      res.redirect(buildFrontendAuthRedirect({ error: 'discord_user_fetch_failed' }));
      return;
    }

    const discordUser = await userResponse.json();
    const email = normalizeEmail(discordUser.email || (discordUser.id + '@discord.local'));

    if (!users[email]) {
      users[email] = {
        avios: 0,
        bookings: []
      };
    }

    const pair = issueTokenPair(email);
    res.redirect(buildFrontendAuthRedirect({
      access_token: pair.access_token,
      refresh_token: pair.refresh_token,
      provider: 'discord',
      returnTo: statePayload.returnTo
    }));
  } catch (_err) {
    res.redirect(buildFrontendAuthRedirect({ error: 'discord_callback_failed' }));
  }
});

app.post('/oauth/token', authLimiter, async (req, res) => {
  const grantType = req.body.grant_type;
  const clientId = req.body.client_id;

  if (clientId && clientId !== CLIENT_ID) {
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (grantType === 'refresh_token') {
    const refreshToken = String(req.body.refresh_token || '');
    const username = verifyRefreshToken(refreshToken);
    if (!username) {
      res.status(401).json({ error: 'invalid_grant' });
      return;
    }

    refreshTokenStore.delete(refreshToken);
    const pair = issueTokenPair(username);
    res.json(pair);
    return;
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

app.post('/oauth/revoke', (req, res) => {
  const refreshToken = String(req.body.refresh_token || '');
  if (refreshToken) {
    refreshTokenStore.delete(refreshToken);
  }
  res.status(204).end();
});

app.get('/api/me/summary', authMiddleware, (req, res) => {
  const user = users[req.user];
  if (!user) {
    res.status(404).json({ error: 'user_not_found' });
    return;
  }
  res.json({ user: req.user, avios: user.avios, bookings: user.bookings.length });
});

app.get('/api/bookings', authMiddleware, (req, res) => {
  const user = users[req.user];
  res.json({ items: user ? user.bookings : [] });
});

app.get('/api/avios', authMiddleware, (req, res) => {
  const user = users[req.user];
  if (!user) {
    res.status(404).json({ error: 'user_not_found' });
    return;
  }
  res.json({ balance: user.avios, tier: 'Silver', nextTierTarget: 20000 });
});

app.post('/api/bookings/simulate', authMiddleware, (req, res) => {
  const user = users[req.user];
  if (!user) {
    res.status(404).json({ error: 'user_not_found' });
    return;
  }

  const item = {
    id: crypto.randomUUID(),
    reference: bookingReference(),
    from: String(req.body.from || 'Unknown'),
    to: String(req.body.to || 'Unknown'),
    tripType: String(req.body.tripType || 'Round trip'),
    depart: String(req.body.depart || ''),
    return: String(req.body.return || ''),
    createdAt: new Date().toISOString()
  };

  user.bookings.unshift(item);
  user.avios += 320;
  res.status(201).json(item);
});

app.use((err, _req, res, _next) => {
  if (String(err.message || '').includes('CORS')) {
    res.status(403).json({ error: 'cors_denied' });
    return;
  }
  console.error(err);
  res.status(500).json({ error: 'internal_server_error' });
});

app.listen(PORT, () => {
  console.log('Finnair OAuth2 API listening on port', PORT);
  console.log('Auth mode: Discord OAuth2 only');
});
