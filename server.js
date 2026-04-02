import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import crypto from 'crypto';

const app = express();

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || '';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '';
const AUTH_STATE_SECRET = process.env.AUTH_STATE_SECRET || '';

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI environment variable.');
  process.exit(1);
}

if (!DISCORD_CLIENT_ID) {
  console.error('Missing DISCORD_CLIENT_ID environment variable.');
  process.exit(1);
}

if (!DISCORD_CLIENT_SECRET) {
  console.error('Missing DISCORD_CLIENT_SECRET environment variable.');
  process.exit(1);
}

if (!DISCORD_REDIRECT_URI) {
  console.error('Missing DISCORD_REDIRECT_URI environment variable.');
  process.exit(1);
}

if (!FRONTEND_ORIGIN) {
  console.error('Missing FRONTEND_ORIGIN environment variable.');
  process.exit(1);
}

if (!AUTH_STATE_SECRET) {
  console.error('Missing AUTH_STATE_SECRET environment variable.');
  process.exit(1);
}

app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', 1);
app.use(
  cors({
    origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN,
    credentials: false
  })
);

const memberSchema = new mongoose.Schema(
  {
    userId: { type: String, index: true, required: true },
    points: { type: Number, default: 0 },
    tier: { type: String, default: 'None' },
    finnairPoints: { type: Number, default: 0 },
    flightsCompleted: { type: Number, default: 0 }
  },
  {
    collection: 'members'
  }
);

const Member = mongoose.model('Member', memberSchema);

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function signPayload(payload) {
  return crypto.createHmac('sha256', AUTH_STATE_SECRET).update(payload).digest('base64url');
}

function createStateToken(returnTo) {
  const payload = JSON.stringify({
    nonce: crypto.randomBytes(16).toString('hex'),
    returnTo,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  return base64UrlEncode(payload) + '.' + signPayload(payload);
}

function verifyStateToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }

  const [payloadPart, signaturePart] = parts;
  let payload;

  try {
    payload = JSON.parse(base64UrlDecode(payloadPart));
  } catch (_error) {
    return null;
  }

  const expectedSignature = Buffer.from(signPayload(JSON.stringify(payload)), 'base64url');
  const providedSignature = Buffer.from(signaturePart, 'base64url');

  if (providedSignature.length !== expectedSignature.length || !crypto.timingSafeEqual(providedSignature, expectedSignature)) {
    return null;
  }

  if (!payload.returnTo || typeof payload.returnTo !== 'string') {
    return null;
  }

  if (!payload.expiresAt || Date.now() > payload.expiresAt) {
    return null;
  }

  return payload;
}

function isAllowedReturnTo(value) {
  try {
    const url = new URL(value);
    return url.origin === FRONTEND_ORIGIN;
  } catch (_error) {
    return false;
  }
}

function buildAuthRedirectUrl(returnTo) {
  const state = createStateToken(returnTo);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: 'identify email',
    state,
    prompt: 'consent'
  });

  return 'https://discord.com/oauth2/authorize?' + params.toString();
}

async function exchangeDiscordCode(code) {
  const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI
    })
  });

  if (!tokenResponse.ok) {
    throw new Error('Discord token exchange failed');
  }

  return tokenResponse.json();
}

async function fetchDiscordUser(accessToken) {
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: {
      Authorization: 'Bearer ' + accessToken
    }
  });

  if (!userResponse.ok) {
    throw new Error('Discord profile request failed');
  }

  return userResponse.json();
}

function buildFrontendRedirect(returnTo, payload) {
  const fragment = new URLSearchParams({
    auth: base64UrlEncode(JSON.stringify(payload))
  });

  return returnTo + '#' + fragment.toString();
}

function getDefaultReturnTo() {
  return FRONTEND_ORIGIN.replace(/\/$/, '') + '/finnair/';
}

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/auth/discord/start', (req, res) => {
  const requestedReturnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '';
  const returnTo = requestedReturnTo && isAllowedReturnTo(requestedReturnTo)
    ? requestedReturnTo
    : getDefaultReturnTo();

  return res.redirect(buildAuthRedirectUrl(returnTo));
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const error = typeof req.query.error === 'string' ? req.query.error : '';

  if (error) {
    return res.redirect(getDefaultReturnTo() + '#error=' + encodeURIComponent(error));
  }

  const verifiedState = verifyStateToken(state);
  if (!verifiedState || !code) {
    return res.redirect(getDefaultReturnTo() + '#error=invalid_state');
  }

  try {
    const tokenData = await exchangeDiscordCode(code);
    const discordUser = await fetchDiscordUser(tokenData.access_token);
    const member = await Member.findOne({ userId: String(discordUser.id) }).lean();

    return res.redirect(buildFrontendRedirect(verifiedState.returnTo, {
      status: 'ok',
      profile: {
        discordId: String(discordUser.id),
        username: discordUser.username || '',
        displayName: discordUser.global_name || discordUser.username || '',
        email: discordUser.email || ''
      },
      member: member
        ? {
            userId: member.userId,
            points: Number(member.points || 0),
            tier: member.tier || 'None',
            finnairPoints: Number(member.finnairPoints || 0),
            flightsCompleted: Number(member.flightsCompleted || 0),
            joinedAt: member.joinedAt || null,
            createdAt: member.createdAt || null,
            updatedAt: member.updatedAt || null
          }
        : null
    }));
  } catch (callbackError) {
    return res.redirect(getDefaultReturnTo() + '#error=' + encodeURIComponent('auth_failed'));
  }
});

app.post('/api/auth/discord/member', async (req, res) => {
  const accessToken = req.body && req.body.accessToken;

  if (!accessToken || typeof accessToken !== 'string') {
    return res.status(400).json({ error: 'accessToken is required' });
  }

  try {
    const discordResp = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: 'Bearer ' + accessToken
      }
    });

    if (!discordResp.ok) {
      return res.status(401).json({ error: 'Discord token is invalid or expired' });
    }

    const discordUser = await discordResp.json();

    const member = await Member.findOne({ userId: String(discordUser.id) }).lean();

    return res.json({
      profile: {
        discordId: String(discordUser.id),
        username: discordUser.username || '',
        displayName: discordUser.global_name || discordUser.username || '',
        email: discordUser.email || ''
      },
      member: member
        ? {
            userId: member.userId,
            points: Number(member.points || 0),
            tier: member.tier || 'None',
            finnairPoints: Number(member.finnairPoints || 0),
            flightsCompleted: Number(member.flightsCompleted || 0),
            joinedAt: member.joinedAt || null,
            createdAt: member.createdAt || null,
            updatedAt: member.updatedAt || null
          }
        : null
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error', details: String(error.message || error) });
  }
});

async function start() {
  await mongoose.connect(MONGODB_URI, {
    dbName: 'finnair_plus'
  });

  app.listen(PORT, () => {
    console.log('Finnair API listening on port ' + PORT);
  });
}

start().catch((error) => {
  console.error('API startup failed:', error);
  process.exit(1);
});
