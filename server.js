import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';

const app = express();

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI || '';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI environment variable.');
  process.exit(1);
}

app.use(express.json({ limit: '1mb' }));
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

app.get('/health', (_req, res) => {
  res.json({ ok: true });
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
