const path = require('path');
const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { Server } = require('socket.io');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '1mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!t) throw new Error('Missing token');
    req.user = jwt.verify(t, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

function cleanUser(u) {
  if (!u) return null;
  return {
    id: Number(u.id),
    name: u.name || u.display_name || u.username || u.email?.split('@')[0] || 'User',
    email: u.email || '',
    avatar: u.avatar || null,
    role: u.role || 'user',
  };
}

async function tableColumns(table) {
  const r = await pool.query(
    `SELECT column_name,is_nullable,column_default,data_type
     FROM information_schema.columns
     WHERE table_schema='public' AND table_name=$1
     ORDER BY ordinal_position`,
    [table]
  );
  return new Map(r.rows.map((x) => [x.column_name, x]));
}

async function ensureColumn(table, column, definition) {
  const safeTables = new Set(['users', 'conversations', 'conversation_members', 'messages']);
  if (!safeTables.has(table)) throw new Error('Unsafe table name');
  await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
}

async function init() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(80),
      email VARCHAR(160) UNIQUE,
      password TEXT,
      avatar TEXT,
      role VARCHAR(20) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  for (const [c, d] of Object.entries({
    name: 'VARCHAR(80)',
    email: 'VARCHAR(160)',
    password: 'TEXT',
    avatar: 'TEXT',
    role: "VARCHAR(20) DEFAULT 'user'",
    created_at: 'TIMESTAMP DEFAULT NOW()',
    display_name: 'VARCHAR(80)',
    password_hash: 'TEXT',
    username: 'VARCHAR(80)',
    last_seen: 'TIMESTAMP',
  })) await ensureColumn('users', c, d);

  await pool.query(`
    UPDATE users
    SET name=COALESCE(NULLIF(name,''),NULLIF(display_name,''),NULLIF(username,''),split_part(COALESCE(email,''),'@',1),'User')
    WHERE name IS NULL OR name=''
  `);
  await pool.query(`
    UPDATE users
    SET display_name=COALESCE(NULLIF(display_name,''),name,username,split_part(COALESCE(email,''),'@',1),'User')
    WHERE display_name IS NULL OR display_name=''
  `);
  await pool.query(`
    UPDATE users
    SET password_hash=COALESCE(NULLIF(password_hash,''),password)
    WHERE password_hash IS NULL OR password_hash=''
  `);
  await pool.query(`
    UPDATE users
    SET password=COALESCE(NULLIF(password,''),password_hash)
    WHERE password IS NULL OR password=''
  `);
  await pool.query(`UPDATE users SET role=COALESCE(role,'user') WHERE role IS NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120),
      is_group BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  for (const [c, d] of Object.entries({
    name: 'VARCHAR(120)',
    is_group: 'BOOLEAN DEFAULT false',
    created_at: 'TIMESTAMP DEFAULT NOW()',
  })) await ensureColumn('conversations', c, d);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(conversation_id,user_id)
    )
  `);
  await ensureColumn('conversation_members', 'created_at', 'TIMESTAMP DEFAULT NOW()');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id INT REFERENCES users(id),
      body TEXT,
      attachment_url TEXT,
      attachment_name TEXT,
      reply_to INT,
      edited BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  for (const [c, d] of Object.entries({
    body: 'TEXT',
    attachment_url: 'TEXT',
    attachment_name: 'TEXT',
    reply_to: 'INT',
    edited: 'BOOLEAN DEFAULT false',
    created_at: 'TIMESTAMP DEFAULT NOW()',
    read_at: 'TIMESTAMP',
  })) await ensureColumn('messages', c, d);
}

app.get('/api/health', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, service: 'chatflow', database: true });
}));

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  let { name, email, password, username } = req.body || {};
  name = String(name || '').trim();
  email = String(email || '').trim().toLowerCase();
  password = String(password || '');
  username = String(username || name).trim().toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_.-]/g, '').slice(0, 80);
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });

  const cols = await tableColumns('users');
  const duplicate = await pool.query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [email]);
  if (duplicate.rowCount) return res.status(409).json({ error: 'An account with this email already exists' });

  let finalUsername = username || `user_${Date.now()}`;
  if (cols.has('username')) {
    let n = finalUsername;
    let i = 1;
    while ((await pool.query('SELECT 1 FROM users WHERE lower(username)=lower($1) LIMIT 1', [n])).rowCount) n = `${finalUsername}_${i++}`.slice(0, 80);
    finalUsername = n;
  }

  const hash = await bcrypt.hash(password, 12);
  const data = {
    name,
    display_name: name,
    email,
    password: hash,
    password_hash: hash,
    username: finalUsername,
    avatar: null,
    role: 'user',
    created_at: new Date(),
    last_seen: new Date(),
  };
  const keys = Object.keys(data).filter((k) => cols.has(k));
  const missing = [...cols.values()].filter((c) => c.column_name !== 'id' && c.is_nullable === 'NO' && !c.column_default && !keys.includes(c.column_name));
  if (missing.length) return res.status(500).json({ error: 'Database schema requires additional field(s): ' + missing.map((x) => x.column_name).join(', ') });

  const placeholders = keys.map((_, i) => `$${i + 1}`).join(',');
  const r = await pool.query(`INSERT INTO users(${keys.join(',')}) VALUES(${placeholders}) RETURNING *`, keys.map((k) => data[k]));
  const u = cleanUser(r.rows[0]);
  res.json({ token: jwt.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: '7d' }), user: u });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const pass = String(req.body?.password || '');
  if (!email || !pass) return res.status(400).json({ error: 'Email and password are required' });
  const cols = await tableColumns('users');
  const passParts = ['password_hash', 'password'].filter((x) => cols.has(x));
  if (!passParts.length) return res.status(500).json({ error: 'No password column exists in users table' });
  const nameExpr = cols.has('display_name') ? 'display_name' : cols.has('name') ? 'name' : cols.has('username') ? 'username' : `split_part(email,'@',1)`;
  const passwordExpr = passParts.length === 2 ? `COALESCE(NULLIF(password_hash,''),password)` : `${passParts[0]}`;
  const r = await pool.query(`SELECT *,${nameExpr} AS normalized_name,${passwordExpr} AS normalized_password FROM users WHERE lower(email)=lower($1) LIMIT 1`, [email]);
  if (!r.rowCount || !r.rows[0].normalized_password || !(await bcrypt.compare(pass, r.rows[0].normalized_password))) return res.status(401).json({ error: 'Invalid credentials' });
  await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [r.rows[0].id]).catch(() => {});
  const u = cleanUser({ ...r.rows[0], name: r.rows[0].normalized_name });
  res.json({ token: jwt.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: '7d' }), user: u });
}));

app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'User not found' });
  res.json(cleanUser(r.rows[0]));
}));

app.get('/api/users', auth, asyncRoute(async (req, res) => {
  const raw = String(req.query.q || '').trim();
  const q = `%${raw}%`;
  const r = await pool.query(
    `SELECT id,
      COALESCE(NULLIF(name,''),NULLIF(display_name,''),NULLIF(username,''),split_part(COALESCE(email,''),'@',1),'User') AS name,
      email,avatar,role
     FROM users
     WHERE id<>$1
       AND ($2='' OR COALESCE(name,display_name,username,email) ILIKE $3)
     ORDER BY name
     LIMIT 50`,
    [req.user.id, raw, q]
  );
  res.json(r.rows.map(cleanUser));
}));

async function getConversation(conversationId) {
  const c = await pool.query('SELECT id,name,is_group,created_at FROM conversations WHERE id=$1', [conversationId]);
  if (!c.rowCount) return null;
  const m = await pool.query(
    `SELECT u.id,
      COALESCE(NULLIF(u.name,''),NULLIF(u.display_name,''),NULLIF(u.username,''),split_part(COALESCE(u.email,''),'@',1),'User') AS name,
      u.email,u.avatar,u.role
     FROM conversation_members cm JOIN users u ON u.id=cm.user_id
     WHERE cm.conversation_id=$1 ORDER BY u.id`,
    [conversationId]
  );
  const last = await pool.query(
    `SELECT id,body,sender_id,created_at,attachment_url,attachment_name,edited,read_at
     FROM messages WHERE conversation_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`,
    [conversationId]
  );
  return { ...c.rows[0], members: m.rows.map(cleanUser), last_message: last.rows[0] || null };
}

app.get('/api/conversations', auth, asyncRoute(async (req, res) => {
  const base = await pool.query(
    `SELECT c.id,c.name,c.is_group,c.created_at
     FROM conversations c
     JOIN conversation_members me ON me.conversation_id=c.id AND me.user_id=$1
     ORDER BY c.created_at DESC,c.id DESC`,
    [req.user.id]
  );
  const conversations = [];
  for (const row of base.rows) {
    try {
      const full = await getConversation(row.id);
      if (full) conversations.push(full);
    } catch (e) {
      console.error('conversation load', row.id, e.message);
    }
  }
  res.json(conversations);
}));

app.post('/api/conversations', auth, asyncRoute(async (req, res) => {
  const requested = Array.isArray(req.body?.userIds) ? req.body.userIds.map(Number).filter(Number.isInteger) : [];
  const ids = [...new Set([Number(req.user.id), ...requested])];
  if (ids.length < 2) return res.status(400).json({ error: 'Select another user' });

  const isGroup = ids.length > 2 || Boolean(req.body?.isGroup);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let conversationId = null;

    if (!isGroup && ids.length === 2) {
      const existing = await client.query(
        `SELECT c.id
         FROM conversations c
         JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=$1
         JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=$2
         WHERE COALESCE(c.is_group,false)=false
         LIMIT 1`,
        [ids[0], ids[1]]
      );
      if (existing.rowCount) conversationId = Number(existing.rows[0].id);
    }

    if (!conversationId) {
      const c = await client.query(
        'INSERT INTO conversations(name,is_group,created_at) VALUES($1,$2,NOW()) RETURNING id',
        [req.body?.name ? String(req.body.name).slice(0, 120) : null, isGroup]
      );
      conversationId = Number(c.rows[0].id);
      for (const id of ids) {
        await client.query(
          'INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2) ON CONFLICT(conversation_id,user_id) DO NOTHING',
          [conversationId, id]
        );
      }
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  const full = await getConversation(conversationId);
  if (!full) return res.status(500).json({ error: 'Conversation could not be loaded after creation' });
  res.json(full);
}));

app.get('/api/conversations/:id/messages', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid conversation id' });
  const ok = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]);
  if (!ok.rowCount) return res.status(403).json({ error: 'Forbidden' });
  await pool.query('UPDATE messages SET read_at=NOW() WHERE conversation_id=$1 AND sender_id<>$2 AND read_at IS NULL', [id, req.user.id]).catch(() => {});
  const r = await pool.query(
    `SELECT m.*,COALESCE(NULLIF(u.name,''),NULLIF(u.display_name,''),NULLIF(u.username,''),split_part(COALESCE(u.email,''),'@',1),'User') AS sender_name,u.avatar AS sender_avatar
     FROM messages m JOIN users u ON u.id=m.sender_id
     WHERE m.conversation_id=$1 ORDER BY m.created_at,m.id`,
    [id]
  );
  res.json(r.rows);
}));

app.post('/api/conversations/:id/read', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const member = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'Forbidden' });
  await pool.query('UPDATE messages SET read_at=NOW() WHERE conversation_id=$1 AND sender_id<>$2 AND read_at IS NULL', [id, req.user.id]);
  io.to('c:' + id).emit('conversation:read', { conversationId: id, userId: Number(req.user.id) });
  res.json({ ok: true });
}));

app.post('/api/upload', auth, upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  if (!process.env.CLOUDINARY_CLOUD_NAME) return res.status(503).json({ error: 'Cloudinary is not configured' });
  const result = await new Promise((resolve, reject) => {
    const s = cloudinary.uploader.upload_stream({ folder: 'advanced-chat', resource_type: 'auto' }, (e, r) => e ? reject(e) : resolve(r));
    s.end(req.file.buffer);
  });
  res.json({ url: result.secure_url, name: req.file.originalname });
}));

app.put('/api/messages/:id', auth, asyncRoute(async (req, res) => {
  const body = String(req.body?.body || '').trim();
  const r = await pool.query('UPDATE messages SET body=$1,edited=true WHERE id=$2 AND sender_id=$3 RETURNING *', [body, Number(req.params.id), req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Message not found' });
  res.json(r.rows[0]);
}));

app.delete('/api/messages/:id', auth, asyncRoute(async (req, res) => {
  const r = await pool.query('DELETE FROM messages WHERE id=$1 AND sender_id=$2 RETURNING id,conversation_id', [Number(req.params.id), req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Message not found' });
  io.to('c:' + Number(r.rows[0].conversation_id)).emit('message:deleted', { id: Number(r.rows[0].id) });
  res.json({ ok: true });
}));

// Helpful, safe schema diagnostics for the logged-in owner of the app.
app.get('/api/diagnostics/schema', auth, asyncRoute(async (req, res) => {
  const names = ['users', 'conversations', 'conversation_members', 'messages'];
  const out = {};
  for (const name of names) out[name] = [...(await tableColumns(name)).values()];
  res.json(out);
}));

const distPath = path.join(__dirname, '../../dist');
app.use(express.static(distPath));
app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found', path: req.path, method: req.method }));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
app.use((err, req, res, next) => {
  console.error('API error:', err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

const onlineUsers = new Map();

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth?.token || '', process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', async (socket) => {
  const uid = Number(socket.user.id);
  if (!onlineUsers.has(uid)) onlineUsers.set(uid, new Set());
  onlineUsers.get(uid).add(socket.id);

  try {
    const ids = [...onlineUsers.keys()];
    const r = ids.length ? await pool.query(
      `SELECT id,COALESCE(NULLIF(name,''),NULLIF(display_name,''),NULLIF(username,''),split_part(COALESCE(email,''),'@',1),'User') AS name,email,avatar
       FROM users WHERE id=ANY($1::int[])`,
      [ids]
    ) : { rows: [] };
    socket.emit('presence:list', r.rows.map(cleanPresence));
    const me = r.rows.find((u) => Number(u.id) === uid);
    socket.broadcast.emit('presence:online', {
      userId: uid,
      name: me?.name || 'User',
      email: me?.email || '',
      avatar: me?.avatar || null,
    });
    await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [uid]).catch(() => {});
  } catch (e) {
    console.error('presence', e);
  }

  socket.on('join', (id) => socket.join('c:' + Number(id)));
  socket.on('leave', (id) => socket.leave('c:' + Number(id)));

  socket.on('typing', (d) => socket.to('c:' + Number(d.conversationId)).emit('typing', { userId: uid, typing: !!d.typing }));

  socket.on('send', async (d) => {
    try {
      const cid = Number(d.conversationId);
      const ok = await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [cid, uid]);
      if (!ok.rowCount) return socket.emit('chat:error', { error: 'You are not a member of this conversation' });
      const body = String(d.body || '').trim();
      if (!body && !d.attachmentUrl) return socket.emit('chat:error', { error: 'Message is empty' });
      const r = await pool.query(
        `INSERT INTO messages(conversation_id,sender_id,body,attachment_url,attachment_name,reply_to)
         VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
        [cid, uid, body, d.attachmentUrl || null, d.attachmentName || null, d.replyTo || null]
      );
      const u = await pool.query(
        `SELECT COALESCE(NULLIF(name,''),NULLIF(display_name,''),NULLIF(username,''),split_part(COALESCE(email,''),'@',1),'User') AS name,avatar,email FROM users WHERE id=$1`,
        [uid]
      );
      const m = r.rows[0];
      m.sender_name = u.rows[0]?.name || 'User';
      m.sender_avatar = u.rows[0]?.avatar || null;
      io.to('c:' + cid).emit('message', m);
      await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [uid]).catch(() => {});
    } catch (e) {
      console.error('send', e);
      socket.emit('chat:error', { error: e.message || 'Could not send message' });
    }
  });

  socket.on('disconnect', async () => {
    const set = onlineUsers.get(uid);
    if (!set) return;
    set.delete(socket.id);
    await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [uid]).catch(() => {});
    if (!set.size) {
      onlineUsers.delete(uid);
      io.emit('presence:offline', { userId: uid });
    }
  });
});

function cleanPresence(u) {
  return {
    userId: Number(u.id),
    name: u.name || 'User',
    email: u.email || '',
    avatar: u.avatar || null,
  };
}

init()
  .then(() => server.listen(process.env.PORT || 10000, '0.0.0.0', () => console.log('ChatFlow server running')))
  .catch((e) => {
    console.error('DB init failed', e);
    process.exit(1);
  });
