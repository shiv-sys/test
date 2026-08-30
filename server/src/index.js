const path=require('path');require('dotenv').config({path:path.join(__dirname,'../.env')});
const express=require('express'),http=require('http'),cors=require('cors'),jwt=require('jsonwebtoken'),bcrypt=require('bcryptjs'),{Pool}=require('pg'),{Server}=require('socket.io'),multer=require('multer'),{v2:cloudinary}=require('cloudinary');
const app=express(),server=http.createServer(app),io=new Server(server,{cors:{origin:'*'}});app.use(cors());app.use(express.json());
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?{rejectUnauthorized:false}:false});
cloudinary.config({cloud_name:process.env.CLOUDINARY_CLOUD_NAME,api_key:process.env.CLOUDINARY_API_KEY,api_secret:process.env.CLOUDINARY_API_SECRET});
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:10*1024*1024}});
async function init(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(80), email VARCHAR(160) UNIQUE, password TEXT,
      avatar TEXT, role VARCHAR(20) DEFAULT 'user', created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(80);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(160);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();
    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(80);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
    CREATE TABLE IF NOT EXISTS conversations (id SERIAL PRIMARY KEY,name VARCHAR(120),is_group BOOLEAN DEFAULT false,created_at TIMESTAMP DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS conversation_members (conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,user_id INT REFERENCES users(id) ON DELETE CASCADE,PRIMARY KEY(conversation_id,user_id));
    CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY,conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,sender_id INT REFERENCES users(id),body TEXT,attachment_url TEXT,attachment_name TEXT,reply_to INT,edited BOOLEAN DEFAULT false,created_at TIMESTAMP DEFAULT NOW());
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_url TEXT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_name TEXT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to INT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN DEFAULT false;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();
  `);
  const cols=await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'`);
  const names=new Set(cols.rows.map(r=>r.column_name));
  if(names.has('username')) await pool.query(`UPDATE users SET name=COALESCE(NULLIF(name,''),username) WHERE name IS NULL OR name=''`);
  if(names.has('display_name')) await pool.query(`UPDATE users SET display_name=COALESCE(NULLIF(display_name,''),name,username,split_part(COALESCE(email,''),'@',1),'User') WHERE display_name IS NULL OR display_name=''`);
  if(names.has('password_hash')) await pool.query(`UPDATE users SET password_hash=COALESCE(password_hash,password) WHERE password_hash IS NULL OR password_hash=''`);
  if(names.has('password')) await pool.query(`UPDATE users SET password=COALESCE(password,password_hash) WHERE password IS NULL OR password=''`);
  await pool.query(`UPDATE users SET name=COALESCE(NULLIF(name,''),split_part(COALESCE(email,''),'@',1),'User') WHERE name IS NULL OR name=''`);
  await pool.query(`UPDATE users SET role=COALESCE(role,'user'),created_at=COALESCE(created_at,NOW()) WHERE role IS NULL OR created_at IS NULL`);
}

function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||'').replace('Bearer ','') ,process.env.JWT_SECRET);next()}catch(e){res.status(401).json({error:'Unauthorized'})}}
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/auth/register',async(req,res)=>{try{
  let{name,email,password,username}=req.body;
  name=String(name||'').trim(); email=String(email||'').trim().toLowerCase(); password=String(password||'');
  if(!name||!email||!password)return res.status(400).json({error:'Name, email and password are required'});
  const hash=await bcrypt.hash(password,12);
  const c=await pool.query(`SELECT column_name,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' AND table_name='users'`);
  const cols=new Map(c.rows.map(x=>[x.column_name,x]));
  const data={name,display_name:name,email,password:hash,password_hash:hash,avatar:null,role:'user',created_at:new Date()};
  if(cols.has('username')) data.username=String(username||name).trim().toLowerCase().replace(/\s+/g,'_').slice(0,80);
  const keys=Object.keys(data).filter(k=>cols.has(k));
  const required=c.rows.filter(x=>x.is_nullable==='NO' && !x.column_default && x.column_name!=='id' && !keys.includes(x.column_name));
  if(required.length)return res.status(500).json({error:'Database schema requires additional field(s): '+required.map(x=>x.column_name).join(', ')});
  const values=keys.map(k=>data[k]); const placeholders=keys.map((_,i)=>'$'+(i+1)).join(',');
  const r=await pool.query(`INSERT INTO users(${keys.join(',')}) VALUES(${placeholders}) RETURNING id,name,email,avatar,role`,values);
  const token=jwt.sign({id:r.rows[0].id},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:r.rows[0]});
}catch(e){res.status(400).json({error:e.code==='23505'?(String(e.detail||'').includes('username')?'Username already registered':'Email already registered'):e.message})}});
app.post('/api/auth/login',async(req,res)=>{try{
  const email=String(req.body.email||'').trim().toLowerCase();
  const c=await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'`);
  const names=new Set(c.rows.map(x=>x.column_name));
  const passwordColumn=names.has('password_hash')?'password_hash':'password';
  const displayColumn=names.has('display_name')?'display_name':'name';
  const r=await pool.query(`SELECT *, ${displayColumn} AS normalized_name, ${passwordColumn} AS normalized_password FROM users WHERE email=$1`,[email]);
  if(!r.rowCount||!r.rows[0].normalized_password||!(await bcrypt.compare(req.body.password||'',r.rows[0].normalized_password)))return res.status(401).json({error:'Invalid credentials'});
  let u=r.rows[0]; delete u.password; delete u.password_hash; u.name=u.normalized_name||u.name||u.username||email.split('@')[0]; delete u.normalized_name; delete u.normalized_password;
  res.json({token:jwt.sign({id:u.id},process.env.JWT_SECRET,{expiresIn:'7d'}),user:u});
}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/me',auth,async(req,res)=>{let r=await pool.query('SELECT id,name,email,avatar,role FROM users WHERE id=$1',[req.user.id]);res.json(r.rows[0])});
app.get('/api/users',auth,async(req,res)=>{let q='%'+String(req.query.q||'')+'%';let r=await pool.query('SELECT id,name,email,avatar FROM users WHERE id<>$1 AND (name ILIKE $2 OR email ILIKE $2) ORDER BY name LIMIT 50',[req.user.id,q]);res.json(r.rows)});
app.get('/api/conversations',auth,async(req,res)=>{let r=await pool.query(`SELECT c.*,COALESCE(json_agg(json_build_object('id',u.id,'name',u.name,'avatar',u.avatar)) FILTER(WHERE u.id IS NOT NULL),'[]') members,(SELECT json_build_object('id',m.id,'body',m.body,'sender_id',m.sender_id,'created_at',m.created_at,'attachment_url',m.attachment_url) FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message FROM conversations c JOIN conversation_members cm0 ON cm0.conversation_id=c.id LEFT JOIN conversation_members cm ON cm.conversation_id=c.id LEFT JOIN users u ON u.id=cm.user_id WHERE cm0.user_id=$1 GROUP BY c.id ORDER BY c.created_at DESC`,[req.user.id]);res.json(r.rows)});
app.post('/api/conversations',auth,async(req,res)=>{let ids=[...new Set([req.user.id,...(req.body.userIds||[]).map(Number)])];if(ids.length<2)return res.status(400).json({error:'Select another user'});let group=ids.length>2||!!req.body.isGroup;let c=await pool.query('INSERT INTO conversations(name,is_group) VALUES($1,$2) RETURNING *',[req.body.name||null,group]);for(const id of ids)await pool.query('INSERT INTO conversation_members VALUES($1,$2)',[c.rows[0].id,id]);res.json(c.rows[0])});
app.get('/api/conversations/:id/messages',auth,async(req,res)=>{let ok=await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',[req.params.id,req.user.id]);if(!ok.rowCount)return res.status(403).json({error:'Forbidden'});let r=await pool.query('SELECT m.*,u.name sender_name,u.avatar sender_avatar FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.created_at',[req.params.id]);res.json(r.rows)});
app.post('/api/upload',auth,upload.single('file'),async(req,res)=>{if(!req.file)return res.status(400).json({error:'No file'});if(!process.env.CLOUDINARY_CLOUD_NAME)return res.status(503).json({error:'Cloudinary is not configured'});try{let result=await new Promise((resolve,reject)=>{let s=cloudinary.uploader.upload_stream({folder:'advanced-chat'},(e,r)=>e?reject(e):resolve(r));s.end(req.file.buffer)});res.json({url:result.secure_url,name:req.file.originalname})}catch(e){res.status(500).json({error:e.message})}});
app.put('/api/messages/:id',auth,async(req,res)=>{let r=await pool.query('UPDATE messages SET body=$1,edited=true WHERE id=$2 AND sender_id=$3 RETURNING *',[req.body.body,req.params.id,req.user.id]);res.json(r.rows[0]||{})});
app.delete('/api/messages/:id',auth,async(req,res)=>{await pool.query('DELETE FROM messages WHERE id=$1 AND sender_id=$2',[req.params.id,req.user.id]);res.json({ok:true})});
const distPath = path.join(__dirname, '../../dist');
app.use(express.static(distPath));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
io.use((socket,next)=>{try{socket.user=jwt.verify(socket.handshake.auth.token,process.env.JWT_SECRET);next()}catch(e){next(new Error('Unauthorized'))}});
const onlineUsers=new Map();
io.on('connection',async socket=>{
  const uid=Number(socket.user.id);
  if(!onlineUsers.has(uid)) onlineUsers.set(uid,new Set());
  onlineUsers.get(uid).add(socket.id);
  const onlineIds=Array.from(onlineUsers.keys());
  const presenceRows=await pool.query('SELECT id,name,email,avatar FROM users WHERE id = ANY($1::int[])',[onlineIds]);
  socket.emit('presence:list',presenceRows.rows.map(u=>({userId:Number(u.id),name:u.name||u.email||'User',email:u.email,avatar:u.avatar})));
  const me=presenceRows.rows.find(u=>Number(u.id)===uid);
  socket.broadcast.emit('presence:online',{userId:uid,name:me?.name||'User',email:me?.email||'',avatar:me?.avatar||null});
  socket.on('join',id=>socket.join('c:'+id));
  socket.on('typing',d=>socket.to('c:'+d.conversationId).emit('typing',{userId:uid,typing:d.typing}));
  socket.on('send',async d=>{let ok=await pool.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2',[d.conversationId,uid]);if(!ok.rowCount)return;let r=await pool.query('INSERT INTO messages(conversation_id,sender_id,body,attachment_url,attachment_name,reply_to) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[d.conversationId,uid,d.body||'',d.attachmentUrl||null,d.attachmentName||null,d.replyTo||null]);let m=r.rows[0];let u=await pool.query('SELECT name,avatar FROM users WHERE id=$1',[uid]);m.sender_name=u.rows[0].name;m.sender_avatar=u.rows[0].avatar;io.to('c:'+d.conversationId).emit('message',m)});
  socket.on('disconnect',()=>{
    const sockets=onlineUsers.get(uid); if(!sockets)return;
    sockets.delete(socket.id);
    if(sockets.size===0){onlineUsers.delete(uid);io.emit('presence:offline',{userId:uid});}
  });
});
init().then(()=>server.listen(process.env.PORT||10000,'0.0.0.0',()=>console.log('Chat server running'))).catch(e=>{console.error(e);process.exit(1)});
