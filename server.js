require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();

// ---------- Config & DB ----------
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) { console.error('MONGODB_URI not set'); process.exit(1); }
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const ENCKEY_B64 = process.env.ENCRYPTION_KEY || '';
const ENCKEY = ENCKEY_B64 ? Buffer.from(ENCKEY_B64.replace(/^base64:/,''), 'base64') : null;
function encryptText(plain) {
  if (!ENCKEY) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCKEY, iv);
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}
function decryptText(b64) {
  if (!ENCKEY || !b64) return '';
  const data = Buffer.from(b64, 'base64');
  const iv = data.slice(0,12), tag = data.slice(12,28), encrypted = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCKEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ---------- Mongoose Schemas ----------
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password_hash: String,
  isAdmin: { type: Boolean, default: false },
  encSiteUsername: String,
  encSitePassword: String,
  currentSessionToken: String
});
const jobSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  filename: String,
  status: { type: String, default: 'pending' }, // pending, processing, completed, failed
  createdAt: { type: Date, default: Date.now },
  startedAt: Date,
  finishedAt: Date,
  result: mongoose.Schema.Types.Mixed
});
const leadSchema = new mongoose.Schema({
  jobId: mongoose.Types.ObjectId,
  rowNumber: Number,
  data: mongoose.Schema.Types.Mixed,
  status: String,
  message: String,
  screenshotPath: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Job = mongoose.model('Job', jobSchema);
const Lead = mongoose.model('Lead', leadSchema);

// ---------- App setup ----------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret_change_me',
  resave: false, saveUninitialized: false
}));
app.use(flash());

// storage dir (not ideal on ephemeral hosts; job results are in DB; screenshots stored)
const storageDir = path.join(__dirname, 'storage');
if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true });
if (!fs.existsSync(path.join(storageDir, 'uploads'))) fs.mkdirSync(path.join(storageDir, 'uploads'), { recursive: true });
if (!fs.existsSync(path.join(storageDir, 'screens'))) fs.mkdirSync(path.join(storageDir, 'screens'), { recursive: true });

const upload = multer({ dest: path.join(storageDir, 'uploads') });

// ---------- Helpers ----------
async function findUserByEmail(email) { return await User.findOne({ email }); }
async function findUserById(id) { return await User.findById(id); }

app.use(async (req, res, next) => {
  if (req.session.userId) {
    res.locals.currentUser = await findUserById(req.session.userId);
  } else res.locals.currentUser = null;
  res.locals.messages = req.flash();
  next();
});

// ---------- Routes ----------
// Home -> redirect to login or dashboard
app.get('/', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.redirect('/dashboard');
});

// Login / Register (only admin can create users in admin panel – but keep register for bootstrap)
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await findUserByEmail(email);
  if (!user) { req.flash('error', 'Invalid credentials'); return res.redirect('/login'); }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) { req.flash('error', 'Invalid credentials'); return res.redirect('/login'); }

  // SINGLE-LOGIN ENFORCEMENT: prevent multiple concurrent logins
  if (user.currentSessionToken) {
    req.flash('error', 'This account is already logged in elsewhere. Contact admin if you need access.');
    return res.redirect('/login');
  }
  const token = uuidv4();
  user.currentSessionToken = token;
  await user.save();

  req.session.userId = user._id;
  req.session.token = token;
  res.redirect('/dashboard');
});

app.get('/logout', async (req, res) => {
  if (req.session.userId) {
    const user = await findUserById(req.session.userId);
    if (user) { user.currentSessionToken = null; await user.save(); }
  }
  req.session.destroy(() => res.redirect('/login'));
});

// Dashboard (only upload)
app.get('/dashboard', async (req,res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('dashboard', { default_username: process.env.DEFAULT_TARGET_USERNAME || '' });
});

// Save target-site credentials (stored encrypted)
app.post('/save_site_creds', async (req,res) => {
  if (!req.session.userId) return res.status(403).send('login needed');
  const { site_username, site_password } = req.body;
  const encU = encryptText(site_username || '');
  const encP = encryptText(site_password || '');
  const user = await findUserById(req.session.userId);
  user.encSiteUsername = encU;
  user.encSitePassword = encP;
  await user.save();
  req.flash('success','Saved target site credentials');
  res.redirect('/dashboard');
});

// Upload leads
app.post('/upload', upload.single('leadsfile'), async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const file = req.file;
  if (!file) { req.flash('error','No file uploaded'); return res.redirect('/dashboard'); }
  const job = new Job({ userId: req.session.userId, filename: file.filename, status: 'pending' });
  await job.save();
  req.flash('success','File uploaded and queued');
  res.redirect('/dashboard');
});

// Admin UI
app.get('/admin', async (req,res) => {
  const cur = res.locals.currentUser;
  if (!cur || !cur.isAdmin) return res.status(403).send('Forbidden');
  const users = await User.find({}, 'email isAdmin');
  const jobs = await Job.find({}).sort({ createdAt: -1 }).limit(200);
  res.render('admin', { users, jobs });
});

// View decrypted user site creds (admin)
app.get('/admin/view_creds/:userid', async (req,res) => {
  const cur = res.locals.currentUser;
  if (!cur || !cur.isAdmin) return res.status(403).send('Forbidden');
  const u = await User.findById(req.params.userid);
  if (!u) return res.status(404).send('Not found');
  res.send(`<h3>User: ${u.email}</h3><p>Site Username: ${decryptText(u.encSiteUsername)}</p><p>Site Password: ${decryptText(u.encSitePassword)}</p><p><a href="/admin">Back</a></p>`);
});

// Job details
app.get('/job/:id', async (req,res) => {
  if (!req.session.userId) return res.redirect('/login');
  const j = await Job.findById(req.params.id);
  if (!j) return res.status(404).send('job not found');
  const leads = await Lead.find({ jobId: j._id }).sort({ rowNumber: 1 });
  res.render('job', { job: j, leads });
});

// Serve screenshots / uploaded files (admin only)
app.get('/storage/screens/:name', (req,res) => {
  const p = path.join(storageDir, 'screens', req.params.name);
  if (fs.existsSync(p)) return res.sendFile(p);
  res.status(404).send('Not found');
});

// ---------- Bootstrap admin user if env provides ----------
(async ()=>{
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASS;
  if (adminEmail && adminPass) {
    const existing = await User.findOne({ email: adminEmail });
    if (!existing) {
      const hash = await bcrypt.hash(adminPass, 10);
      const u = new User({ email: adminEmail, password_hash: hash, isAdmin: true });
      await u.save();
      console.log('Created admin', adminEmail);
    }
  }
})();

// ---------- Start ----------
const port = process.env.PORT || 3000;
app.listen(port, ()=>console.log('Server running on', port));
