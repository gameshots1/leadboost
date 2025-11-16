require('dotenv').config();
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const XLSX = require('xlsx');
const puppeteer = require('puppeteer');
const crypto = require('crypto');

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) { console.error('MONGODB_URI not set'); process.exit(1); }
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const ENCKEY_B64 = process.env.ENCRYPTION_KEY || '';
const ENCKEY = ENCKEY_B64 ? Buffer.from(ENCKEY_B64.replace(/^base64:/,''), 'base64') : null;
function decryptText(b64) {
  if (!ENCKEY || !b64) return '';
  const data = Buffer.from(b64, 'base64');
  const iv = data.slice(0,12), tag = data.slice(12,28), encrypted = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCKEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

const jobSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  filename: String,
  status: String,
  createdAt: Date,
  startedAt: Date,
  finishedAt: Date
});
const leadSchema = new mongoose.Schema({
  jobId: mongoose.Types.ObjectId,
  rowNumber: Number,
  data: mongoose.Schema.Types.Mixed,
  status: String,
  message: String,
  screenshotPath: String
});
const userSchema = new mongoose.Schema({
  email: String,
  encSiteUsername: String,
  encSitePassword: String
});

const Job = mongoose.model('Job', jobSchema);
const Lead = mongoose.model('Lead', leadSchema);
const User = mongoose.model('User', userSchema);

const storageDir = path.join(__dirname, 'storage');
if (!fs.existsSync(path.join(storageDir, 'screens'))) fs.mkdirSync(path.join(storageDir, 'screens'), { recursive: true });

async function processJob(job) {
  console.log('Processing job', job._id);
  await Job.updateOne({ _id: job._id }, { status: 'processing', startedAt: new Date() });

  const user = await User.findById(job.userId);
  const siteUser = decryptText(user.encSiteUsername);
  const sitePass = decryptText(user.encSitePassword);

  const uploadsDir = path.join(__dirname, 'storage', 'uploads');
  const filePath = path.join(uploadsDir, job.filename);
  if (!fs.existsSync(filePath)) {
    await Job.updateOne({ _id: job._id }, { status: 'failed', result: { error: 'file_missing' }});
    console.error('File missing', filePath);
    return;
  }

  const workbook = XLSX.readFile(filePath);
  const sheet = workbook.Sheets[workbook.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });

  // Launch headless browser
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox','--disable-setuid-sandbox'] });
  const page = await browser.newPage();
  page.setDefaultTimeout(30000);

  // accept any dialogs (duplicate mobile popup and post-register confirm)
  page.on('dialog', async dialog => {
    console.log('Dialog detected:', dialog.message());
    try { await dialog.accept(); } catch (e) { console.warn('Dialog accept failed', e.message); }
  });

  try {
    // Login - try a few selectors
    await page.goto('https://leadkasikandar.co.in/', { waitUntil: 'networkidle2' });

    // Attempt to find login form / fields - try candidate selectors
    const loginAttempts = [
      { userSel: 'input[name="mobile"]', passSel: 'input[name="password"]', btnSel: 'button[type="submit"]' },
      { userSel: 'input#mobile', passSel: 'input#password', btnSel: 'button[type="submit"]' },
      { userSel: 'input[name="username"]', passSel: 'input[name="password"]', btnSel: 'button[type="submit"]' }
    ];
    let loggedIn = false;
    for (const a of loginAttempts) {
      try {
        if (!await page.$(a.userSel)) continue;
        await page.evaluate(sel => document.querySelector(sel).value = '', a.userSel);
        await page.type(a.userSel, String(siteUser || ''), { delay: 20 });
        await page.type(a.passSel, String(sitePass || ''), { delay: 20 });
        await page.click(a.btnSel);
        await page.waitForTimeout(2000);
        // quick heuristic - check if entry page exists or logout link
        const ok = await page.evaluate(()=> !!(document.querySelector('a[href*="logout"]') || document.querySelector('#registerBtn') || document.querySelector('input[name="company_name"]')));
        if (ok) { loggedIn = true; break; }
      } catch(e) { /* try next */ }
    }
    if (!loggedIn) {
      console.warn('Login not confirmed; continuing to entry URL');
    }

    // Try navigation to entry page
    const entryCandidates = [
      'https://leadkasikandar.co.in/entry',
      'https://leadkasikandar.co.in/add-lead',
      'https://leadkasikandar.co.in/leads',
      'https://leadkasikandar.co.in/entry.php',
      'https://leadkasikandar.co.in/pages/entry.php'
    ];
    for (const url of entryCandidates) {
      try { await page.goto(url, { waitUntil: 'networkidle2' }); break; } catch(e){ /* ignore */ }
    }
    await page.waitForTimeout(1000);

    // Process rows
    let rowNo = 0;
    for (const r of rows) {
      rowNo++;
      try {
        console.log('Row', rowNo, r);

        // Find selectors (fallback lists)
        const companyCandidates = ['input[name="company_name"]', 'input[name="company"]', 'input#company', 'input[placeholder*="Company"]'];
        const mobileCandidates = ['input[name="mobile_number"]', 'input[name="mobile"]', 'input#mobile', 'input[placeholder*="Mobile"]'];
        const cityCandidates = ['input[name="city"]', 'input#city', 'input[placeholder*="City"]'];
        const pinCandidates = ['input[name="pincode"]', 'input[name="pin"]', 'input#pincode', 'input[placeholder*="Pincode"]'];
        const leadTypeCandidates = ['select[name="lead_type"]', 'select#lead_type', 'select[name="type"]'];
        const registerCandidates = ['button#registerBtn', 'button[name="register"]', 'button[onclick*="register"]', 'button[type="submit"]'];

        async function pick(selList) {
          for (const s of selList) {
            if (await page.$(s)) return s;
          }
          return null;
        }

        const companySel = await pick(companyCandidates);
        const mobileSel = await pick(mobileCandidates);
        const citySel = await pick(cityCandidates);
        const pinSel = await pick(pinCandidates);
        const leadSel = await pick(leadTypeCandidates);
        const regSel = await pick(registerCandidates);

        if (!companySel || !mobileSel || !citySel || !pinSel || !leadSel || !regSel) {
          throw new Error(`Missing selectors (company:${!!companySel}, mobile:${!!mobileSel}, city:${!!citySel}, pin:${!!pinSel}, lead:${!!leadSel}, reg:${!!regSel})`);
        }

        // Fill Company
        await page.evaluate(sel => { const el=document.querySelector(sel); if (el) el.value=''; }, companySel);
        if (r['Company name']) await page.type(companySel, String(r['Company name']).trim(), { delay: 20 });

        // Fill Mobile
        await page.evaluate(sel => { const el=document.querySelector(sel); if (el) el.value=''; }, mobileSel);
        if (r['Phone']) await page.type(mobileSel, String(r['Phone']).trim(), { delay: 20 });

        // Move focus to next field to trigger duplicate check popup
        await page.focus(citySel);
        // Wait exactly 3s for the duplicate-mobile popup to appear (and be handled by page.on('dialog'))
        await page.waitForTimeout(3000);

        // Fill city & pincode
        await page.evaluate(sel => { const el=document.querySelector(sel); if (el) el.value=''; }, citySel);
        if (r['City']) await page.type(citySel, String(r['City']).trim(), { delay: 20 });

        await page.evaluate(sel => { const el=document.querySelector(sel); if (el) el.value=''; }, pinSel);
        if (r['Pincode']) await page.type(pinSel, String(r['Pincode']).trim(), { delay: 20 });

        // Select Lead Type = Regular (try direct select then fallback to setting option by text)
        try { await page.select(leadSel, 'Regular'); } catch(e) {
          await page.evaluate((sel)=>{
            const s=document.querySelector(sel);
            if(!s) return;
            for(const o of s.options) {
              if(o.text.trim().toLowerCase()==='regular' || String(o.value).toLowerCase().includes('regular')) { s.value=o.value; s.dispatchEvent(new Event('change',{bubbles:true})); break; }
            }
          }, leadSel);
        }

        // Click Register
        await page.click(regSel);
        // Wait a short time for register confirm dialog to appear (handled by dialog handler)
        await page.waitForTimeout(1500);

        // Record success
        await new Lead({ jobId: job._id, rowNumber: rowNo, data: r, status: 'success', message: 'registered' }).save();

      } catch (errRow) {
        console.error('Row error', rowNo, errRow.message);
        const screenshotName = `job${job._id}_row${rowNo}_${Date.now()}.png`;
        const outPath = path.join(storageDir, 'screens', screenshotName);
        try { await page.screenshot({ path: outPath, fullPage: true }); } catch(e){/*ignore*/ }
        await new Lead({ jobId: job._id, rowNumber: rowNo, data: r, status: 'failed', message: errRow.message, screenshotPath: `/storage/screens/${screenshotName}` }).save();
      }
    }

    await browser.close();
    await Job.updateOne({ _id: job._id }, { status: 'completed', finishedAt: new Date() });
    console.log('Job completed', job._id);
  } catch (err) {
    console.error('Job fatal error', err.message);
    try { await browser.close(); } catch(e){}
    await Job.updateOne({ _id: job._id }, { status: 'failed', result: { error: err.message }});
  }
}

async function pollLoop() {
  console.log('Worker started');
  while (true) {
    const job = await Job.findOne({ status: 'pending' }).sort({ createdAt: 1 });
    if (job) {
      try { await processJob(job); } catch(e){ console.error('processJob error', e); }
    } else {
      await new Promise(r => setTimeout(r, 3000));
    }
  }
}

pollLoop();
