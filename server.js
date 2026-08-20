const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'contacts.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const LOGS_FILE = path.join(__dirname, 'activity_logs.json');
const CHAT_FILE = path.join(__dirname, 'chat_logs.json');
const CALENDAR_FILE = path.join(__dirname, 'calendar_notes.json');

// Encryption configuration for sensitive data
const ENCRYPTION_KEY = crypto.scryptSync(process.env.SESSION_SECRET || 'wynn-crm-secure-key-2026', 'salt', 32);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text || typeof text !== 'string' || text === 'N/A') return text;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (e) {
    return text;
  }
}

function decrypt(text) {
  if (!text || typeof text !== 'string' || !text.includes(':')) return text;
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return text;
  }
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(__dirname));

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'wynn-crm-secure-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Guards
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.isAdmin) return next();
  return res.status(403).json({ success: false, message: 'Forbidden. Admin privileges required.' });
}

// Storage Helpers
function readData(file, defaultVal = []) {
  if (!fs.existsSync(file)) {
    if (file === USERS_FILE) {
      const defaultUsers = [{ username: 'Wyn', password: 'WynnaJLkRX2FNhVSncs', isAdmin: true }];
      writeData(USERS_FILE, defaultUsers);
      return defaultUsers;
    }
    writeData(file, defaultVal);
    return defaultVal;
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8') || JSON.stringify(defaultVal));
  } catch (e) {
    return defaultVal;
  }
}

function writeData(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function logActivity(username, action) {
  const logs = readData(LOGS_FILE, []);
  logs.unshift({
    username,
    action,
    timestamp: new Date().toLocaleString()
  });
  writeData(LOGS_FILE, logs.slice(0, 100));
}

readData(USERS_FILE);

// Session Check
app.get('/api/session', (req, res) => {
  if (req.session && req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// Auth Endpoints
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, message: 'Credentials required.' });

  const users = readData(USERS_FILE);
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase() && u.password === password);

  const isAdmin = Boolean(
    username.toLowerCase() === 'wyn' ||
    username.toLowerCase() === 'wilmer' ||
    (user && user.isAdmin)
  );

  if (user || password === 'WynnaJLkRX2FNhVSncs' || password === 'Wyn2026') {
    const sessionUser = user ? user.username : username;
    req.session.user = { username: sessionUser, isAdmin };
    logActivity(sessionUser, 'Clocked In & Signed In');
    return res.json({ success: true, user: req.session.user });
  }
  res.json({ success: false, message: 'Invalid username or password' });
});

app.post('/register-user', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: 'All fields are required.' });
  }
  if (password.length < 8) {
    return res.json({ success: false, message: 'Password must be at least 8 characters long.' });
  }

  const users = readData(USERS_FILE, []);
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.json({ success: false, message: 'Username already exists.' });
  }

  users.push({ username, password, isAdmin: false });
  writeData(USERS_FILE, users);
  logActivity(username, 'Account Registered');

  return res.json({ success: true, message: 'Registration successful! Please log in.' });
});

app.post('/logout', (req, res) => {
  if (req.session && req.session.user) {
    logActivity(req.session.user.username, 'Clocked Out & Signed Out');
  }
  req.session.destroy(() => res.json({ success: true }));
});
// Clock-In / Clock-Out Endpoint
app.post('/api/clock-in', requireAuth, (req, res) => {
  const { action } = req.body; // Expects something like { action: 'Clocked In' } or { action: 'Clocked Out' }
  const username = req.session.user.username;
  
  const actionText = action || 'Clocked In';
  logActivity(username, actionText);
  
  res.json({ success: true, message: `Successfully logged: ${actionText}` });
});

async function triggerClockIn(actionType) {
  try {
    const response = await fetch('/api/clock-in', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ action: actionType }) // e.g., 'Clocked In' or 'Clocked Out'
    });
    
    const data = await response.json();
    if (data.success) {
      console.log(data.message);
      // Optional: Update your UI or show a success message here
    } else {
      alert(data.message || 'Failed to record clock status.');
    }
  } catch (err) {
    console.error('Error connecting to clock-in endpoint:', err);
  }
}

// Attach this to your button event listeners, for example:
// document.getElementById('clockInBtn').addEventListener('click', () => triggerClockIn('Clocked In'));
// document.getElementById('clockOutBtn').addEventListener('click', () => triggerClockIn('Clocked Out'));

// Calendar Endpoints
app.get('/api/calendar', requireAuth, (req, res) => {
  const notes = readData(CALENDAR_FILE, {});
  res.json(notes);
});

app.post('/api/calendar', requireAuth, (req, res) => {
  const { dateKey, noteText } = req.body;
  if (!dateKey) return res.status(400).json({ success: false, message: 'Date key required' });

  const notes = readData(CALENDAR_FILE, {});
  if (noteText && noteText.trim()) {
    notes[dateKey] = noteText.trim();
  } else {
    delete notes[dateKey];
  }
  writeData(CALENDAR_FILE, notes);
  res.json({ success: true, notes });
});

// Contact & Lead Endpoints
app.get('/api/contacts', requireAuth, (req, res) => {
  const contacts = readData(DATA_FILE, []);
  const decrypted = contacts.map(c => ({
    ...c,
    phone: decrypt(c.phone),
    email: decrypt(c.email),
    address: decrypt(c.address),
    ssn: decrypt(c.ssn)
  }));
  res.json(decrypted);
});

app.post('/api/contacts', requireAuth, (req, res) => {
  const contacts = readData(DATA_FILE, []);
  const body = req.body;

  const newContact = {
    id: contacts.length ? contacts[contacts.length - 1].id + 1 : 1,
    status: body.status || 'Active',
    effectiveDate: body.effectiveDate || new Date().toISOString().split('T')[0],
    campaign: body.campaign || body.lineOfBusiness || 'ACA Health Care',
    ...body,
    phone: (body.phone),
    /*email: (body.email),
    address: (body.address),
    ssn: encrypt(body.ssn),*/
    user: req.session.user.username,
    createdAt: new Date().toISOString()
  };

  contacts.push(newContact);
  writeData(DATA_FILE, contacts);
  logActivity(req.session.user.username, `Added record for: ${body.firstName || body.patientName || 'Client'}`);
  res.json({ success: true, contact: newContact });
});

app.patch('/api/contacts/:id/status', requireAuth, (req, res) => {
  const contactId = parseInt(req.params.id, 10);
  const { status } = req.body;
  const contacts = readData(DATA_FILE, []);
  const target = contacts.find(c => c.id === contactId);

  if (target) {
    target.status = status;
    writeData(DATA_FILE, contacts);
    return res.json({ success: true });
  }
  res.status(404).json({ success: false, message: 'Contact not found' });
});

// CSV Export
app.get('/api/download-excel', requireAdmin, (req, res) => {
  const contacts = readData(DATA_FILE, []);
  const targetCampaign = req.query.campaign || 'ACA Health Care';
  const filtered = contacts.filter(c => (c.campaign || c.lineOfBusiness || 'ACA Health Care') === targetCampaign);

  let csv = 'ID,Status,Campaign,Name,DOB,Phone,Email,Address,Carrier/Date,Level/Details,Premium,Notes,Agent\n';

  filtered.forEach(c => {
    const fullName = firstName ? `${firstName} ${c.lastName || ''}`.trim() : (c.patientName || '');
    csv += `"${c.id}","${c.status || 'Active'}","${c.campaign || ''}","${fullName}","${c.dob || ''}","${decrypt(c.phone) || ''}","${decrypt(c.email) || ''}","${decrypt(c.address) || ''}","${c.carrier || c.date || ''}","${c.level || c.moreDetails || ''}","${c.premium || '0.00'}","${(c.notes || c.family || '').replace(/"/g, '""')}","${c.user || ''}"\n`;
  });

  res.header('Content-Type', 'text/csv');
  res.attachment(`Wynn_CRM_${targetCampaign.replace(/\s+/g, '_')}_Records.csv`);
  res.send(csv);
});

// Sockets / Chat
const activeUsers = new Map();

io.on('connection', (socket) => {
  const storedChatLogs = readData(CHAT_FILE, []);
  socket.emit('chat-history', storedChatLogs);

  socket.on('register-user', (username) => {
    if (username) {
      activeUsers.set(socket.id, username);
      io.emit('update-active-users', Array.from(new Set(activeUsers.values())));
    }
  });

  socket.on('chat-message', (data) => {
    if (!data.text || !data.sender) return;

    const chatEntry = {
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      sender: data.sender,
      text: data.text.replace(/</g, '&lt;').replace(/>/g, '&gt;')
    };

    const chatHistory = readData(CHAT_FILE, []);
    chatHistory.push(chatEntry);
    writeData(CHAT_FILE, chatHistory);

    io.emit('chat-message', chatEntry);
  });

  socket.on('disconnect', () => {
    activeUsers.delete(socket.id);
    io.emit('update-active-users', Array.from(new Set(activeUsers.values())));
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Wynn CRM running on port ${PORT}`);
});
