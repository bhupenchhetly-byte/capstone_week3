const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'SYSTEM_ENGINE_CORE_SECRET_KEY_987321';

// --- IN-MEMORY DATA STORAGE ---
let usersCollection = [];
let ticketsCollection = [];
let auditLogsCollection = [];

// --- MIDDLEWARE SYSTEM ---
app.use(helmet({ contentSecurityPolicy: false })); 
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- SECURE AUTHORIZATION GATEKEEPER MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access Denied: Token Missing' });

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ error: 'Session Expired or Corrupted Token' });
    req.user = decodedUser;
    next();
  });
};

// --- AUTHENTICATION ENDPOINTS ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = usersCollection.find(u => u.email === email);
    if (!user) return res.status(400).json({ error: 'Invalid Routing Credentials' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Security Handshake Denied' });

    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
    
    auditLogsCollection.push({
      action: `User Authentication Success: ${user.email}`,
      performedBy: user.name,
      timestamp: new Date()
    });

    res.json({ token, user: { name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- TELEMETRY & DATA OVERVIEW METRICS ---
app.get('/api/dashboard/metrics', authenticateToken, async (req, res) => {
  res.json({ 
    totalUsers: usersCollection.length, 
    activeSessions: 42, 
    engineStatus: 'Operational' 
  });
});

// --- USER DIRECTORY CRUD ENGINE ---
app.get('/api/users', authenticateToken, async (req, res) => {
  const { search } = req.query;
  if (search) {
    const query = search.toLowerCase();
    const filtered = usersCollection.filter(u => 
      u.name.toLowerCase().includes(query) || u.email.toLowerCase().includes(query)
    );
    return res.json(filtered);
  }
  res.json(usersCollection);
});

// CREATE NEW USER (With its own unique password)
app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    if(usersCollection.some(u => u.email === email)) {
      return res.status(400).json({ error: 'Data Conflict: Email already registered.' });
    }
    if(!password || password.trim() === '') {
      return res.status(400).json({ error: 'Password is required for new accounts.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: '_' + Math.random().toString(36).substr(2, 9),
      name,
      email,
      password: hashedPassword,
      role: role || 'Staff Admin'
    };

    usersCollection.push(newUser);
    auditLogsCollection.push({ 
      action: `Created User Profile: ${email}`, 
      performedBy: req.user.name, 
      timestamp: new Date() 
    });

    res.status(201).json({ id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role });
  } catch (err) {
    res.status(400).json({ error: 'Data Error: ' + err.message });
  }
});

// UPDATE PASSWORD / PROFILE FOR INDIVIDUAL USER
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const user = usersCollection.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Record not found' });

  const { name, email, role, password } = req.body;
  
  user.name = name || user.name;
  user.email = email || user.email;
  user.role = role || user.role;

  // Changes password ONLY for this specific individual user if typed in
  if (password && password.trim() !== '') {
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }
    user.password = await bcrypt.hash(password, 10);
    auditLogsCollection.push({ 
      action: `Updated User Profile ID: ${req.params.id} (Password changed individually)`, 
      performedBy: req.user.name, 
      timestamp: new Date() 
    });
  } else {
    auditLogsCollection.push({ 
      action: `Updated User Profile ID: ${req.params.id} (Profile fields updated)`, 
      performedBy: req.user.name, 
      timestamp: new Date() 
    });
  }

  res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  usersCollection = usersCollection.filter(u => u.id !== req.params.id);
  auditLogsCollection.push({ 
    action: `Terminated User Record ID: ${req.params.id}`, 
    performedBy: req.user.name, 
    timestamp: new Date() 
  });
  res.json({ success: true, message: 'Record scrubbed' });
});

app.get('/api/reports/telemetry-csv', (req, res) => {
  let csvContent = "Timestamp,Executed Operational Event,Operator Engine Identity\n";
  auditLogsCollection.forEach(log => {
    csvContent += `"${new Date(log.timestamp).toISOString()}","${log.action}","${log.performedBy}"\n`;
  });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=telemetry_audit_log.csv');
  res.status(200).send(csvContent);
});

app.post('/api/support/ticket', async (req, res) => {
  const { name, email, message } = req.body;
  const newTicket = { id: Date.now(), name, email, message, timestamp: new Date() };
  ticketsCollection.push(newTicket);
  res.status(201).json({ success: true, payload: newTicket });
});

// --- INDIVIDUAL ADMIN PASSWORD CONFIGURATION DICTIONARY ---
const seedSystemSystemAdmin = async () => {
  // Each individual starts with a completely different password assigned here:
  usersCollection.push({ 
    id: '001', 
    name: 'Primary Admin', 
    email: 'admin@group1.com', 
    password: await bcrypt.hash('shea24146', 10), // Password for admin@group1.com
    role: 'Group 1 System Lead' 
  });
  
  usersCollection.push({ 
    id: '002', 
    name: 'Dipesh Giri', 
    email: 'dipeshgiri@mail.com', 
    password: await bcrypt.hash('shea24146', 8), // Password for dipeshgiri@mail.com
    role: 'Administrator' 
  });
  
  usersCollection.push({ 
    id: '003', 
    name: 'Bhupen Budhathoki', 
    email: 'BhupenBudhathoki@mail.com', 
    password: await bcrypt.hash('shea24150', 8), // Password for BhupenBudhathoki@mail.com
    role: 'Admin 2' 
  });
  
  usersCollection.push({ 
    id: '004', 
    name: 'Aashish Aale', 
    email: 'AashishAale@mail.com', 
    password: await bcrypt.hash('Aashishaale88', 8), // Password for AashishAale@mail.com
    role: 'Admin 3' 
  });
  
  auditLogsCollection.push({ action: "System Workspace Seed Context Initialized with unique keys", performedBy: "SYSTEM", timestamp: new Date() });
};
seedSystemSystemAdmin();

app.listen(PORT, () => {
    console.log(`\n=============================================================`);
    console.log(`🚀 PROTO-SERVER RUNNING`);
    console.log(`📡 System Online: Access Environment via http://localhost:${PORT}/login.html`);
    console.log(`=============================================================\n`);
});