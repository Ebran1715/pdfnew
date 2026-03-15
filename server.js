const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(896089467724-crir8t378v8kd0qm39pj5d6rlsb77qcl.apps.googleusercontent.com);
const logger   = require('./activity-logger');
const express  = require('express');
const bodyParser = require('body-parser');
const cors     = require('cors');
const dotenv   = require('dotenv');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const fs       = require('fs');
const { v4: uuidv4 } = require('uuid');
const multer   = require('multer');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const { encryptPDFBuffer, decryptPDFBuffer, isPDFEncrypted } = require('./pdf-encryptor');

dotenv.config();

// ==================== ADMIN CREDENTIALS ====================
const ADMIN_EMAIL    = 'admin@pdfworks.com'; // ← change this
const ADMIN_PASSWORD = 'admin123';            // ← change this

// ==================== JSON FILE DATABASE ====================
const DB_FILE = path.join(__dirname, 'users.json');

function readDB() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], sessions: [], activity: [] }));
        }
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch(e) {
        return { users: [], sessions: [], activity: [] };
    }
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function findUser(email) {
    return readDB().users.find(u => u.email === email);
}

function saveUser(user) {
    const db = readDB();
    const existingIndex = db.users.findIndex(u => u.email === user.email);
    
    if (existingIndex >= 0) {
        // Update existing user
        db.users[existingIndex] = { ...db.users[existingIndex], ...user };
    } else {
        // Add new user
        db.users.push(user);
    }
    
    writeDB(db);
}

function saveSession(session) {
    const db = readDB();
    db.sessions.push(session);
    // Keep last 1000 sessions only
    if (db.sessions.length > 1000) db.sessions = db.sessions.slice(-1000);
    writeDB(db);
}

function deleteSession(token) {
    const db = readDB();
    db.sessions = db.sessions.filter(s => s.token !== token);
    writeDB(db);
}

function logUserActivity(userId, action, ip, extra = {}) {
    const db = readDB();
    db.activity.push({
        id: uuidv4(),
        user_id: userId,
        action,
        ip,
        timestamp: new Date().toISOString(),
        ...extra
    });
    if (db.activity.length > 10000) db.activity = db.activity.slice(-10000);
    writeDB(db);
}

console.log('✅ Using JSON file database (no MySQL needed)');

const app = express();

// ==================== CORS ====================
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
// Add this after your cors setup
app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ==================== STATIC FILES ====================
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });
app.use(express.static(publicDir));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

// ==================== MULTER ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename:    (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});

const fileFilter = (req, file, cb) => {
    const allowed = [
        'application/pdf','image/jpeg','image/png','image/jpg',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    cb(null, allowed.includes(file.mimetype));
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 50 * 1024 * 1024 } });

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError')  return res.status(403).json({ error: 'Token expired' });
            if (err.name === 'JsonWebTokenError')  return res.status(403).json({ error: 'Invalid token' });
            return res.status(403).json({ error: 'Invalid token: ' + err.message });
        }
        req.user = user;
        next();
    });
};

// ==================== ADMIN MIDDLEWARE ====================
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    console.log('🔑 Admin login attempt:', email);
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ email, role: 'admin' }, 'your-secret-key', { expiresIn: '24h' });
        res.json({ token, email });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

const requireAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        if (user.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
        req.user = user;
        next();
    });
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
        return res.status(400).json({ error: 'All fields are required' });

    if (findUser(email))
        return res.status(400).json({ error: 'Email already registered' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = {
            id: uuidv4(),
            name,
            email,
            password: hashedPassword,
            is_premium: false,
            created_at: new Date().toISOString(),
            last_login: null
        };
        saveUser(user);

        const token = jwt.sign({ id: user.id, email, name }, 'your-secret-key', { expiresIn: '7d' });
        logger.logLogin(email, req.ip || '127.0.0.1');

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: user.id, name, email, is_premium: false }
        });
    } catch(err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email and password are required' });

    const user = findUser(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name },
        'your-secret-key',
        { expiresIn: '7d' }
    );

    // Save session
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    saveSession({ user_id: user.id, token, ip: req.ip || '127.0.0.1', expires_at: expiresAt.toISOString() });

    // Update last login
    user.last_login = new Date().toISOString();
    saveUser(user);

    logUserActivity(user.id, 'login', req.ip || '127.0.0.1');
    logger.logLogin(user.email, req.ip || '127.0.0.1');

    res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, name: user.name, email: user.email, is_premium: user.is_premium }
    });
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    deleteSession(token);
    logUserActivity(req.user.id, 'logout', req.ip || '127.0.0.1');
    logger.logLogout(req.user.email, req.ip || '127.0.0.1');
    res.json({ message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    const user = readDB().users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
        user: {
            id: user.id, name: user.name, email: user.email,
            is_premium: user.is_premium,
            created_at: user.created_at, last_login: user.last_login
        }
    });
});
                    // Google Login
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        // Verify Google token
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: 896089467724-crir8t378v8kd0qm39pj5d6rlsb77qcl.apps.googleusercontent.com

        });

        const payload = ticket.getPayload();
        const { name, email, picture, sub: googleId } = payload;

        if (!email) {
            return res.status(400).json({ error: 'Could not get email from Google' });
        }

        // Check if user exists
        let user = findUser(email);

        if (!user) {
            // Create new user
            user = {
                id: Date.now().toString(),
                name: name,
                email: email,
                picture: picture,
                googleId: googleId,
                provider: 'google',
                createdAt: new Date().toISOString()
            };
            saveUser(user);
            console.log('New Google user created:', email);
        } else {
            // Update existing user with Google info
            user.picture = picture;
            user.googleId = googleId;
            user.provider = 'google';
            saveUser(user);
        }

        // Create session
        const sessionToken = Math.random().toString(36).substring(2) + 
                            Date.now().toString(36) + 
                            Math.random().toString(36).substring(2);
        
        saveSession(sessionToken, email);

        // Log activity
        logUserActivity(email, 'google_login', {
            name: user.name,
            provider: 'google'
        });

        res.json({
            token: sessionToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                picture: user.picture,
                provider: 'google'
            }
        });

    } catch (error) {
        console.error('Google auth error:', error);
        res.status(401).json({ error: 'Google authentication failed' });
    }
});

// ==================== USER STATS ====================
app.get('/api/stats', authenticateToken, (req, res) => {
    const db       = readDB();
    const activity = db.activity.filter(a => a.user_id === req.user.id);
    const today    = new Date().toISOString().split('T')[0];
    res.json({
        stats: {
            total_activities:  activity.length,
            today_activities:  activity.filter(a => a.timestamp.startsWith(today)).length,
            tools_used:        new Set(activity.filter(a => a.tool).map(a => a.tool)).size,
            active_sessions:   db.sessions.filter(s => s.user_id === req.user.id && new Date(s.expires_at) > new Date()).length
        }
    });
});

// ==================== PROTECT PDF ====================
app.post('/api/protect-pdf', upload.single('file'), async (req, res) => {
    try {
        const password = req.body.password;
        if (!password) return res.status(400).json({ error: 'Password missing' });
        if (!req.file)  return res.status(400).json({ error: 'No file uploaded' });

        const pdfBuffer      = fs.readFileSync(req.file.path);
        const encryptedBuffer = await encryptPDFBuffer(pdfBuffer, password);
        logger.logToolUse(req.user?.email || 'guest', 'protect-pdf', req.file.originalname, req.file.size);
        fs.unlinkSync(req.file.path);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="protected.pdf"');
        res.send(encryptedBuffer);
    } catch(err) {
        console.error('Protect PDF error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== UNPROTECT PDF ====================
app.post('/api/unprotect-pdf', upload.single('file'), async (req, res) => {
    try {
        const password = req.body.password || '';
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const pdfBuffer = fs.readFileSync(req.file.path);
        fs.unlink(req.file.path, () => {});

        const decrypted = await decryptPDFBuffer(pdfBuffer, password);
        logger.logToolUse(req.user?.email || 'guest', 'unprotect-pdf', req.file.originalname, req.file.size);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="unlocked.pdf"');
        res.send(decrypted);
    } catch(err) {
        console.error('Unprotect PDF error:', err.message);
        if (err.message === 'Incorrect password')
            return res.status(400).json({ error: 'Incorrect password' });
        res.status(500).json({ error: err.message });
    }
});

// ==================== LOG ALL TOOLS ====================
app.post('/api/log-tool', (req, res) => {
    const { tool, filename, filesize, email, type } = req.body;
    if (type === 'download') {
        logger.logDownload(email || 'guest', tool, filename);
    } else {
        logger.logToolUse(email || 'guest', tool, filename, filesize);
    }
    res.json({ ok: true });
});

// ==================== ACTIVITY ROUTES ====================
app.post('/api/activity/view', authenticateToken, (req, res) => {
    const { tool, fileName } = req.body;
    logUserActivity(req.user.id, 'view', req.ip, { tool, file_name: fileName });
    res.json({ message: 'View logged' });
});

app.post('/api/activity/download', authenticateToken, (req, res) => {
    const { tool, fileName, format, pageCount } = req.body;
    logUserActivity(req.user.id, 'download', req.ip, { tool, file_name: fileName, format, pages: pageCount });
    res.json({ message: 'Download logged' });
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/activity', requireAdmin, (req, res) => {
    const { type, email, tool, limit = 200, offset = 0 } = req.query;
    let entries = logger.getAll();
    if (type)  entries = entries.filter(e => e.type  === type);
    if (email) entries = entries.filter(e => e.email === email);
    if (tool)  entries = entries.filter(e => e.tool  === tool);
    const total = entries.length;
    res.json({ total, entries: entries.slice(parseInt(offset), parseInt(offset) + parseInt(limit)) });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const all = logger.getAll();
    res.json({
        total:        all.length,
        logins:       all.filter(e => e.type === 'login').length,
        tool_uses:    all.filter(e => e.type === 'tool_use').length,
        downloads:    all.filter(e => e.type === 'download').length,
        users:        [...new Set(all.map(e => e.email).filter(Boolean))].length,
        tools:        all.reduce((acc, e) => { if (e.tool) acc[e.tool] = (acc[e.tool]||0)+1; return acc; }, {}),
        recent_users: [...new Set(all.slice(0,50).map(e => e.email).filter(Boolean))].slice(0,10),
    });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
    const users = readDB().users.map(u => ({
        id: u.id, name: u.name, email: u.email,
        is_premium: u.is_premium, created_at: u.created_at, last_login: u.last_login
    }));
    res.json({ users, total: users.length });
});

app.delete('/api/admin/activity', requireAdmin, (req, res) => {
    fs.writeFileSync(path.join(__dirname, 'activity.json'), '[]');
    res.json({ message: 'Activity log cleared' });
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running', timestamp: new Date().toISOString() });
});

// ==================== SERVE INDEX.HTML ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/check-token', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3009;
app.listen(PORT, () => {
    console.log(`\n🚀 Server running on port ${PORT}`);
    console.log(`📁 Website: http://localhost:${PORT}`);
    console.log(`📁 Admin:   http://localhost:${PORT}/admin.html`);
    console.log(`📁 Health:  http://localhost:${PORT}/api/health`);
    console.log(`📁 Uploads: ${uploadDir}`);
    console.log(`\n✅ JSON file database — no MySQL needed!`);
});