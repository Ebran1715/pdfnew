const logger = require('./activity-logger');
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const { encryptPDFBuffer, decryptPDFBuffer, isPDFEncrypted } = require('./pdf-encryptor');


dotenv.config();

const app = express();

// CORS configuration
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
}
app.use(express.static(publicDir));

// Create uploads directory
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
app.use('/uploads', express.static(uploadDir));

// MySQL connection for XAMPP
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'pdfworks_db',
    connectionLimit: 10
};

const pool = mysql.createPool(dbConfig);

// Test database connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        return;
    }
    console.log('✅ Connected to MySQL database');
    connection.release();
});

// ==================== MULTER CONFIGURATION ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'application/pdf', 'image/jpeg', 'image/png', 'image/jpg',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 50 * 1024 * 1024 }
});

// ==================== MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    console.log('🔐 Auth header received:', authHeader ? 'Present' : 'Missing');
    console.log('🔑 Token:', token ? token.substring(0, 30) + '...' : 'No token');

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) {
            console.log('❌ Token verification failed:', err.message);
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ error: 'Token expired' });
            }
            if (err.name === 'JsonWebTokenError') {
                return res.status(403).json({ error: 'Invalid token signature' });
            }
            return res.status(403).json({ error: 'Invalid token: ' + err.message });
        }
        console.log('✅ Token verified for user:', user.email || user.id);
        req.user = user;
        next();
    });
};

// ==================== ADMIN MIDDLEWARE ====================
const ADMIN_EMAIL = 'admin@pdfworks.com';
const ADMIN_PASSWORD = 'admin123'; // ← change this

// Admin login route (no database)
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    console.log('🔑 Admin login attempt - email:', email, '| password:', password);
    console.log('🔑 Expected - email:', ADMIN_EMAIL, '| password:', ADMIN_PASSWORD);
    
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        const token = jwt.sign(
            { email, role: 'admin' },
            'your-secret-key',
            { expiresIn: '24h' }
        );
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
        if (user.role !== 'admin')
            return res.status(403).json({ error: 'Admin access only' });
        req.user = user;
        next();
    });
};

// ==================== DEBUG TOKEN ENDPOINT ====================
app.post('/api/debug-token', (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, 'your-secret-key');
        res.json({
            valid: true,
            decoded,
            expires: new Date(decoded.exp * 1000).toISOString()
        });
    } catch (err) {
        res.json({ valid: false, error: err.message, name: err.name });
    }
});

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        pool.query('SELECT id FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (results.length > 0) {
                return res.status(400).json({ error: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const userUuid = uuidv4();

            pool.query(
                'INSERT INTO users (uuid, name, email, password, is_premium) VALUES (?, ?, ?, ?, ?)',
                [userUuid, name, email, hashedPassword, false],
                (err, result) => {
                    if (err) {
                        console.error('Insert error:', err);
                        return res.status(500).json({ error: 'Failed to create user' });
                    }

                    const token = jwt.sign(
                        { id: result.insertId, email, name },
                        'your-secret-key',
                        { expiresIn: '7d' }
                    );

                    logger.logLogin(email, '127.0.0.1');

                    res.status(201).json({
                        message: 'User created successfully',
                        token,
                        user: { id: result.insertId, name, email, is_premium: false }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    pool.query(
        'SELECT id, name, email, password, is_premium FROM users WHERE email = ?',
        [email],
        async (err, results) => {
            if (err) {
                console.error('Login query error:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = results[0];

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                'your-secret-key',
                { expiresIn: '7d' }
            );

            // Save session to DB
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 7);
            pool.query(
                'INSERT INTO user_sessions (user_id, token, ip_address, expires_at) VALUES (?, ?, ?, ?)',
                [user.id, token, req.ip || '127.0.0.1', expiresAt],
                (err) => { if (err) console.error('Failed to create session:', err); }
            );

            // Log to DB
            pool.query(
                'INSERT INTO user_activity (user_id, action, ip_address) VALUES (?, ?, ?)',
                [user.id, 'login', req.ip || '127.0.0.1'],
                (err) => { if (err) console.error('Failed to log activity:', err); }
            );

            // Update last login
            pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

            // ✅ Log to activity.json
            logger.logLogin(user.email, req.ip || '127.0.0.1');

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    is_premium: user.is_premium === 1 ? true : false
                }
            });
        }
    );
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    pool.query(
        'DELETE FROM user_sessions WHERE token = ?',
        [token],
        (err) => { if (err) console.error('Logout error:', err); }
    );

    pool.query(
        'INSERT INTO user_activity (user_id, action, ip_address) VALUES (?, ?, ?)',
        [req.user.id, 'logout', req.ip],
        (err) => { if (err) console.error('Failed to log activity:', err); }
    );

    // ✅ Log to activity.json
    logger.logLogout(req.user.email, req.ip || '127.0.0.1');

    res.json({ message: 'Logged out successfully' });
});

// ==================== FILE UPLOAD ROUTES ====================
app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileUuid = uuidv4();
    const userId = req.user.id;

    pool.query(
        `INSERT INTO user_files (user_id, file_uuid, original_name, file_path, file_size, mime_type)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, fileUuid, req.file.originalname, req.file.filename, req.file.size, req.file.mimetype],
        (err, result) => {
            if (err) {
                console.error('File record error:', err);
                fs.unlinkSync(req.file.path);
                return res.status(500).json({ error: 'Failed to save file record' });
            }

            pool.query(
                'INSERT INTO user_activity (user_id, action, tool_used, file_name, file_size, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
                [userId, 'file_upload', req.body.tool || 'upload', req.file.originalname, req.file.size, req.ip],
                (err) => { if (err) console.error('Failed to log activity:', err); }
            );

            res.json({
                message: 'File uploaded successfully',
                file: {
                    id: result.insertId,
                    uuid: fileUuid,
                    name: req.file.originalname,
                    size: req.file.size,
                    path: `/uploads/${req.file.filename}`
                }
            });
        }
    );
});

// ==================== PROTECT PDF ====================
app.post('/api/protect-pdf', upload.single('file'), async (req, res) => {
    try {
        console.log("🔒 Protect route hit");
        const password = req.body.password;
        console.log("📦 Received password:", password);

        if (!password) return res.status(400).json({ error: 'Password missing' });
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const pdfBuffer = fs.readFileSync(req.file.path);
        console.log("🔐 Encrypting PDF with pure JS...");
        const encryptedBuffer = await encryptPDFBuffer(pdfBuffer, password);
        console.log("✅ Encryption done");

        // ✅ Log to activity.json
        logger.logToolUse(req.user?.email || 'guest', 'protect-pdf', req.file.originalname, req.file.size);

        fs.unlinkSync(req.file.path);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="protected.pdf"');
        res.send(encryptedBuffer);

    } catch (err) {
        console.error("❌ Protect PDF error:", err);
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

        // ✅ Log to activity.json
        logger.logToolUse(req.user?.email || 'guest', 'unprotect-pdf', req.file.originalname, req.file.size);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="unlocked.pdf"');
        res.send(decrypted);

    } catch (err) {
        console.error('❌ Unprotect PDF error:', err.message);
        if (err.message === 'Incorrect password') {
            return res.status(400).json({ error: 'Incorrect password' });
        }
        res.status(500).json({ error: err.message });
    }
});

// ==================== LOG ALL TOOLS (frontend calls this) ====================
app.post('/api/log-tool', (req, res) => {
    const { tool, filename, filesize, email } = req.body;
    logger.logToolUse(email || 'guest', tool, filename, filesize);
    res.json({ ok: true });
});

// ==================== TOOL USAGE ROUTES (DB) ====================
app.post('/api/activity/tool', authenticateToken, (req, res) => {
    const { tool, action, fileName, fileSize, details } = req.body;
    pool.query(
        `INSERT INTO user_activity (user_id, action, tool_used, file_name, file_size, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, action || 'tool_use', tool, fileName, fileSize, details ? JSON.stringify(details) : null, req.ip],
        (err) => {
            if (err) {
                console.error('Failed to log activity:', err);
                return res.status(500).json({ error: 'Failed to log activity' });
            }
            res.json({ message: 'Activity logged' });
        }
    );
});

app.post('/api/activity/view', authenticateToken, (req, res) => {
    const { tool, fileName, fileId } = req.body;
    pool.query(
        `INSERT INTO user_activity (user_id, action, tool_used, file_name, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.user.id, 'view', tool, fileName, JSON.stringify({ fileId }), req.ip],
        (err) => {
            if (err) {
                console.error('Failed to log view:', err);
                return res.status(500).json({ error: 'Failed to log view' });
            }
            res.json({ message: 'View logged' });
        }
    );
});

app.post('/api/activity/download', authenticateToken, (req, res) => {
    const { tool, fileName, fileId, format, pageCount } = req.body;
    pool.query(
        `INSERT INTO user_activity (user_id, action, tool_used, file_name, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.user.id, 'download', tool, fileName, JSON.stringify({ fileId, format, pages: pageCount }), req.ip],
        (err) => {
            if (err) {
                console.error('Failed to log download:', err);
                return res.status(500).json({ error: 'Failed to log download' });
            }
            res.json({ message: 'Download logged' });
        }
    );
});

// ==================== GET DATA ROUTES ====================
app.get('/api/files', authenticateToken, (req, res) => {
    pool.query(
        `SELECT id, file_uuid, original_name, file_size, mime_type, created_at
         FROM user_files WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
        [req.user.id],
        (err, results) => {
            if (err) {
                console.error('Error fetching files:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ files: results });
        }
    );
});

app.get('/api/activity', authenticateToken, (req, res) => {
    const { limit = 20, offset = 0 } = req.query;
    pool.query(
        `SELECT action, tool_used, file_name, file_size, details, ip_address, created_at
         FROM user_activity WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [req.user.id, parseInt(limit), parseInt(offset)],
        (err, results) => {
            if (err) {
                console.error('Error fetching activity:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            pool.query(
                'SELECT COUNT(*) as total FROM user_activity WHERE user_id = ?',
                [req.user.id],
                (err, countResult) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    res.json({
                        activities: results,
                        total: countResult[0].total,
                        limit: parseInt(limit),
                        offset: parseInt(offset)
                    });
                }
            );
        }
    );
});

app.get('/api/sessions', authenticateToken, (req, res) => {
    pool.query(
        `SELECT id, ip_address, created_at, expires_at
         FROM user_sessions WHERE user_id = ? AND expires_at > NOW() ORDER BY created_at DESC`,
        [req.user.id],
        (err, results) => {
            if (err) {
                console.error('Error fetching sessions:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ sessions: results });
        }
    );
});

app.get('/api/stats', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];
    pool.query(
        `SELECT 
            (SELECT COUNT(*) FROM user_activity WHERE user_id = ?) as total_activities,
            (SELECT COUNT(*) FROM user_files WHERE user_id = ?) as total_files,
            (SELECT COALESCE(SUM(file_size), 0) FROM user_files WHERE user_id = ?) as total_storage,
            (SELECT COUNT(*) FROM user_activity WHERE user_id = ? AND DATE(created_at) = ?) as today_activities,
            (SELECT COUNT(DISTINCT tool_used) FROM user_activity WHERE user_id = ?) as tools_used,
            (SELECT COUNT(*) FROM user_sessions WHERE user_id = ? AND expires_at > NOW()) as active_sessions`,
        [userId, userId, userId, userId, today, userId, userId],
        (err, results) => {
            if (err) {
                console.error('Stats error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ stats: results[0] });
        }
    );
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    pool.query(
        'SELECT id, name, email, is_premium, created_at, last_login FROM users WHERE id = ?',
        [req.user.id],
        (err, results) => {
            if (err || results.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = results[0];
            res.json({
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    is_premium: user.is_premium === 1 ? true : false,
                    created_at: user.created_at,
                    last_login: user.last_login
                }
            });
        }
    );
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/activity', requireAdmin, (req, res) => {
    const { type, email, tool, limit = 200, offset = 0 } = req.query;

    let entries = logger.getAll();
    if (type)  entries = entries.filter(e => e.type  === type);
    if (email) entries = entries.filter(e => e.email === email);
    if (tool)  entries = entries.filter(e => e.tool  === tool);

    const total = entries.length;
    const paginated = entries.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
    res.json({ total, entries: paginated });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const all = logger.getAll();
    const stats = {
        total:        all.length,
        logins:       all.filter(e => e.type === 'login').length,
        tool_uses:    all.filter(e => e.type === 'tool_use').length,
        downloads:    all.filter(e => e.type === 'download').length,
        users:        [...new Set(all.map(e => e.email).filter(Boolean))].length,
        tools:        all.reduce((acc, e) => {
            if (e.tool) acc[e.tool] = (acc[e.tool] || 0) + 1;
            return acc;
        }, {}),
        recent_users: [...new Set(all.slice(0, 50).map(e => e.email).filter(Boolean))].slice(0, 10),
    };
    res.json(stats);
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

// ==================== CHECK TOKEN VALIDITY ====================
app.get('/api/check-token', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ==================== TEST ENDPOINT ====================
app.post('/api/test-upload', authenticateToken, (req, res) => {
    console.log('🧪 TEST ENDPOINT HIT');
    res.json({
        message: 'Test successful',
        receivedBody: req.body,
        hasPassword: !!req.body.password,
        hasFiles: !!req.files
    });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3009;
app.listen(PORT, () => {
    console.log(`\n🚀 Server running on port ${PORT}`);
    console.log(`📁 Website: http://localhost:${PORT}`);
    console.log(`📁 Admin:   http://localhost:${PORT}/admin.html`);
    console.log(`📁 Health:  http://localhost:${PORT}/api/health`);
    console.log(`📁 Uploads: ${uploadDir}`);
    console.log(`\n✅ Activity logging enabled!`);
});