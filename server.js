require('dotenv').config();

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendEmail(to, subject, html) {
    try {
        console.log('📧 Sending email to:', to);
        await sgMail.send({
            to: to,
            from: {
                email: process.env.EMAIL_USER,
                name: 'PDFWorks Pro'
            },
            subject: subject,
            html: html
        });
        console.log('✅ Email sent to:', to);
    } catch(error) {
        console.error('❌ Email failed:', error.message);
        throw error;
    }
}

console.log('SENDGRID_API_KEY:', process.env.SENDGRID_API_KEY ? '✅ Set' : '❌ NOT SET');
console.log('EMAIL_USER:', process.env.EMAIL_USER || '❌ NOT SET');

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const logger = require('./activity-logger');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const { encryptPDFBuffer, decryptPDFBuffer } = require('./pdf-encryptor');

console.log('EMAIL_USER:', process.env.EMAIL_USER || '❌ NOT SET');
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ Set' : '❌ NOT SET');

// OTP storage
const otpStore = {};

// ==================== ADMIN CREDENTIALS ====================
const ADMIN_EMAIL = 'admin@pdfworks.com';
const ADMIN_PASSWORD = 'admin123';

// ==================== ACTIVITY FILE ====================
const activityFile = path.join(__dirname, 'activity.json');
if (!fs.existsSync(activityFile)) {
    fs.writeFileSync(activityFile, '[]');
}

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
        db.users[existingIndex] = { ...db.users[existingIndex], ...user };
    } else {
        db.users.push(user);
    }
    writeDB(db);
}

function saveSession(session) {
    const db = readDB();
    db.sessions.push(session);
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
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});

const fileFilter = (req, file, cb) => {
    const allowed = [
        'application/pdf', 'image/jpeg', 'image/png', 'image/jpg',
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

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') return res.status(403).json({ error: 'Token expired' });
            if (err.name === 'JsonWebTokenError') return res.status(403).json({ error: 'Invalid token' });
            return res.status(403).json({ error: 'Invalid token: ' + err.message });
        }
        req.user = user;
        next();
    });
};

// ==================== ADMIN ROUTES ====================
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    console.log('🔑 Admin login attempt:', email);
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ email, role: 'admin' }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '24h' });
        res.json({ token, email });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

const requireAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
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

        const token = jwt.sign(
            { id: user.id, email, name },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
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
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = findUser(email);
        if (!user) {
            return res.status(400).json({ error: 'No account found with this email' });
        }

        if (user.provider === 'google') {
            return res.status(400).json({
                error: 'This account uses Google login. Please use the Google button.'
            });
        }

        let passwordMatch = false;
        if (user.password) {
            try {
                passwordMatch = await bcrypt.compare(password, user.password);
            } catch(e) {
                passwordMatch = user.password === password;
            }
        }

        if (!passwordMatch) {
            return res.status(400).json({ error: 'Incorrect password' });
        }

        const sessionToken = Math.random().toString(36).substring(2) +
            Date.now().toString(36) +
            Math.random().toString(36).substring(2);

        saveSession({
            token: sessionToken,
            email: email,
            createdAt: new Date().toISOString()
        });

        try {
            let activities = [];
            try {
                const data = fs.readFileSync(activityFile, 'utf8');
                activities = JSON.parse(data);
                if (!Array.isArray(activities)) activities = [];
            } catch(e) { activities = []; }

            activities.push({
                id: Date.now().toString(),
                tool: 'login',
                email: email,
                type: 'login',
                timestamp: new Date().toISOString()
            });

            fs.writeFileSync(activityFile, JSON.stringify(activities, null, 2));
        } catch(e) {
            console.error('Activity log error:', e);
        }

        res.json({
            token: sessionToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                provider: user.provider || 'email',
                verified: true
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token) deleteSession(token);
        res.json({ message: 'Logged out successfully' });
    } catch(e) {
        res.json({ message: 'Logged out' });
    }
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
        if (!token) return res.status(400).json({ error: 'Token is required' });

        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { name, email, picture, sub: googleId } = payload;

        if (!email) return res.status(400).json({ error: 'Could not get email from Google' });

        let user = findUser(email);

        if (!user) {
            user = {
                id: Date.now().toString(),
                name, email, picture, googleId,
                provider: 'google',
                verified: true,
                createdAt: new Date().toISOString()
            };
            saveUser(user);
            console.log('New Google user created:', email);

            // Send welcome email
            try {
                await sendEmail(
                    email,
                    'Welcome to PDFWorks Pro! 🎉',
                    `
                    <div style="font-family:Arial;max-width:600px;margin:0 auto;">
                        <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:40px;text-align:center;color:white;border-radius:16px 16px 0 0;">
                            <h1>📄 PDFWorks Pro</h1>
                            <p>Welcome aboard! 🎉</p>
                        </div>
                        <div style="padding:40px;background:white;border-radius:0 0 16px 16px;">
                            <h2>Hello, ${name}! 👋</h2>
                            <p>Your account has been created successfully with Google.</p>
                            <p>You now have access to all PDF tools!</p>
                            <a href="https://working-pdf.onrender.com"
                               style="display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:14px 32px;border-radius:30px;text-decoration:none;font-weight:700;margin-top:20px;">
                                🚀 Start Using PDFWorks Pro
                            </a>
                        </div>
                    </div>
                    `
                );
            } catch(emailError) {
                console.error('Welcome email failed:', emailError.message);
            }

        } else {
            user.picture = picture;
            user.googleId = googleId;
            saveUser(user);
        }

        const sessionToken = Math.random().toString(36).substring(2) +
            Date.now().toString(36) +
            Math.random().toString(36).substring(2);

        saveSession({
            token: sessionToken,
            email: email,
            createdAt: new Date().toISOString()
        });

        // Log activity
        try {
            let activities = [];
            try {
                const data = fs.readFileSync(activityFile, 'utf8');
                activities = JSON.parse(data);
                if (!Array.isArray(activities)) activities = [];
            } catch(e) { activities = []; }

            activities.push({
                id: Date.now().toString(),
                tool: 'google_login',
                email: email,
                type: 'login',
                timestamp: new Date().toISOString()
            });

            fs.writeFileSync(activityFile, JSON.stringify(activities, null, 2));
        } catch(e) {
            console.error('Activity log error:', e);
        }

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

// ==================== SEND OTP ====================
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { email, type } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please enter a valid email address' });
        }

        if (type === 'login') {
            const user = findUser(email);
            if (!user) {
                return res.status(400).json({ error: 'No account found with this email' });
            }
        }

        if (type === 'signup') {
            const user = findUser(email);
            if (user) {
                return res.status(400).json({ error: 'Email already registered. Please login.' });
            }
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        otpStore[email] = {
            otp: otp,
            type: type,
            createdAt: Date.now(),
            expiresAt: Date.now() + (10 * 60 * 1000),
            attempts: 0
        };

        console.log(`OTP generated for ${email}: ${otp}`);

        await sendEmail(
            email,
            'Your OTP Code - PDFWorks Pro',
            `
            <!DOCTYPE html>
            <html>
            <body style="font-family:Arial,sans-serif;margin:0;padding:0;background:#f5f5f5;">
                <div style="max-width:600px;margin:40px auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.1);">
                    <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:40px;text-align:center;color:white;">
                        <h1 style="margin:0;font-size:28px;">📄 PDFWorks Pro</h1>
                        <p style="margin:10px 0 0;opacity:0.9;">
                            ${type === 'signup' ? 'Welcome! Verify your email to get started' : 'Here is your login OTP'}
                        </p>
                    </div>
                    <div style="padding:40px;text-align:center;">
                        <h2 style="color:#333;">Your Verification Code</h2>
                        <p style="color:#666;">
                            Use this OTP to ${type === 'signup' ? 'create your account' : 'login to your account'}
                        </p>
                        <div style="background:#f8f9ff;border:2px dashed #667eea;border-radius:12px;padding:30px;margin:30px 0;">
                            <div style="font-size:48px;font-weight:900;color:#667eea;letter-spacing:12px;">${otp}</div>
                            <div style="font-size:14px;color:#666;margin-top:10px;">One Time Password</div>
                        </div>
                        <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:12px;margin:20px 0;color:#856404;font-size:14px;">
                            ⏰ This OTP expires in <strong>10 minutes</strong>
                        </div>
                        <p style="color:#dc3545;font-size:13px;">
                            ⚠️ Never share this OTP with anyone.<br>
                            PDFWorks Pro will never ask for your OTP.
                        </p>
                    </div>
                    <div style="background:#f8f9ff;padding:20px;text-align:center;font-size:12px;color:#999;">
                        <p>© 2024 PDFWorks Pro • If you did not request this, please ignore this email.</p>
                    </div>
                </div>
            </body>
            </html>
            `
        );

        console.log(`✅ OTP sent successfully to ${email}`);
        res.json({ success: true, message: 'OTP sent to your email' });

    } catch (error) {
        console.error('❌ Send OTP error:', error.message);
        res.status(500).json({
            error: 'Failed to send OTP: ' + error.message
        });
    }
});

// ==================== VERIFY OTP ====================
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp, name, password, type } = req.body;

        console.log('Verifying OTP for:', email);

        if (!otpStore[email]) {
            return res.status(400).json({
                error: 'OTP expired or not found. Please request a new one.'
            });
        }

        if (Date.now() > otpStore[email].expiresAt) {
            delete otpStore[email];
            return res.status(400).json({
                error: 'OTP has expired. Please request a new one.'
            });
        }

        if (otpStore[email].attempts >= 3) {
            delete otpStore[email];
            return res.status(400).json({
                error: 'Too many wrong attempts. Please request a new OTP.'
            });
        }

        const storedOTP = String(otpStore[email].otp).trim();
        const receivedOTP = String(otp).trim();

        console.log('Stored OTP:', storedOTP);
        console.log('Received OTP:', receivedOTP);
        console.log('Match:', storedOTP === receivedOTP);

        if (storedOTP !== receivedOTP) {
            otpStore[email].attempts++;
            const remaining = 3 - otpStore[email].attempts;
            return res.status(400).json({
                error: `Wrong OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
            });
        }

        delete otpStore[email];

        let user;

        if (type === 'signup') {
            const hashedPassword = await bcrypt.hash(password, 10);
            user = {
                id: Date.now().toString(),
                name: name,
                email: email,
                password: hashedPassword,
                provider: 'email',
                verified: true,
                createdAt: new Date().toISOString()
            };
            saveUser(user);

            // Send welcome email
            try {
                await sendEmail(
                    email,
                    'Welcome to PDFWorks Pro! 🎉',
                    `
                    <div style="font-family:Arial;max-width:600px;margin:0 auto;">
                        <div style="background:linear-gradient(135deg,#667eea,#764ba2);padding:40px;text-align:center;color:white;border-radius:16px 16px 0 0;">
                            <h1>📄 PDFWorks Pro</h1>
                            <p>Welcome aboard! 🎉</p>
                        </div>
                        <div style="padding:40px;background:white;border-radius:0 0 16px 16px;">
                            <h2>Hello, ${name}! 👋</h2>
                            <p>Your account has been created successfully!</p>
                            <p>You now have access to all PDF tools.</p>
                            <a href="https://working-pdf.onrender.com"
                               style="display:inline-block;background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:14px 32px;border-radius:30px;text-decoration:none;font-weight:700;margin-top:20px;">
                                🚀 Start Using PDFWorks Pro
                            </a>
                        </div>
                    </div>
                    `
                );
            } catch(emailError) {
                console.error('Welcome email failed:', emailError.message);
            }

        } else {
            user = findUser(email);
            if (!user) {
                return res.status(400).json({ error: 'User not found' });
            }
        }

        const sessionToken = Math.random().toString(36).substring(2) +
            Date.now().toString(36) +
            Math.random().toString(36).substring(2);

        saveSession({
            token: sessionToken,
            email: email,
            createdAt: new Date().toISOString()
        });

        try {
            let activities = [];
            try {
                const data = fs.readFileSync(activityFile, 'utf8');
                activities = JSON.parse(data);
                if (!Array.isArray(activities)) activities = [];
            } catch(e) { activities = []; }

            activities.push({
                id: Date.now().toString(),
                tool: type === 'signup' ? 'signup' : 'login',
                email: email,
                type: type === 'signup' ? 'signup' : 'login',
                timestamp: new Date().toISOString()
            });

            fs.writeFileSync(activityFile, JSON.stringify(activities, null, 2));
        } catch(e) {
            console.error('Activity log error:', e);
        }

        res.json({
            token: sessionToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                provider: user.provider || 'email',
                verified: true
            }
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ error: 'Verification failed: ' + error.message });
    }
});

// ==================== RESEND OTP ====================
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email, type } = req.body;

        delete otpStore[email];

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        otpStore[email] = {
            otp: otp,
            type: type,
            createdAt: Date.now(),
            expiresAt: Date.now() + (10 * 60 * 1000),
            attempts: 0
        };

        await sendEmail(
            email,
            'New OTP Code - PDFWorks Pro',
            `
            <div style="font-family:Arial;max-width:500px;margin:0 auto;padding:40px;background:#f9f9f9;border-radius:16px;">
                <h2 style="color:#667eea;text-align:center;">📄 PDFWorks Pro</h2>
                <p style="text-align:center;color:#666;">Your new OTP code:</p>
                <div style="background:#fff;border:2px dashed #667eea;border-radius:12px;padding:30px;text-align:center;margin:20px 0;">
                    <div style="font-size:48px;font-weight:900;color:#667eea;letter-spacing:12px;">${otp}</div>
                    <p style="color:#999;margin-top:10px;">Expires in 10 minutes</p>
                </div>
                <p style="color:#dc3545;text-align:center;font-size:13px;">Never share this OTP with anyone.</p>
            </div>
            `
        );

        res.json({ success: true, message: 'New OTP sent to your email' });

    } catch (error) {
        console.error('Resend OTP error:', error);
        res.status(500).json({ error: 'Failed to resend OTP' });
    }
});

// ==================== TEST EMAIL ====================
app.get('/api/test-email', async (req, res) => {
    try {
        await sendEmail(
            process.env.EMAIL_USER,
            'Test Email from PDFWorks',
            '<p>Email is working! ✅</p>'
        );
        res.json({
            success: true,
            message: 'Test email sent!',
            email_user: process.env.EMAIL_USER
        });
    } catch(error) {
        res.json({
            success: false,
            error: error.message,
            email_user: process.env.EMAIL_USER
        });
    }
});

// ==================== USER STATS ====================
app.get('/api/stats', authenticateToken, (req, res) => {
    const db = readDB();
    const activity = db.activity.filter(a => a.user_id === req.user.id);
    const today = new Date().toISOString().split('T')[0];
    res.json({
        stats: {
            total_activities: activity.length,
            today_activities: activity.filter(a => a.timestamp.startsWith(today)).length,
            tools_used: new Set(activity.filter(a => a.tool).map(a => a.tool)).size,
            active_sessions: db.sessions.filter(s => s.user_id === req.user.id).length
        }
    });
});

// ==================== PROTECT PDF ====================
app.post('/api/protect-pdf', upload.single('file'), async (req, res) => {
    try {
        const password = req.body.password;
        if (!password) return res.status(400).json({ error: 'Password missing' });
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const pdfBuffer = fs.readFileSync(req.file.path);
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
    if (type) entries = entries.filter(e => e.type === type);
    if (email) entries = entries.filter(e => e.email === email);
    if (tool) entries = entries.filter(e => e.tool === tool);
    const total = entries.length;
    res.json({ total, entries: entries.slice(parseInt(offset), parseInt(offset) + parseInt(limit)) });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const all = logger.getAll();
    res.json({
        total: all.length,
        logins: all.filter(e => e.type === 'login').length,
        tool_uses: all.filter(e => e.type === 'tool_use').length,
        downloads: all.filter(e => e.type === 'download').length,
        users: [...new Set(all.map(e => e.email).filter(Boolean))].length,
        tools: all.reduce((acc, e) => { if (e.tool) acc[e.tool] = (acc[e.tool] || 0) + 1; return acc; }, {}),
        recent_users: [...new Set(all.slice(0, 50).map(e => e.email).filter(Boolean))].slice(0, 10),
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
    console.log(`✅ SendGrid email configured - OTP emails will work!`);
});