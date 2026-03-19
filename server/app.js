const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

// ===== ENVIRONMENT VARIABLES VALIDATION =====
// Fail fast if required environment variables are missing
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:');
  missingEnvVars.forEach(varName => {
    console.error(`   - ${varName}`);
  });
  console.error('\nPlease set these variables in your .env file and restart the server.');
  process.exit(1);
}

const express = require('express');
require('./cron/updateMemberStatus');
const connectDB = require('./config/db');
const cors = require('cors');
const helmet = require('helmet');
// const mongoSanitize = require('express-mongo-sanitize'); // Incompatible with Express 5
// const xss = require('xss-clean'); // Incompatible with Express 5
// const hpp = require('hpp'); // Incompatible with Express 5
const rateLimit = require('express-rate-limit');
const logger = require('./utils/logger');

const app = express();

// ===== CORS CONFIGURATION =====
// Restrictive in production, permissive in development
const normalizeOrigin = (origin = '') => {
  const trimmedOrigin = origin.trim().replace(/\/+$/, '');

  if (!trimmedOrigin) {
    return '';
  }

  try {
    return new URL(trimmedOrigin).origin;
  } catch {
    return trimmedOrigin;
  }
};

const configuredOrigins = Array.from(new Set([
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : []),
  process.env.FRONTEND_URL
].map(origin => normalizeOrigin(origin || '')).filter(Boolean)));

const corsOptions = {
  origin(origin, callback) {
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }

    if (!origin) {
      return callback(null, true);
    }

    if (configuredOrigins.includes(normalizeOrigin(origin))) {
      return callback(null, true);
    }

    logger.warn(`Blocked CORS request from origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  credentials: true
};

app.use(cors(corsOptions));

if (process.env.NODE_ENV === 'production' && configuredOrigins.length === 0) {
  logger.warn('⚠️  WARNING: No allowed frontend origins configured in production. Set ALLOWED_ORIGINS or FRONTEND_URL.');
}

// ===== SECURITY MIDDLEWARE =====
app.use(helmet());

// ===== RATE LIMITING =====
// Reduced to production-appropriate levels
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 2000,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', limiter);

// ===== BODY PARSER WITH SIZE LIMITS =====
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data Sanitization against NoSQL query injection
app.use((req, res, next) => {
  const sanitize = (obj) => {
    for (const key in obj) {
      if (key.startsWith('$')) {
        delete obj[key];
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
    }
  };
  if (req.body) sanitize(req.body);
  if (req.query) sanitize(req.query);
  if (req.params) sanitize(req.params);
  next();
});

// Data Sanitization against XSS
app.use((req, res, next) => {
  const sanitizeXss = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        obj[key] = obj[key].replace(/</g, '&lt;').replace(/>/g, '&gt;');
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeXss(obj[key]);
      }
    }
  };
  if (req.body) sanitizeXss(req.body);
  if (req.query) sanitizeXss(req.query);
  if (req.params) sanitizeXss(req.params);
  next();
});

// Prevent Parameter Pollution
// app.use(hpp()); // DISABLED: Incompatible with Express 5 read-only req.query

// ===== REQUEST TIMEOUT MIDDLEWARE =====
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 seconds
  res.setTimeout(30000);
  next();
});

// ===== REQUEST LOGGING =====
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
  next();
});

// ===== HEALTH CHECK ENDPOINT =====
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ===== ROUTES =====
const memberRoutes = require('./routes/memberRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const paymentRoutes = require('./routes/paymentRoutes')
const attendanceRoutes = require('./routes/attendanceRoutes')
const settingsRoutes = require('./routes/settingsRoutes');
const reportRoutes = require('./routes/reportRoutes');
const authRoutes = require("./routes/authRoutes");
const memberAuthRoutes = require("./routes/memberAuthRoutes");
const qrRoutes = require('./routes/qrRoutes');
const { adminAuth, memberAuth } = require("./middlewares/authMiddleware");

app.get('/', (req, res) => {
  res.json({ message: 'GYM API is running!!!' });
});

// Admin routes (using adminAuth)
app.use('/api/members', adminAuth, memberRoutes);
app.use('/api/dashboard', adminAuth, dashboardRoutes);
app.use('/api/payments', adminAuth, paymentRoutes);
app.use('/api/attendance', adminAuth, attendanceRoutes);
app.use('/api/settings', adminAuth, settingsRoutes);
app.use('/api/reports', adminAuth, reportRoutes);

app.use("/api/auth", authRoutes);
app.use("/api/member-auth", memberAuthRoutes);

// QR routes
app.use("/api/qr", qrRoutes);

const Attendance = require("./models/Attendance");
app.get("/api/member/attendance", memberAuth, async (req, res) => {
  try {
    const records = await Attendance.find({ memberId: req.member.id })
      .sort({ date: -1 })
      .select("date checkInTime markedBy");

    const formatted = records.map(r => ({
      _id: r._id,
      date: r.date,
      present: true,
      checkInTime: r.checkInTime,
      markedBy: r.markedBy
    }));

    res.json(formatted);
  } catch (err) {
    logger.error('Error fetching member attendance:', err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// ===== ERROR HANDLING MIDDLEWARE =====
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);

  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production'
    ? 'An error occurred'
    : err.message;

  res.status(err.status || 500).json({
    msg: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

const PORT = process.env.PORT || 3000;

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, "0.0.0.0", () => {
      logger.info(`✅ Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
      console.log(`✅ Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    });
  } catch (err) {
    logger.error('❌ Failed to start server:', err);
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
};

startServer();
