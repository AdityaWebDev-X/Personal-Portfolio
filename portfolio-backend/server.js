require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;

// 1. Production Security Hardening via Middleware
app.use(helmet());
app.use(express.json());

// 2. Strict Cross-Origin Configuration
const allowedOrigins = [
  'https://yourusername.github.io', // Replace with your exact GitHub Pages root deployment domain
  'http://127.0.0.1:5500',          // Keeps local development live-server environments valid
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by Cross-Origin Resource Protection matrix.'));
    }
  }
}));

// 3. Prevent DDoS/Spam Attacks via Automated Rate Limiting[cite: 1]
const contactSubmissionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute operational analysis window
  max: 5, // Limit each IP address footprint to 5 transmissions per window
  message: { error: 'Too many recovery requests initialized from this IP. System entry locked down.' }
});

// 4. Secure API Processing Endpoint
app.post('/api/v1/secure-contact', contactSubmissionLimiter, (req, res) => {
  const { name, email, message } = req.body;

  // Structural confirmation step
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Data payload is structurally incomplete.' });
  }

  // Sanitization Defense Layer against Indirect Prompt Injection[cite: 1]
  // We treat everything as clean strings, removing structural code notation execution vulnerabilities
  const sanitizedName = String(name).replace(/[<>]/g, "");
  const sanitizedEmail = String(email).trim().toLowerCase();
  const sanitizedMessage = String(message)
    .replace(/[<>]/g, "")
    .substring(0, 1000); // Enforce a defensive storage size constraint

  /* 
    PRODUCTION NOTE: This is where you connect your distribution loop.
    You can route this via 'nodemailer' to your inbox, send a Discord Webhook request,
    or process it into a secure MongoDB cluster[cite: 1].
  */
  console.log('--- Secure System Log Appended ---');
  console.log(`From: ${sanitizedName} (${sanitizedEmail})`);
  console.log(`Content: ${sanitizedMessage}`);

  return res.status(200).json({ status: 'success', message: 'Payload securely processed into backend logs.' });
});

// Centralized error execution framework
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message || 'Internal pipeline malfunction initialized.' });
});

app.listen(PORT, () => {
  console.log(`[SYSTEM STABLE] Secure interface processing on port ${PORT}`);
});