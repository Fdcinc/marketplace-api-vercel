/**
 * @file middleware/authMiddleware.js
 * @description Primary authentication middleware.
 * Supports Auth0 (long tokens) and legacy local JWT.
 * Performs JIT user creation + Stripe sync on first Auth0 login.
 * Integrates express-rate-limit for production-grade rate limiting with automatic cleanup.
 * 
 * @requires jwt, express-oauth2-jwt-bearer, auth0 UserInfoClient, express-rate-limit
 * @note Ensure 'express-rate-limit' is installed via npm install express-rate-limit
 */
const jwt = require('jsonwebtoken');
const { auth } = require('express-oauth2-jwt-bearer');
const { verifyToken } = require('../services/tokenManager');
const { UserInfoClient } = require('auth0');
const rateLimit = require('express-rate-limit');
const User = require('../models/users');
const connectDB = require('../config/db'); // Import your connection helper
const { ensureStripeCustomer } = require('../controllers/authController'); 

const checkAuth0Jwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
});

const userInfoClient = new UserInfoClient({ domain: process.env.AUTH0_DOMAIN });

/**
 * Production-grade rate limiter for authentication endpoints (login/register/JIT).
 * Uses express-rate-limit to handle memory windows and automatic cleanup.
 */
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP, please try again after 15 minutes'
  }
});

exports.authLimiter = authRateLimiter;

exports.protect = async (req, res, next) => {
  // CRITICAL: Ensure database connection is ready before any logic
  await connectDB(); 

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const isAuth0Token = token.length > 250;

    if (isAuth0Token) {
      // --- AUTH0 FLOW ---
      return checkAuth0Jwt(req, res, async (err) => {
        if (err) {
          console.error("Auth0 JWT Validation Failed:", err.message);
          return res.status(401).json({ success: false, error: 'Invalid Auth0 Token' });
        }
        
        try {
          // Improved email extraction using the explicitly captured raw token scope
          const payload = req.auth.payload;
          let email = payload['https://api.marketplace.com/email'] || 
                     payload.email || 
                     (await userInfoClient.getUserInfo(token).catch(() => ({}))).email;

          if (!email) throw new Error("No email found in token payload or user info");

          const normalizedEmail = email.toLowerCase().trim();
          let user = await User.findOne({ email: normalizedEmail });

          if (!user) {
            console.log(`JIT Provisioning: ${normalizedEmail}`);
            user = await User.create({ 
              email: normalizedEmail, 
              name: payload.name || 'Auth0 User', 
              passwordHash: 'AUTH0_MANAGED' 
            });
            await ensureStripeCustomer(user);
          }

          req.user = { id: user._id.toString() };
          next();
        } catch (e) {
          console.error("Auth0 Processing Error:", e.message);
          return res.status(500).json({ success: false, error: 'Auth0 processing failed' });
        }
      });
    } else {
      // --- LOCAL JWT FLOW ---
      try {
        const { success, decoded, error } = verifyToken(token);
        if (!success) {
          console.error("Local JWT Error:", error);
          return res.status(401).json({ success: false, error: 'Invalid local token' });
        }
        const user = await User.findById(decoded.id);
        if (!user) return res.status(401).json({ success: false, error: 'User does not exist' });

        req.user = { id: user._id.toString() };
        next();
      } catch (innerErr) {
        console.error("Local JWT Execution Error:", innerErr.message);
        return res.status(401).json({ success: false, error: 'Invalid local token processing' });
      }
    }
  } catch (err) {
    console.error("Global Middleware Catch:", err.message);
    res.status(500).json({ success: false, error: 'Authentication service failure' });
  }
};