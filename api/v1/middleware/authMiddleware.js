/**
 * @file middleware/authMiddleware.js
 * @description Consolidated primary authentication and gateway middleware.
 * Supports Auth0 (long tokens / header flag) and legacy local JWT.
 * Performs JIT user creation + Stripe sync on first Auth0 login.
 * Integrates express-rate-limit, role-based restriction, and API gateway validation.
 * 
 * @requires jwt, express-oauth2-jwt-bearer, auth0 UserInfoClient, express-rate-limit
 */
const jwt = require('jsonwebtoken');
const { auth } = require('express-oauth2-jwt-bearer');
const { verifyToken } = require('../services/tokenManager');
const { UserInfoClient } = require('auth0');
const rateLimit = require('express-rate-limit');
const User = require('../models/users');
const connectDB = require('../config/db');
const { ensureStripeCustomer } = require('../controllers/authController'); 

const checkAuth0Jwt = auth({
  audience: process.env.AUTH0_AUDIENCE || 'https://api.marketplace.com',
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
});

const userInfoClient = new UserInfoClient({ domain: process.env.AUTH0_DOMAIN });

/**
 * Production-grade rate limiter for authentication endpoints (login/register/JIT).
 */
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP, please try again after 15 minutes'
  }
});

exports.authLimiter = authRateLimiter;

/**
 * Gateway validation middleware to protect downstream internal services.
 */
const verifyGateway = (req, res, next) => {
  const gatewaySecret = req.headers['x-platform-secret'];
  const expectedSecret = process.env.GATEWAY_SECRET || 'my-marketplace-private-key-123';

  if (!gatewaySecret || gatewaySecret !== expectedSecret) {
    console.warn("❌ Gateway Secret Mismatch");
    return res.status(403).json({ success: false, error: 'Access Denied: Invalid platform secret' });
  }
  next();
};

exports.verifyGateway = verifyGateway;

/**
 * Role-based access control middleware.
 */
const restrictTo = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Insufficient permissions' });
  }
  next();
};

exports.restrictTo = restrictTo;

/**
 * Consolidated primary protection middleware handling Auth0 (with JIT provisioning) and local JWTs.
 */
exports.protect = async (req, res, next) => {
  await connectDB(); 

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const isAuth0Token = token.length > 250 || req.headers['x-auth-source'] === 'auth0';

    if (isAuth0Token) {
      // --- AUTH0 FLOW ---
      return checkAuth0Jwt(req, res, async (err) => {
        if (err) {
          console.error("Auth0 JWT Validation Failed:", err.message);
          return res.status(401).json({ success: false, error: 'Invalid Auth0 Token' });
        }
        
        try {
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

          req.user = user;
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
        const user = await User.findById(decoded.id).select('-passwordHash');
        if (!user) return res.status(401).json({ success: false, error: 'User does not exist' });

        req.user = user;
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