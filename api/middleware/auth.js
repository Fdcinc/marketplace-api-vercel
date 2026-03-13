const jwt = require('jsonwebtoken');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');

/**
 * Protect middleware: Ensures the user is logged in and the token is valid
 */
const protect = async (req, res, next) => {
  let token;

  // 1. Extract token from headers
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Not authorized - no token provided',
    });
  }

  try {
    // 2. HARDENING: Check Blacklist FIRST
    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted) {
      return res.status(401).json({ 
        success: false, 
        error: 'Token is no longer valid (logged out)' 
      });
    }

    // 3. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      clockTolerance: 30,
    });

    // 4. Fetch user and exclude sensitive fields
    req.user = await User.findById(decoded.id).select(
      '-passwordHash -__v -loginAttempts -schemaVersion -recoveryCodes -twoFactorSecret'
    );

    // 5. Check if user still exists
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication failed - user not found',
      });
    }

    // 6. Check account status
    if (req.user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: `Account is ${req.user.status}`,
      });
    }

    next();
  } catch (err) {
    console.error('JWT verification failed:', err.message);

    const message = err.name === 'TokenExpiredError' 
      ? 'Session expired. Please login again.' 
      : 'Authentication failed - invalid token';

    return res.status(401).json({
      success: false,
      error: message,
    });
  }
};

/**
 * Role-based restriction middleware
 */
const restrictTo = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied - requires one of: ${allowedRoles.join(', ')}`,
      });
    }
    next();
  };
};

// ──── CRITICAL: YOU MUST EXPORT THE FUNCTIONS ────
module.exports = { protect, restrictTo };