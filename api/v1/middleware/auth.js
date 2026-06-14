const jwt = require('jsonwebtoken');
const { auth } = require('express-oauth2-jwt-bearer');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db');

// 1. Setup Auth0 Validator
const validateAuth0 = auth({
  audience: 'https://api.marketplace.com',
  issuerBaseURL: `https://dev-ko4dlaqiz2jjixch.us.auth0.com/`,
});

const verifyGateway = (req, res, next) => {
  const gatewaySecret = req.headers['x-platform-secret'];
  const expectedSecret = process.env.GATEWAY_SECRET || 'my-marketplace-private-key-123';

  if (!gatewaySecret || gatewaySecret !== expectedSecret) {
    console.log("❌ Gateway Secret Mismatch");
    return res.status(403).json({ success: false, error: 'Access Denied: Invalid platform secret' });
  }
  next();
};

const protect = async (req, res, next) => {
  try {
    await connectDB();
    const authHeader = req.headers.authorization;
    
    // Extract token safely
    const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ error: 'No valid Bearer token provided' });
    }

    const isAuth0 = req.headers['x-auth-source'] === 'auth0';

    if (isAuth0) {
      return validateAuth0(req, res, async (err) => {
        if (err) return res.status(401).json({ error: 'Auth0 token invalid' });
        
        const auth0Id = req.auth.payload.sub;
        const currentUser = await User.findOne({ auth0Id }).select('-passwordHash');
        if (!currentUser) return res.status(401).json({ error: 'User not found in DB' });
        req.user = currentUser;
        next();
      });
    } else {
      // Legacy Path: token is already verified as existing above
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const currentUser = await User.findById(decoded.id).select('-passwordHash');
      
      if (!currentUser) return res.status(401).json({ error: 'User not found' });
      req.user = currentUser;
      next();
    }
  } catch (err) {
    console.error('❌ Auth Error:', err.message);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

const restrictTo = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Insufficient permissions' });
  }
  next();
};

module.exports = { protect, restrictTo, verifyGateway };