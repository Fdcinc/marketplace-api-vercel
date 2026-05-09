const jwt = require('jsonwebtoken');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db');

const verifyGateway = (req, res, next) => {
  const gatewaySecret = req.headers['x-platform-secret'];
  const expectedSecret = process.env.GATEWAY_SECRET || 'my-marketplace-private-key-123';

  if (!gatewaySecret || gatewaySecret !== expectedSecret) {
    console.log("❌ Gateway Secret Mismatch");
    return res.status(403).json({ 
      success: false, 
      error: 'Access Denied: Invalid platform secret' 
    });
  }
  next();
};

const protect = async (req, res, next) => {
  try {
    await connectDB();

    const authHeader = req.headers.authorization;
    console.log('🔐 Auth Header received:', authHeader ? authHeader.substring(0, 70) + '...' : 'MISSING');

    let token = authHeader?.startsWith('Bearer ') 
                ? authHeader.split(' ')[1] 
                : null;

    if (!token) {
      console.log('❌ No token provided');
      return res.status(401).json({ error: 'No token provided' });
    }

    // Verify JWT
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtErr) {
      console.error('❌ JWT Verify Error:', jwtErr.name, jwtErr.message);
      if (jwtErr.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token has expired. Please login again.' });
      }
      return res.status(401).json({ error: 'Invalid token' });
    }

    const currentUser = await User.findById(decoded.id).select('-passwordHash');

    if (!currentUser) {
      console.log('❌ User not found for ID:', decoded.id);
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = currentUser;
    console.log(`✅ Auth successful → ${currentUser.email} (${currentUser.role})`);
    
    next();
  } catch (err) {
    console.error('❌ Protect Middleware Crash:', err.message);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

const restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Insufficient permissions' });
  }
  next();
};

module.exports = { protect, restrictTo, verifyGateway };