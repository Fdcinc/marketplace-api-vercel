const jwt = require('jsonwebtoken');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db');

// NEW: Gateway Security Middleware
const verifyGateway = (req, res, next) => {
  const gatewaySecret = req.headers['x-platform-secret'];

  // This must match exactly what you put in kong-copy.yaml
  if (gatewaySecret !== process.env.GATEWAY_SECRET) {
    return res.status(403).json({ 
      success: false, 
      error: 'Access Denied: Direct access is forbidden. Please use the API Gateway.' 
    });
  }
  next();
};

const protect = async (req, res, next) => {
  try {
    await connectDB(); 

    let token = req.headers.authorization?.startsWith('Bearer') 
                ? req.headers.authorization.split(' ')[1] 
                : null;

    if (!token) return res.status(401).json({ error: 'Not authorized' });

    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted) return res.status(401).json({ error: 'Token logged out' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-passwordHash');

    if (!req.user) return res.status(401).json({ error: 'User not found' });

    next();
  } catch (err) {
    res.status(401).json({ error: 'Authentication failed' });
  }
};

const restrictTo = (...roles) => {
    return (req, res, next) => {
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          error: 'You do not have permission to perform this action'
        });
      }
      next();
    };
  };

// Add verifyGateway to your exports
module.exports = { protect, restrictTo, verifyGateway };