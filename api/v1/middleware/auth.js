const jwt = require('jsonwebtoken');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db');

const verifyGateway = (req, res, next) => {
  const gatewaySecret = req.headers['x-platform-secret'];
  if (gatewaySecret !== process.env.GATEWAY_SECRET) {
    return res.status(403).json({ success: false, error: 'Access Denied: Use the API Gateway.' });
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
    
    // We fetch the user and attach it to the REQ object
    const currentUser = await User.findById(decoded.id);

    if (!currentUser) return res.status(401).json({ error: 'User not found' });

    req.user = currentUser; 
    
    // This is the bridge to trackUsage
    next(); 
  } catch (err) {
    res.status(401).json({ error: 'Authentication failed' });
  }
};

const restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Forbidden' });
  }
  next();
};

module.exports = { protect, restrictTo, verifyGateway };