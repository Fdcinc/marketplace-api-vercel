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
    let token = req.headers.authorization?.startsWith('Bearer') ? req.headers.authorization.split(' ')[1] : null;
    if (!token) return res.status(401).json({ error: 'Not authorized' });

    if (await Blacklist.findOne({ token })) return res.status(401).json({ error: 'Token logged out' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-passwordHash');

    if (!req.user) return res.status(401).json({ error: 'User not found' });
    console.log(`👤 User: ${req.user.email} | StripeID: ${req.user.stripeCustomerId}`);
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