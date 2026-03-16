const jwt = require('jsonwebtoken');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db'); // IMPORTED

const protect = async (req, res, next) => {
  try {
    await connectDB(); // ENSURE CONNECTION

    let token = req.headers.authorization?.startsWith('Bearer') 
      ? req.headers.authorization.split(' ')[1] 
      : null;

    if (!token) return res.status(401).json({ success: false, error: 'Not authorized' });

    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted) return res.status(401).json({ success: false, error: 'Token invalidated' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-passwordHash');

    if (!req.user || req.user.status !== 'active') {
      return res.status(401).json({ success: false, error: 'User unavailable or inactive' });
    }

    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Authentication failed' });
  }
};

module.exports = { protect };