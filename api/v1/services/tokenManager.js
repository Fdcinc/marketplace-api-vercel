/** 
 * @file utils/tokenManager.js
 * @description Centralized utility for issuing and verifying local JWTs.
 */

const jwt = require('jsonwebtoken');

const generateToken = (userId) => {
  return jwt.sign( { id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d', // Token expires in 7 days
  });
};

const verifyToken = (token) => {
  try {
    return { success: true, decoded: jwt.verify(token, process.env.JWT_SECRET) };
  } catch (err) {
    return { success: false, error: err.message };
  }
};

module.exports = { generateToken, verifyToken };