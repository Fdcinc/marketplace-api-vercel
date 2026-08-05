/**
 * @file middleware/auth.js  (legacy compatibility layer)
 * @description Thin re-export of the consolidated authMiddleware.
 * Prefer importing directly from authMiddleware.js in new code.
 *
 * Assumes MongoDB is already connected globally at app startup.
 */
const {
  protect,
  restrictTo,
  verifyGateway,
  authLimiter,
} = require('./authMiddleware');

module.exports = {
  protect,
  restrictTo,
  verifyGateway,
  authLimiter,
};