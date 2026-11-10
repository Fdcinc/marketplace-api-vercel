const { mppx } = require('../config/mpp');
const { protect } = require('./authMiddleware');
const trackUsage = require('./trackUsage');

function paidRoute(amount, currency = 'usd') {
  return [
    // 1. Dual-Auth Gate
    (req, res, next) => {
      const authHeader = req.headers.authorization || '';
      if (authHeader.startsWith('Bearer ')) {
        console.log(`👤 Developer flow: ${req.method} ${req.path}`);
        return protect(req, res, () => {
          trackUsage(req, res, () => next());
        });
      }
      next(); // Proceed to MPP charge
    },
    // 2. MPP Charge Middleware
    mppx.charge({ amount: String(amount) })
  ];
}

module.exports = { paidRoute };