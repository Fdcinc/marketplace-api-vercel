/**
 * @file v1/routes/mpp.js
 * @description Machine Payments Protocol (MPP) paid routes
 */

const express = require('express');
const router = express.Router();
const { mppx } = require('../config/mpp');

/**
 * POST /api/v1/mpp/mpp-data
 * Price: $0.50
 */
router.post(
  '/mpp-data',
  mppx.charge({
    amount: '0.50',
    currency: 'usd',
    decimals: 2,
  }),
  (req, res) => {
    res.json({
      success: true,
      message: 'Machine payment verified! Premium marketplace payload delivered.',
      paymentDetails: req.payment || {},
    });
  }
);

/**
 * GET /api/v1/mpp/premium
 * Price: $0.25
 */
router.get(
  '/premium',
  mppx.charge({
    amount: '0.25',
    currency: 'usd',
    decimals: 2,
  }),
  (req, res) => {
    res.json({
      success: true,
      message: 'Premium data delivered after MPP payment',
      paymentDetails: req.payment || {},
      data: {
        insight: 'High-value marketplace insight',
        timestamp: new Date().toISOString(),
      },
    });
  }
);

module.exports = router;