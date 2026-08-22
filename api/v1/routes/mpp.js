/**
 * @file v1/routes/mpp.js
 * @description Machine Payments Protocol (MPP) paid routes + discovery endpoint
 */

const express = require('express');
const router = express.Router();
const { mppx } = require('../config/mpp');

/**
 * GET /.well-known/mpp
 * @description MPP service discovery endpoint for autonomous agents
 */
router.get('/.well-known/mpp', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    service: 'Marketplace API',
    version: '1.0.0',
    description: 'Premium data and insights with MPP payment support',
    endpoints: [
      {
        path: '/api/v1/mpp/mpp-data',
        method: 'POST',
        amount: '0.50',
        currency: 'usd',
        description: 'Premium marketplace data payload.',
        paymentMethods: ['card', 'link', 'tempo'],
        'x-agent-id': 'optional',
      },
      {
        path: '/api/v1/mpp/premium',
        method: 'GET',
        amount: '0.25',
        currency: 'usd',
        description: 'Premium marketplace insights.',
        paymentMethods: ['card', 'link', 'tempo'],
        'x-agent-id': 'optional',
      },
    ],
    mcp: {
      url: `${baseUrl}/api/v1/mcp/tools`,
      description: 'MCP tools for AI agents',
    },
    openapi: {
      url: `${baseUrl}/openapi.json`,
      description: 'OpenAPI spec for developers',
    },
  });
});

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
      timestamp: new Date().toISOString(),
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