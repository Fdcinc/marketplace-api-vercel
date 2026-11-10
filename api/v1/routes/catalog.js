const express = require('express');
const router = express.Router();
const { paidRoute } = require('../middleware/paidRoute');
const { standardLimiter, strictLimiter } = require('../middleware/rateLimiter');

const services = [
  {
    path: '/validate-email',
    method: 'get',
    price: '0.002',
    description: 'Validate an email address format.',
    limiters: [standardLimiter],
    inputSchema: { type: 'object', properties: { email: { type: 'string' } }, required: ['email'] },
    handler: async (req, res) => {
      const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.query.email || '');
      res.json({ email: req.query.email, valid });
    }
  },
  {
    path: '/text-to-structure',
    method: 'post',
    price: '0.15',
    description: 'Convert messy unstructured text into a guaranteed JSON schema.',
    limiters: [strictLimiter],
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
    handler: async (req, res) => {
      // Production: Call OpenAI/DeepSeek here
      res.json({ structured: { extracted: req.body.text?.substring(0, 20) }, confidence: 0.98 });
    }
  },
  {
    path: '/web-search',
    method: 'get',
    price: '0.007',
    description: 'Neural web search returning ranked results.',
    limiters: [standardLimiter],
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] },
    handler: async (req, res) => {
      res.json({ results: [{ title: `Result for ${req.query.query}`, url: 'https://example.com' }] });
    }
  }
];

// Dynamically mount routes
services.forEach(service => {
  const middlewares = [
    ...(service.limiters || []),
    ...paidRoute(service.price),
    service.handler
  ];
  router[service.method](service.path, ...middlewares);
});

module.exports = { router, services };