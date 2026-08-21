/**
 * @file v1/routes/mcp.js
 * @description MCP (Model Context Protocol) HTTP endpoint for agents
 */

const express = require('express');
const router = express.Router();

// Simple MCP-style tools listing
router.get('/tools', (req, res) => {
  res.json({
    tools: [
      {
        name: 'get_mpp_data',
        description: 'Get premium marketplace data. Costs $0.50 via MPP (Machine Payments Protocol).',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
        payment: {
          amount: '0.50',
          currency: 'usd',
          endpoint: 'POST /api/v1/mpp/mpp-data',
        },
      },
      {
        name: 'get_premium_data',
        description: 'Get premium marketplace insights. Costs $0.25 via MPP.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
        payment: {
          amount: '0.25',
          currency: 'usd',
          endpoint: 'GET /api/v1/mpp/premium',
        },
      },
      {
        name: 'get_openapi',
        description: 'Get the full OpenAPI specification of the Marketplace API.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ],
  });
});

// MCP-style tool call (agents will call this)
router.post('/call', async (req, res) => {
  const { name, arguments: args } = req.body;

  if (name === 'get_mpp_data') {
    return res.json({
      content: [
        {
          type: 'text',
          text: 'This tool requires payment. Please call POST /api/v1/mpp/mpp-data and handle the 402 Payment Required response using MPP.',
        },
      ],
      isError: false,
      paymentRequired: true,
      endpoint: 'POST /api/v1/mpp/mpp-data',
      amount: '0.50',
    });
  }

  if (name === 'get_premium_data') {
    return res.json({
      content: [
        {
          type: 'text',
          text: 'This tool requires payment. Please call GET /api/v1/mpp/premium and handle the 402 Payment Required response using MPP.',
        },
      ],
      isError: false,
      paymentRequired: true,
      endpoint: 'GET /api/v1/mpp/premium',
      amount: '0.25',
    });
  }

  if (name === 'get_openapi') {
    const { getOpenApiSpec } = require('../config/openapi');
    return res.json({
      content: [
        {
          type: 'text',
          text: JSON.stringify(getOpenApiSpec(), null, 2),
        },
      ],
    });
  }

  res.status(404).json({
    content: [{ type: 'text', text: `Unknown tool: ${name}` }],
    isError: true,
  });
});

module.exports = router;