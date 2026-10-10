/**
 * @file config/openapi.js
 * @description Expanded OpenAPI 3.1.0 discovery spec for agents (MCP + MPP + billing).
 */
const getOpenApiSpec = () => ({
  openapi: '3.1.0',
  info: {
    title: 'Marketplace API',
    version: '1.1.0',
    description:
      'Marketplace API with Machine Payments Protocol (MPP) support via Stripe/Tempo and Model Context Protocol (MCP) tool discovery.',
  },
  servers: [
    {
      url: process.env.API_BASE_URL || 'http://localhost:5000',
      description: 'Current environment',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Local JWT or Auth0 access token',
      },
      mppPayment: {
        type: 'apiKey',
        in: 'header',
        name: 'Authorization',
        description: 'MPP payment credential (Payment <credential>)',
      },
    },
  },
  paths: {
    '/api/v1/mpp/mpp-data': {
      post: {
        summary: 'MPP Paid Data Endpoint',
        description:
          'Requires payment of $0.50 via Machine Payments Protocol (or 1 credit for authenticated developers).',
        operationId: 'mppData',
        tags: ['MPP'],
        security: [{ bearerAuth: [] }, { mppPayment: [] }],
        responses: {
          '200': {
            description: 'Payment successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean' },
                    message: { type: 'string' },
                    paidBy: { type: 'string' },
                    paymentDetails: { type: 'object' },
                    creditsRemaining: { type: 'number' },
                  },
                },
              },
            },
          },
          '402': {
            description:
              'Payment Required – returns WWW-Authenticate: Payment challenge',
          },
        },
      },
    },
    '/api/v1/mpp/premium': {
      get: {
        summary: 'MPP Premium Data Endpoint',
        description:
          'Requires payment of $0.25 via Machine Payments Protocol (or 1 credit for authenticated developers).',
        operationId: 'mppPremium',
        tags: ['MPP'],
        security: [{ bearerAuth: [] }, { mppPayment: [] }],
        responses: {
          '200': {
            description: 'Payment successful – premium data returned',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean' },
                    message: { type: 'string' },
                    paidBy: { type: 'string' },
                    paymentDetails: { type: 'object' },
                    data: { type: 'object' },
                  },
                },
              },
            },
          },
          '402': {
            description:
              'Payment Required – returns WWW-Authenticate: Payment challenge',
          },
        },
      },
    },
    '/api/v1/mcp/tools': {
      get: {
        summary: 'List available MCP tools',
        description:
          'Public discovery endpoint. Returns the list of tools an agent can call.',
        operationId: 'mcpListTools',
        tags: ['MCP'],
        responses: {
          '200': {
            description: 'Tool list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    tools: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          description: { type: 'string' },
                          inputSchema: { type: 'object' },
                          payment: { type: 'object' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/mcp/call': {
      post: {
        summary: 'Execute an MCP tool',
        description:
          'Protected. Executes the named tool with the supplied arguments.',
        operationId: 'mcpCallTool',
        tags: ['MCP'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name'],
                properties: {
                  name: {
                    type: 'string',
                    description: 'Tool name from /tools',
                  },
                  arguments: { type: 'object' },
                },
              },
            },
          },
        },
        responses: {
          '200': { description: 'Tool result (MCP content array)' },
          '401': { description: 'Unauthorized' },
          '404': { description: 'Unknown tool' },
        },
      },
    },
    '/api/v1/billing/create-checkout-session': {
      post: {
        summary: 'Create credit-pack Checkout session',
        operationId: 'createCreditCheckout',
        tags: ['Billing'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Returns { url }' } },
      },
    },
    '/api/v1/billing/create-portal-session': {
      post: {
        summary: 'Create Stripe Customer Portal session',
        operationId: 'createBillingPortal',
        tags: ['Billing'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Returns { url }' } },
      },
    },
    '/api/v1/billing/switch-to-credits': {
      post: {
        summary: 'End trial early and convert remaining requests to credits',
        operationId: 'switchToCredits',
        tags: ['Billing'],
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Conversion result' } },
      },
    },
  },
  tags: [
    { name: 'MPP', description: 'Machine Payments Protocol paid endpoints' },
    {
      name: 'MCP',
      description: 'Model Context Protocol tool discovery & execution',
    },
    { name: 'Billing', description: 'Credit packs, portal, trial conversion' },
  ],
});

module.exports = { getOpenApiSpec };
