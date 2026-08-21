/**
 * @file v1/config/openapi.js
 * @description Centralized OpenAPI discovery spec for automated agent tools.
 */

const getOpenApiSpec = () => ({
  openapi: '3.1.0',
  info: {
    title: 'Marketplace API',
    version: '1.0.0',
    description: 'Marketplace API with Machine Payments Protocol (MPP) support via Stripe',
  },
  paths: {
    '/api/v1/auth/mpp-data': {
      post: {
        summary: 'MPP Paid Endpoint',
        description: 'Requires payment of $0.50 via Machine Payments Protocol (Stripe)',
        operationId: 'mppData',
        tags: ['MPP'],
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
                    paymentDetails: { type: 'object' },
                  },
                },
              },
            },
          },
          '402': {
            description: 'Payment Required – returns WWW-Authenticate payment challenge headers',
          },
        },
      },
    },
  },
});

module.exports = { getOpenApiSpec };