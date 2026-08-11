/**
 * @file models/processedStripeEvent.js
 * @description Stores Stripe event IDs so webhooks are processed at most once.
 */
const mongoose = require('mongoose');

const ProcessedStripeEventSchema = new mongoose.Schema(
  {
    eventId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    type: {
      type: String,
      required: true,
      index: true,
    },
    objectId: {
      type: String,
      default: null,
      index: true,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

ProcessedStripeEventSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 30 * 24 * 60 * 60 }
);

module.exports =
  mongoose.models.ProcessedStripeEvent ||
  mongoose.model('ProcessedStripeEvent', ProcessedStripeEventSchema);