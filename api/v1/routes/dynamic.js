/**
 * @file routes/dynamic.js
 * @description Dynamic pricing endpoint based on payload size.
 */
const express = require('express');
const router = express.Router();
const { paidRoute } = require('../middleware/paidRoute');

// Custom middleware to calculate dynamic price
const dynamicPricing = (basePrice, unitPrice) => {
  return async (req, res, next) => {
    const requestedItems = parseInt(req.query.limit) || 1;
    const totalPrice = (basePrice + (requestedItems * unitPrice)).toFixed(2);
    
    console.log(`Dynamically pricing request at $${totalPrice}`);
    
    // Call the paidRoute with the calculated price
    // We only need the MPP charge part here since it's a unique case
    return paidRoute(totalPrice)[1](req, res, next);
  };
};

router.get(
  '/bulk-data',
  // Base fee of $0.50 + $0.01 per item
  dynamicPricing(0.50, 0.01),
  (req, res) => {
    res.json({ 
      success: true,
      message: "Bulk data delivered", 
      itemsRequested: req.query.limit,
      paidBy: req.payment ? 'agent' : 'developer'
    });
  }
);

module.exports = router;