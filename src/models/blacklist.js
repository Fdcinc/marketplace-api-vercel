const mongoose = require('mongoose'); // ONLY ONCE

const BlacklistSchema = new mongoose.Schema({
  token: { 
    type: String, 
    required: true, 
    index: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now, 
    expires: '1d' 
  }
});

// Check if the model already exists to prevent overwrite errors in some environments
module.exports = mongoose.models.Blacklist || mongoose.model('Blacklist', BlacklistSchema);