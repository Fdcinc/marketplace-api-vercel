require('dotenv').config({ path: '../../../.env' }); // Adjust path to reach your .env
const mongoose = require('mongoose');

console.log("URI Check:", process.env.MONGODB_URI); // Debug to see if it's loading now

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected locally'))
  .catch(err => console.error('❌ Local error:', err.message));