const mongoose = require('mongoose');
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected locally'))
  .catch(err => console.error('Local error:', err.message));