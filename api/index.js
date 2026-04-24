const path = require('path');
// This tells dotenv to look one level up from the /api folder for the .env
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const connectDB = require('./v1/config/db'); // Points to api/config/db.js
const authRoutes = require('./v1/routes/auth'); // Points to api/routes/auth.js

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB
connectDB();

app.use('/api/v1/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ message: "Marketplace API is running locally" });
});

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  // Adding '0.0.0.0' allows external connections (like Docker/Kong)
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

module.exports = app;

module.exports = app;