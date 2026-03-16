const path = require('path');
// This tells dotenv to look one level up from the /api folder for the .env
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db'); // Points to api/config/db.js
const authRoutes = require('./routes/auth'); // Points to api/routes/auth.js

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB
connectDB();

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ message: "Marketplace API is running locally" });
});

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

module.exports = app;