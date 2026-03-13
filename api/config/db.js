// src/config/db.js
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10,
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);

    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected — will attempt to reconnect...');
    });

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err.message);
    });
  } catch (err) {
    console.error('MongoDB initial connection failed:', err.message);
    // Do NOT process.exit() here — let the server stay alive
  }
};

module.exports = connectDB;