// config/db.js
const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error('Please define MONGODB_URI environment variable');
}

// Cache the connection across serverless function invocations
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    console.log('Using cached database connection');
    return cached.conn;
  }

  if (!cached.promise) {
    // Log the connection string (with password masked) for debugging
    const maskedUri = MONGODB_URI.replace(/:([^@]+)@/, ':****@');
    console.log('Creating new database connection to:', maskedUri);

    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4, // Force IPv4 (helps with some Atlas issues)
    };

    cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => {
      console.log('MongoDB connected successfully');
      mongoose.connection.on('disconnected', () => {
        console.log('MongoDB disconnected — will attempt to reconnect...');
      });
      mongoose.connection.on('error', (err) => {
        console.error('MongoDB connection error:', err.message);
      });
      return mongoose;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null; // Allow retry on next request
    console.error('Full MongoDB connection error:', {
      message: e.message,
      name: e.name,
      code: e.code,
      stack: e.stack,
    });
    throw e; // Re-throw so the route can handle it
  }

  return cached.conn;
}

module.exports = connectDB;