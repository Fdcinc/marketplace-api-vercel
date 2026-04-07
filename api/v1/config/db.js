const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI;

// CRITICAL: If the URI is missing, catch it early
if (!MONGODB_URI) {
  throw new Error('Please define the MONGODB_URI environment variable');
}

let cached = global.mongoose || { conn: null, promise: null };

async function connectDB() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    // 1. Set global mongoose options before connecting
    // This ensures that even if buffering is off, Mongoose knows how to handle the initial boot
    mongoose.set('strictQuery', true); 

    cached.promise = mongoose.connect(MONGODB_URI, {
      bufferCommands: true, // Change to true to prevent the specific error you saw
      autoIndex: true,      // Good for development to ensure unique indexes work
    }).then((m) => {
      console.log('✅ MongoDB Connected');
      return m;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (e) {
    cached.promise = null; // Reset if the connection fails
    throw e;
  }

  return cached.conn;
}

// Store the connection in the global object so it persists across function reloads
global.mongoose = cached;

module.exports = connectDB;