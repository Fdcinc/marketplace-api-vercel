/**
 * @file config/db.js
 * @description Global MongoDB connection with caching (safe for serverless + long-running servers).
 *
 * Connect ONCE at application startup. Controllers/middleware should NOT call connectDB().
 *
 * @requires mongoose
 * @env MONGODB_URI
 *
 * Usage (in index.js / app entry):
 *   const connectDB = require('./v1/config/db');
 *   await connectDB();
 */
const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error('Please define the MONGODB_URI environment variable');
}

/** @type {{ conn: typeof mongoose | null, promise: Promise<typeof mongoose> | null }} */
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

/**
 * Establishes (or reuses) a single MongoDB connection.
 * Safe to call multiple times — subsequent calls return the cached connection.
 */
async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    console.log('🔄 Connecting to MongoDB...');

    mongoose.set('strictQuery', true);

    cached.promise = mongoose
      .connect(MONGODB_URI, {
        bufferCommands: false,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS: 45000,
      })
      .then((m) => {
        console.log('✅ MongoDB Connected');
        return m;
      });
  }

  try {
    cached.conn = await cached.promise;
  } catch (err) {
    cached.promise = null;
    console.error('❌ MongoDB connection error:', err.message);
    throw err;
  }

  return cached.conn;
}

/**
 * Optional helper: returns true when mongoose is ready.
 */
function isConnected() {
  return mongoose.connection.readyState === 1;
}

module.exports = connectDB;
module.exports.isConnected = isConnected;
module.exports.mongoose = mongoose;
