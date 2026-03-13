const mongoose = require('mongoose');
const User = require('../models/users');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');
require('dotenv').config({ path: envPath });

const migrateToV2 = async () => {
  try {
    const uri = process.env.MONGODB_URI;
    console.log("--- MIGRATION START ---");
    console.log("Connecting to:", uri ? uri.substring(0, 30) + "..." : "NULL");

    await mongoose.connect(uri);
    console.log("✅ 1. Connected to Database");

    // Check how many users exist with Version 1
    const countV1 = await User.countDocuments({ 
      $or: [{ schemaVersion: 1 }, { schemaVersion: { $exists: false } }] 
    });
    console.log(`✅ 2. Found ${countV1} users needing update.`);

    if (countV1 === 0) {
      console.log("ℹ️ No users found that need migration. Check your Atlas data.");
    } else {
      // Perform the update
      const result = await User.updateMany(
        { 
          $or: [
            { schemaVersion: 1 },
            { schemaVersion: { $exists: false } }
          ]
        }, 
        {
          $set: { 
            schemaVersion: 2,
            twoFactorEnabled: false,
            emailVerified: false,
            loginAttempts: 0,
            status: 'active'
          }
        }
      );
      console.log(`✅ 3. Update result: Matched ${result.matchedCount}, Modified ${result.modifiedCount}`);
    }

    console.log("--- MIGRATION FINISHED ---");
    process.exit(0);
  } catch (err) {
    console.error("❌ Migration Error:", err.message);
    process.exit(1);
  }
};

migrateToV2();