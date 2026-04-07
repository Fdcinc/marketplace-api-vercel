const path = require('path');
const mongoose = require('mongoose');
const User = require('../models/users');
const fs = require('fs');

// 1. Improved .env loading logic
const rootEnv = path.join(process.cwd(), '.env');
if (fs.existsSync(rootEnv)) {
  require('dotenv').config({ path: rootEnv });
} else {
  // Fallback for different execution contexts
  require('dotenv').config({ path: path.join(__dirname, '../../../.env') });
}

const ADMIN_EMAIL = 'nick@marketplace.com';
const NEW_PASSWORD = 'admin2026test';

async function resetAdminPassword() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is undefined. Check your .env file at the root.');
    }

    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected.');

    // 2. Find OR Create the Admin
    let user = await User.findOne({ email: ADMIN_EMAIL });

    if (!user) {
      console.log(`Creating NEW admin account for ${ADMIN_EMAIL}...`);
      user = new User({ 
        email: ADMIN_EMAIL, 
        name: 'Nick Admin' 
      });
    } else {
      console.log(`Found existing user ${ADMIN_EMAIL}. Updating credentials...`);
    }

    // 3. Update Fields
    // IMPORTANT: We set plain text. The Model's pre-save hook 
    // transforms this into a 60-character bcrypt hash.
    user.passwordHash = NEW_PASSWORD; 
    user.role = 'superadmin'; // Matches your validator enum
    user.status = 'active';   // Matches your validator enum
    user.emailVerified = true;
    user.schemaVersion = 2;

    // 4. Save to Database
    // This triggers the pre-save hook in api/v1/models/users.js
    await user.save();

    console.log('\n' + '='.repeat(40));
    console.log('🚀 ADMIN STATUS UPDATED SUCCESSFULLY');
    console.log(`Email:    ${ADMIN_EMAIL}`);
    console.log(`Password: ${NEW_PASSWORD}`);
    console.log(`Role:     ${user.role}`);
    console.log('='.repeat(40));

    // Cleanly close connection
    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('\n❌ SCRIPT ERROR:', err.message);
    // Suggest the fix if the validation error persists
    if (err.message.includes('passwordHash')) {
      console.log('\n💡 TIP: Ensure you removed "minlength: 60" from the passwordHash field in api/v1/models/users.js');
    }
    process.exit(1);
  }
}

resetAdminPassword();