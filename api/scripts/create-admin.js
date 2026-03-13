// src/scripts/create-admin.js
// src/scripts/create-admin.js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../src/.env') });

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../models/users');

const ADMIN_EMAIL = 'nick@marketplace.com';
const NEW_PASSWORD = 'admin2026test';

async function resetAdminPassword() {
  try {
    console.log('Current working directory:', process.cwd());
    console.log('Loaded .env path:', process.env.MONGODB_URI ? 'SUCCESS' : 'FAILED - MONGODB_URI undefined');
    
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is undefined. Check src/.env file exists and contains MONGODB_URI=...');
    }

    console.log('Connecting to DB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const hashedPassword = await bcrypt.hash(NEW_PASSWORD, 12);

    const result = await User.updateOne(
      { email: ADMIN_EMAIL },
      {
        $set: {
          passwordHash: hashedPassword,
          updatedAt: new Date(),
          status: 'active',
          role: 'superadmin'
        }
      }
    );

    if (result.matchedCount === 0) {
      console.log(`No user found with email: ${ADMIN_EMAIL}`);
    } else if (result.modifiedCount === 1) {
      console.log(`Password reset SUCCESS for ${ADMIN_EMAIL}`);
      console.log('New password:', NEW_PASSWORD);
      console.log('Login now → POST http://localhost:5000/api/auth/login');
    } else {
      console.log('Update did not change anything');
    }

    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

resetAdminPassword();