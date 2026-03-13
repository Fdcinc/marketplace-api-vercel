const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      match: [/^[^@]+@[^@]+\.[^@]+$/, 'Please provide a valid email'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password is required'],
      select: false,
    },
    
    // ──── MARKETPLACE LOGIC ────
    interestedCategoryIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Category'
    }],
    addresses: [
      {
        street: String,
        city: String,
        state: String,
        zip: String,
        country: String,
        isDefault: { type: Boolean, default: false }
      }
    ],

    // ──── SECURITY & 2FA ────
    emailVerified: { type: Boolean, default: false },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, select: false },
    recoveryCodes: { 
      type: [String], 
      select: false 
    },

    // ──── ACCOUNT PROTECTION ────
    status: {
      type: String,
      enum: ['active', 'inactive', 'suspended', 'deleted'],
      default: 'active',
    },
    role: {
      type: String,
      enum: ['customer', 'vendor', 'admin', 'superadmin'],
      default: 'customer',
    },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLoginAt: { type: Date },
    deletedAt: { type: Date, default: null },

    // ──── SYSTEM ────
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },
    schemaVersion: { type: Number, default: 2 }, // Updated to V2 as current standard
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// ──── PRE-SAVE HOOK (Encryption & Versioning) ────
// ──── PRE-SAVE HOOK (Hardened & Fixed) ────
UserSchema.pre('save', async function () {
  // 1. Only run if password was modified
  if (!this.isModified('passwordHash')) return;

  try {
    const salt = await bcrypt.genSalt(12);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    // Note: With async/await, we do NOT call next()
  } catch (err) {
    // If you need to stop the save on error, throw it
    throw new Error(`Encryption failed: ${err.message}`);
  }
});

// ──── HELPER METHODS ────

// Check if account is currently locked
UserSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hardened toJSON: Removes sensitive fields automatically
UserSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.twoFactorSecret;
  delete user.recoveryCodes;
  delete user.passwordResetToken;
  delete user.passwordResetExpires;
  return user;
};

module.exports = mongoose.model('User', UserSchema);