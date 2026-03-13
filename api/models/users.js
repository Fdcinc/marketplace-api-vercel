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
    schemaVersion: { type: Number, default: 1 },
  },
  {
    timestamps: true, // Automatically handles createdAt and updatedAt
  }
);

// ──── PRE-SAVE HOOK (Encryption) ────
UserSchema.pre('save', async function () {
  if (!this.isModified('passwordHash')) return;
  try {
    const salt = await bcrypt.genSalt(12);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
  } catch (err) {
    throw new Error(`Encryption failed: ${err.message}`);
  }
});

// ──── HELPER METHODS ────

// 1. Check if account is currently locked
UserSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// 2. Format user for public profiles (security)
UserSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.twoFactorSecret;
  delete user.recoveryCodes;
  return user;
};

// versioning logic: Handle legacy fields for older schema versions
UserSchema.post('init', function(doc) {
  if (doc.schemaVersion === 1) {
    // Example: If V1 users had a 'bio' string but V2 expects an object
    // doc.profile = { bio: doc.bio }; 
    
    // Example: Ensure 2FA field exists for V1 users in the app logic
    if (doc.twoFactorEnabled === undefined) {
      doc.twoFactorEnabled = false;
    }
  }
});

module.exports = mongoose.model('User', UserSchema);