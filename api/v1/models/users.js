const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  name: { type: String, trim: true },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true,
    match: [/^[^@]+@[^@]+\.[^@]+$/, 'Please provide a valid email address']
  },
  passwordHash: { 
    type: String, 
    required: true, 
    select: false 
  },
  
  // ──── MARKETPLACE DATA ────
  interestedCategoryIds: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Category' 
  }],
  addresses: { 
    type: [Object], 
    default: [] 
  },

  // ──── AUTHENTICATION & SECURITY ────
  emailVerified: { type: Boolean, default: false },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, select: false },
  recoveryCodes: { type: [String], select: false },
  
  // ──── ACCOUNT STATUS & ROLES ────
  status: { 
    type: String, 
    enum: ['active', 'inactive', 'suspended', 'deleted'], 
    default: 'active' 
  },
  role: { 
    type: String, 
    // HERE IS THE VENDOR CHANGE: replaced 'seller' with 'vendor'
    enum: ['customer', 'vendor', 'admin', 'superadmin'], 
    default: 'customer' 
  },
  
  // ──── AUDIT & RECOVERY ────
  schemaVersion: { type: Number, default: 2, min: 1 },
  lastLoginAt: { type: Date },
  deletedAt: { type: Date, default: null },
  passwordResetToken: { type: String, select: false },
  passwordResetExpires: { type: Date, select: false },
  
  // ──── SECURITY RATE-LIMITING ────
  loginAttempts: { type: Number, default: 0, min: 0 },
  lockUntil: { type: Date }
}, { 
  timestamps: true,
  versionKey: '__v' 
});

/**
 * PRE-SAVE HOOK
 */
UserSchema.pre('save', async function (next) { // Add next here
  if (!this.isModified('passwordHash')) return next();

  try {
    // Regex check to see if it's already a bcrypt hash
    if (/^\$2[ayb]\$.{56}$/.test(this.passwordHash)) return next();

    const salt = await bcrypt.genSalt(12);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    next();
  } catch (err) {
    next(new Error(`Encryption failed: ${err.message}`));
  }
});

/**
 * VIRTUALS
 * This makes the frontend happy by providing 'id' instead of just '_id'
 */
UserSchema.virtual('id').get(function() {
  return this._id.toHexString();
});

// Ensure virtuals are included when converting document to JSON/Object
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });

/**
 * HELPER METHODS
 */
UserSchema.methods.comparePassword = async function (candidatePassword) {
  // candidatePassword = plain text from user login
  // this.passwordHash = hashed string from DB
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);