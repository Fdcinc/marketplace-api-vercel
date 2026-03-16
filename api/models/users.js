const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true, select: false },
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  role: { type: String, default: 'customer' },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date }
}, { timestamps: true });

// ──── PRE-SAVE HOOK (Fixed) ────
UserSchema.pre('save', async function () {
  // 1. Only run if password was modified
  if (!this.isModified('passwordHash')) return;

  try {
    const salt = await bcrypt.genSalt(12);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    // Notice: NO next() call here. 
    // Mongoose knows to wait because the function is async.
  } catch (err) {
    throw new Error(`Encryption failed: ${err.message}`);
  }
});

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);