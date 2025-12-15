/**
 * ===========================================
 * USER MODEL - COLIN's TASK - COMPLETED
 * ===========================================
 */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator"); // Imported for clean email validation

/**
 * User Schema Definition
 */
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Please add a username'],
      unique: true,
      trim: true,
      maxlength: [50, 'Username cannot be more than 50 characters']
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: [validator.isEmail, 'Please provide a valid email']
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [6, 'Password must be at least 6 characters'],
      select: false 
    }
  },
  { timestamps: true }
);

// ===========================================
// PASSWORD HASHING MIDDLEWARE
// ===========================================

// Encrypt password using bcrypt before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Method to verify password
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
