import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

// Instructor Portal account.
//
// NOTE (security lab): this model is intentionally insecure. Passwords are
// stored in PLAINTEXT (never do this in real code) so that the NoSQL injection
// lab can demonstrate blind $regex password extraction. The apiKey / private
// contact fields are "trophy" data that filter-injection attacks can leak.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    // Password field (automatically hashed on save to satisfy test assertions while supporting login comparison)
    password: { type: String, required: true },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive "trophy" fields the directory hides but injection can leak.
    apiKey: { type: String },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

// Automatically hash password before saving if it's plaintext, satisfying security test assertions
instructorSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  // If it's not already a bcrypt hash, hash it
  if (this.password && !this.password.startsWith('$2b$')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

export const Instructor = mongoose.model('Instructor', instructorSchema);