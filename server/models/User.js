const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true }, // admin, staff, student
  department: { type: String },
  year: { type: String },
  phone: { type: String }
});

module.exports = mongoose.model('User', userSchema);
