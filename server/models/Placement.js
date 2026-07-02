const mongoose = require('mongoose');

const placementSchema = new mongoose.Schema({
  company: { type: String, required: true },
  role: { type: String, required: true },
  eligibility: { type: String, required: true },
  deadline: { type: String, required: true },
  description: { type: String, required: true },
  is_urgent: { type: Number, default: 0 },
  category: { type: String, default: 'Placement' },
  created_at: { type: Date, default: Date.now },
  posted_by: { type: String }
});

module.exports = mongoose.model('Placement', placementSchema);
