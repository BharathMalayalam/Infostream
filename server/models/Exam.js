const mongoose = require('mongoose');

const examSchema = new mongoose.Schema({
  exam_type: { type: String },
  title: { type: String, required: true },
  content: { type: String, required: true },
  department: { type: String },
  year: { type: String },
  is_urgent: { type: Number, default: 0 },
  category: { type: String, default: 'Exam Cell' },
  created_at: { type: Date, default: Date.now },
  posted_by: { type: String }
});

module.exports = mongoose.model('Exam', examSchema);
