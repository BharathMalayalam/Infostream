const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  department: { type: String },
  year: { type: String },
  is_urgent: { type: Number, default: 0 },
  category: { type: String, default: 'Events' },
  created_at: { type: Date, default: Date.now },
  posted_by: { type: String }
});

module.exports = mongoose.model('Notification', notificationSchema);
