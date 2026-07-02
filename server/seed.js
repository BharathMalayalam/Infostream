require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/infostream';

async function seedAdmin() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('MongoDB Connected');

        // Check if admin already exists
        const existing = await User.findOne({ role: 'admin' });
        if (existing) {
            console.log(`Admin already exists: "${existing.username}"`);
            process.exit(0);
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);

        const admin = new User({
            username: 'admin',
            password: hashedPassword,
            role: 'admin',
            phone: ''
        });

        await admin.save();
        console.log('=================================');
        console.log('Admin user created successfully!');
        console.log('Username : admin');
        console.log('Password : admin123');
        console.log('=================================');
        console.log('Change the password after first login!');
        process.exit(0);
    } catch (err) {
        console.error('Seeding failed:', err.message);
        process.exit(1);
    }
}

seedAdmin();
