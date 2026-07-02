const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

router.post('/register', async (req, res) => {
    try {
        const { username, password, role, department, year, phone } = req.body;
        
        // Check if user exists
        const userExists = await User.findOne({ username });
        if (userExists) return res.status(400).json({ message: 'Username already exists' });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const user = new User({ username, password: hashedPassword, role, department, year, phone });
        await user.save();

        res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const selected_role = role || 'student';

        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Access Denied: Invalid credentials' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ message: 'Access Denied: Invalid credentials' });

        if (user.role !== selected_role) {
            return res.status(400).json({ message: 'Identity verification failed: Selected role does not match user profile.' });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role, department: user.department, year: user.year },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
