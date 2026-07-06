const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const isProduction = process.env.NODE_ENV === 'production';

const COOKIE_OPTIONS = {
    httpOnly: true,          // not accessible via JS — prevents XSS token theft
    secure: isProduction,    // HTTPS-only in production
    sameSite: isProduction ? 'none' : 'lax', // 'none' requires secure=true (HTTPS)
    path: '/',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours in ms
};

// ── REGISTER ──────────────────────────────────────────────
router.post('/register', async (req, res) => {
    try {
        const { username, password, role, department, year, phone } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        // Only allow 'student' role via public registration — admin/staff created by admin
        const allowedPublicRoles = ['student'];
        const assignedRole = allowedPublicRoles.includes(role) ? role : 'student';

        const userExists = await User.findOne({ username });
        if (userExists) return res.status(400).json({ message: 'Username already exists.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            username,
            password: hashedPassword,
            role: assignedRole,
            department: assignedRole === 'student' ? department : undefined,
            year: assignedRole === 'student' ? year : undefined,
            phone,
        });
        await user.save();

        res.status(201).json({ message: 'Registration successful.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── LOGIN ─────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const selectedRole = role || 'student';

        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid credentials.' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ message: 'Invalid credentials.' });

        // Role must match exactly what was selected at login
        if (user.role !== selectedRole) {
            return res.status(400).json({ message: 'Selected role does not match your account.' });
        }

        const token = jwt.sign(
            {
                id: user._id,
                username: user.username,
                role: user.role,
                department: user.department,
                year: user.year,
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Set token as HTTP-only cookie — never exposed to JS
        res.cookie('token', token, COOKIE_OPTIONS);

        // Send back only non-sensitive user info (no token in body)
        res.json({
            role: user.role,
            username: user.username,
            id: user._id,
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ── LOGOUT ────────────────────────────────────────────────
router.post('/logout', (req, res) => {
    // Clear the HTTP-only cookie by overwriting with an expired one
    res.clearCookie('token', {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/',
    });
    res.json({ message: 'Logged out successfully.' });
});

// ── VERIFY (check if current cookie session is valid) ─────
router.get('/verify', (req, res) => {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ authenticated: false });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ authenticated: true, role: verified.role, username: verified.username, id: verified.id });
    } catch {
        res.status(401).json({ authenticated: false });
    }
});

// ── CHANGE PASSWORD ───────────────────────────────────────
const auth = require('../middleware/auth');
router.post('/change-password', auth(), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required.' });
        }

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });

        const validPass = await bcrypt.compare(currentPassword, user.password);
        if (!validPass) return res.status(400).json({ message: 'Incorrect current password.' });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.json({ message: 'Password updated successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
