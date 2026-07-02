const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Notification = require('../models/Notification');
const Placement = require('../models/Placement');
const Exam = require('../models/Exam');
const auth = require('../middleware/auth');
const bcrypt = require('bcryptjs');

// Admin Dashboard Data
router.get('/admin', auth(['admin', 'staff']), async (req, res) => {
    try {
        const notifications = await Notification.find().sort({ created_at: -1 });
        const placements = await Placement.find().sort({ created_at: -1 });
        const exams = await Exam.find().sort({ created_at: -1 });
        let users = [];
        
        if (req.user.role === 'admin') {
            users = await User.find().sort({ role: -1, username: 1 });
        }

        res.json({ notifications, placements, exams, users });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Admin adds notifications
router.post('/notifications', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { title, content, type, department, year, is_urgent, category } = req.body;
        
        if (!title) return res.status(400).json({ message: 'Validation Error: Transmission header cannot be empty' });
        if (!content) return res.status(400).json({ message: 'Validation Error: Data stream content cannot be empty' });
        
        let deptStr = null, yearStr = null;
        if (type === 'department') {
            if (!department || department.length === 0) return res.status(400).json({ message: 'Validation Error: Please select at least one target sector' });
            if (!year || year.length === 0) return res.status(400).json({ message: 'Validation Error: Please select at least one sector phase' });
            deptStr = department.join(',');
            yearStr = year.join(',');
        }

        const notif = new Notification({
            title, content, department: deptStr, year: yearStr, 
            is_urgent: is_urgent ? 1 : 0, 
            category: category || 'Events',
            posted_by: req.user.username
        });
        await notif.save();
        res.json({ message: 'Notification published' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/placements', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { company, role, eligibility, deadline, description, is_urgent } = req.body;
        
        if (!company) return res.status(400).json({ message: 'Validation Error: Corporate entity cannot be empty' });
        if (!role) return res.status(400).json({ message: 'Validation Error: Operational role cannot be empty' });
        if (!eligibility) return res.status(400).json({ message: 'Validation Error: Eligibility parameters cannot be empty' });
        if (!deadline) return res.status(400).json({ message: 'Validation Error: Activation deadline must be set' });
        
        const ddate = new Date(deadline);
        if (ddate <= new Date()) return res.status(400).json({ message: 'Validation Error: Activation deadline must be a future date' });
        
        if (!description) return res.status(400).json({ message: 'Validation Error: Detailed intelligence cannot be empty' });

        const p = new Placement({
            company, role, eligibility, deadline, description,
            is_urgent: is_urgent ? 1 : 0,
            posted_by: req.user.username
        });
        await p.save();
        res.json({ message: 'Placement update broadcasting...' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/exams', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { exam_type, title, content, department, year, is_urgent } = req.body;
        
        if (!title) return res.status(400).json({ message: 'Validation Error: Update header cannot be empty' });
        if (!content) return res.status(400).json({ message: 'Validation Error: Detailed payload cannot be empty' });
        if (!department || department.length === 0) return res.status(400).json({ message: 'Validation Error: Please select at least one target sector' });
        if (!year || year.length === 0) return res.status(400).json({ message: 'Validation Error: Please select at least one target phase' });

        const e = new Exam({
            exam_type, title, content,
            department: department.join(','), year: year.join(','),
            is_urgent: is_urgent ? 1 : 0,
            posted_by: req.user.username
        });
        await e.save();
        res.json({ message: 'Exam update published' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.delete('/notifications/:id', auth(['admin', 'staff']), async (req, res) => {
    await Notification.findByIdAndDelete(req.params.id);
    res.json({ message: 'Notification deleted successfully' });
});

router.delete('/placements/:id', auth(['admin', 'staff']), async (req, res) => {
    await Placement.findByIdAndDelete(req.params.id);
    res.json({ message: 'Placement record deleted successfully' });
});

router.delete('/exams/:id', auth(['admin', 'staff']), async (req, res) => {
    await Exam.findByIdAndDelete(req.params.id);
    res.json({ message: 'Exam record deleted successfully' });
});

// Admin User Management
router.post('/users/staff', auth('admin'), async (req, res) => {
    try {
        const { username, password, phone } = req.body;
        const exists = await User.findOne({ username });
        if (exists) return res.status(400).json({ message: 'Username already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const u = new User({ username, password: hashedPassword, role: 'staff', phone });
        await u.save();
        res.json({ message: `Staff account created for ${username}` });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/users/student', auth('admin'), async (req, res) => {
    try {
        const { username, password, department, year, phone } = req.body;
        const exists = await User.findOne({ username });
        if (exists) return res.status(400).json({ message: 'Identifier already exists in network' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const u = new User({ username, password: hashedPassword, role: 'student', department, year, phone });
        await u.save();
        res.json({ message: `Student identity provisioned: ${username}` });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.delete('/users/:id', auth('admin'), async (req, res) => {
    if (req.params.id === req.user.id) {
        return res.status(400).json({ message: 'Cannot revoke own identity' });
    }
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'Identity revoked and access terminated' });
});

// Student Dashboard Data
router.get('/student', auth('student'), async (req, res) => {
    try {
        const { department, year } = req.user;
        
        let notifications = await Notification.find();
        notifications = notifications.filter(n => !n.department || (n.department.includes(department) && n.year.includes(year))).map(n => ({ ...n._doc, type: 'notification' }));
        
        const placements = (await Placement.find()).map(p => ({ ...p._doc, type: 'placement' }));
        
        let exams = await Exam.find();
        exams = exams.filter(e => !e.department || (e.department.includes(department) && e.year.includes(year))).map(e => ({ ...e._doc, type: 'exam' }));

        let all_streams = [...notifications, ...placements, ...exams];
        all_streams.sort((a, b) => {
            if (b.is_urgent !== a.is_urgent) return b.is_urgent - a.is_urgent;
            return new Date(b.created_at) - new Date(a.created_at);
        });

        res.json({ streams: all_streams });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.get('/urgent_check', auth('student'), async (req, res) => {
    try {
        const { department, year } = req.user;
        const since = req.query.since || new Date().toISOString();

        let notifications = await Notification.find({ is_urgent: 1, created_at: { $gt: new Date(since) } });
        notifications = notifications.filter(n => !n.department || (n.department.includes(department) && n.year.includes(year))).map(n => ({ type: 'notification', title: n.title, content: n.content, created_at: n.created_at }));

        const placements = await Placement.find({ is_urgent: 1, created_at: { $gt: new Date(since) } });
        const p_mapped = placements.map(p => ({ type: 'placement', title: p.company, content: p.role, created_at: p.created_at }));

        let exams = await Exam.find({ is_urgent: 1, created_at: { $gt: new Date(since) } });
        exams = exams.filter(e => !e.department || (e.department.includes(department) && e.year.includes(year))).map(e => ({ type: 'exam', title: e.title, content: e.exam_type, created_at: e.created_at }));

        res.json({ urgent_alerts: [...notifications, ...p_mapped, ...exams] });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
