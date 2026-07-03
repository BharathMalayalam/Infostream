const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Notification = require('../models/Notification');
const Placement = require('../models/Placement');
const Exam = require('../models/Exam');
const auth = require('../middleware/auth');
const bcrypt = require('bcryptjs');

// ─────────────────────────────────────────────────────────────
// Helper: check if a student matches a notification/exam target
// Uses exact word-boundary matching to prevent "CS" matching "CSE"
// ─────────────────────────────────────────────────────────────
function matchesDeptYear(record, userDept, userYear) {
    // No targeting = global broadcast → visible to everyone
    if (!record.department) return true;

    // Department is stored as comma-separated e.g. "CSE,ECE,IT"
    const targetDepts  = record.department.split(',').map(d => d.trim());
    const targetYears  = record.year ? record.year.split(',').map(y => y.trim()) : [];

    return targetDepts.includes(userDept) && targetYears.includes(String(userYear));
}

// ═══════════════════════════════════════════════════════════════
// ADMIN / STAFF — Dashboard Data
// ═══════════════════════════════════════════════════════════════
router.get('/auth/admin', auth(['admin', 'staff']), async (req, res) => {
    try {
        const notifications = await Notification.find().sort({ created_at: -1 });
        const placements    = await Placement.find().sort({ created_at: -1 });
        const exams         = await Exam.find().sort({ created_at: -1 });

        // Only full admins can see user roster
        let users = [];
        if (req.user.role === 'admin') {
            users = await User.find({}, '-password').sort({ role: -1, username: 1 });
        }

        res.json({ notifications, placements, exams, users });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ─── Post Notification ────────────────────────────────────────
router.post('/auth/notifications', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { title, content, type, department, year, is_urgent, category } = req.body;

        if (!title?.trim())   return res.status(400).json({ message: 'Title cannot be empty.' });
        if (!content?.trim()) return res.status(400).json({ message: 'Message content cannot be empty.' });

        let deptStr = null;
        let yearStr = null;

        if (type === 'department') {
            if (!department || department.length === 0)
                return res.status(400).json({ message: 'Please select at least one department.' });
            if (!year || year.length === 0)
                return res.status(400).json({ message: 'Please select at least one year.' });
            deptStr = department.join(',');
            yearStr = year.join(',');
        }

        const notif = new Notification({
            title:      title.trim(),
            content:    content.trim(),
            department: deptStr,
            year:       yearStr,
            is_urgent:  is_urgent ? 1 : 0,
            category:   category || 'Events',
            posted_by:  req.user.username,
        });
        await notif.save();
        res.json({ message: 'Notification published successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ─── Post Placement ───────────────────────────────────────────
router.post('/auth/placements', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { company, role, eligibility, deadline, description, is_urgent } = req.body;

        if (!company?.trim())     return res.status(400).json({ message: 'Company name is required.' });
        if (!role?.trim())        return res.status(400).json({ message: 'Job title is required.' });
        if (!eligibility?.trim()) return res.status(400).json({ message: 'Eligibility criteria is required.' });
        if (!deadline)            return res.status(400).json({ message: 'Application deadline is required.' });
        if (!description?.trim()) return res.status(400).json({ message: 'Job description is required.' });

        // Ensure deadline is a future date
        const deadlineDate = new Date(deadline);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (deadlineDate < today)
            return res.status(400).json({ message: 'Deadline must be a future date.' });

        const placement = new Placement({
            company:     company.trim(),
            role:        role.trim(),
            eligibility: eligibility.trim(),
            deadline,
            description: description.trim(),
            is_urgent:   is_urgent ? 1 : 0,
            posted_by:   req.user.username,
        });
        await placement.save();
        res.json({ message: 'Placement posted successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ─── Post Exam Notice ─────────────────────────────────────────
router.post('/auth/exams', auth(['admin', 'staff']), async (req, res) => {
    try {
        const { exam_type, title, content, department, year, is_urgent } = req.body;

        if (!title?.trim())   return res.status(400).json({ message: 'Exam title is required.' });
        if (!content?.trim()) return res.status(400).json({ message: 'Exam details are required.' });
        if (!department || department.length === 0)
            return res.status(400).json({ message: 'Please select at least one department.' });
        if (!year || year.length === 0)
            return res.status(400).json({ message: 'Please select at least one year.' });

        const exam = new Exam({
            exam_type:  exam_type || 'Internal Test',
            title:      title.trim(),
            content:    content.trim(),
            department: department.join(','),
            year:       year.join(','),
            is_urgent:  is_urgent ? 1 : 0,
            posted_by:  req.user.username,
        });
        await exam.save();
        res.json({ message: 'Exam notice published successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ─── Delete Records ───────────────────────────────────────────
router.delete('/auth/notifications/:id', auth(['admin', 'staff']), async (req, res) => {
    try {
        await Notification.findByIdAndDelete(req.params.id);
        res.json({ message: 'Notification deleted.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.delete('/auth/placements/:id', auth(['admin', 'staff']), async (req, res) => {
    try {
        await Placement.findByIdAndDelete(req.params.id);
        res.json({ message: 'Placement deleted.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.delete('/auth/exams/:id', auth(['admin', 'staff']), async (req, res) => {
    try {
        await Exam.findByIdAndDelete(req.params.id);
        res.json({ message: 'Exam notice deleted.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN ONLY — User Management
// ═══════════════════════════════════════════════════════════════

// Create staff account
router.post('/auth/users/staff', auth('admin'), async (req, res) => {
    try {
        const { username, password, phone } = req.body;
        if (!username?.trim() || !password)
            return res.status(400).json({ message: 'Username and password are required.' });

        const exists = await User.findOne({ username });
        if (exists) return res.status(400).json({ message: 'Username already exists.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await new User({ username: username.trim(), password: hashedPassword, role: 'staff', phone }).save();
        res.json({ message: `Staff account created for ${username}.` });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Create admin account (super admin provisioning another super admin)
router.post('/auth/users/admin', auth('admin'), async (req, res) => {
    try {
        const { username, password, phone } = req.body;
        if (!username?.trim() || !password)
            return res.status(400).json({ message: 'Username and password are required.' });

        const exists = await User.findOne({ username });
        if (exists) return res.status(400).json({ message: 'Username already exists.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await new User({ username: username.trim(), password: hashedPassword, role: 'admin', phone }).save();
        res.json({ message: `Super Admin account created for ${username}.` });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Create student account (admin-provisioned)
router.post('/auth/users/student', auth('admin'), async (req, res) => {
    try {
        const { username, password, department, year, phone } = req.body;
        if (!username?.trim() || !password)
            return res.status(400).json({ message: 'Username and password are required.' });

        const exists = await User.findOne({ username });
        if (exists) return res.status(400).json({ message: 'Username already exists.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await new User({ username: username.trim(), password: hashedPassword, role: 'student', department, year, phone }).save();
        res.json({ message: `Student account created for ${username}.` });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Delete user (cannot delete yourself)
router.delete('/auth/users/:id', auth('admin'), async (req, res) => {
    try {
        if (req.params.id === req.user.id)
            return res.status(400).json({ message: 'You cannot delete your own account.' });

        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });

        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User account deleted successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ═══════════════════════════════════════════════════════════════
// STUDENT — Stream Feed
// ═══════════════════════════════════════════════════════════════
router.get('/auth/student', auth('student'), async (req, res) => {
    try {
        const { department, year } = req.user;

        // Notifications: global OR targeted to this student's dept+year
        const allNotifications = await Notification.find().sort({ created_at: -1 });
        const notifications = allNotifications
            .filter(n => matchesDeptYear(n, department, year))
            .map(n => ({ ...n._doc, type: 'notification' }));

        // Placements: all placements are visible to all students
        const placements = (await Placement.find().sort({ created_at: -1 }))
            .map(p => ({ ...p._doc, type: 'placement' }));

        // Exams: always targeted to specific dept+year
        const allExams = await Exam.find().sort({ created_at: -1 });
        const exams = allExams
            .filter(e => matchesDeptYear(e, department, year))
            .map(e => ({ ...e._doc, type: 'exam' }));

        // Merge and sort: urgent first, then newest first
        const streams = [...notifications, ...placements, ...exams].sort((a, b) => {
            if (b.is_urgent !== a.is_urgent) return b.is_urgent - a.is_urgent;
            return new Date(b.created_at) - new Date(a.created_at);
        });

        res.json({ streams });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// ─── Urgent alert polling ─────────────────────────────────────
router.get('/auth/urgent_check', auth('student'), async (req, res) => {
    try {
        const { department, year } = req.user;
        const since = req.query.since ? new Date(req.query.since) : new Date();

        // Urgent notifications since last check
        const allNotifs = await Notification.find({ is_urgent: 1, created_at: { $gt: since } });
        const notifications = allNotifs
            .filter(n => matchesDeptYear(n, department, year))
            .map(n => ({ type: 'notification', title: n.title, content: n.content, created_at: n.created_at }));

        // Urgent placements (global)
        const placements = (await Placement.find({ is_urgent: 1, created_at: { $gt: since } }))
            .map(p => ({ type: 'placement', title: p.company, content: p.role, created_at: p.created_at }));

        // Urgent exams since last check
        const allExams = await Exam.find({ is_urgent: 1, created_at: { $gt: since } });
        const exams = allExams
            .filter(e => matchesDeptYear(e, department, year))
            .map(e => ({ type: 'exam', title: e.title, content: e.exam_type, created_at: e.created_at }));

        res.json({ urgent_alerts: [...notifications, ...placements, ...exams] });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
