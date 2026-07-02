const jwt = require('jsonwebtoken');

const auth = (roles = []) => {
    // roles param can be a single role string (e.g. 'admin') or an array of roles (e.g. ['admin', 'staff'])
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return (req, res, next) => {
        const token = req.header('Authorization');
        if (!token) return res.status(401).json({ message: 'Access Denied: No token provided' });

        try {
            const verified = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET || 'supersecretkey');
            req.user = verified;
            
            if (roles.length && !roles.includes(req.user.role)) {
                return res.status(403).json({ message: 'Unauthorized access' });
            }
            
            next();
        } catch (err) {
            res.status(400).json({ message: 'Invalid token' });
        }
    };
};

module.exports = auth;
