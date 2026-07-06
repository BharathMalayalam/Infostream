const jwt = require('jsonwebtoken');

/**
 * Auth middleware — reads JWT from HTTP-only cookie (not Authorization header).
 * @param {string|string[]} roles - allowed roles e.g. 'admin' or ['admin', 'staff']
 */
const auth = (roles = []) => {
    if (typeof roles === 'string') roles = [roles];

    return (req, res, next) => {
        // Read token from HTTP-only cookie set at login
        const token = req.cookies?.token;

        if (!token) {
            return res.status(401).json({ message: 'Access denied: not authenticated.' });
        }

        try {
            const verified = jwt.verify(token, process.env.JWT_SECRET);
            req.user = verified;

            // Check role if restrictions specified
            if (roles.length && !roles.includes(req.user.role)) {
                return res.status(403).json({ message: 'Forbidden: insufficient permissions.' });
            }

            next();
        } catch (err) {
            // Token expired or tampered
            const isProd = process.env.NODE_ENV === 'production';
            res.clearCookie('token', {
                httpOnly: true,
                secure: isProd,
                sameSite: isProd ? 'none' : 'lax',
                path: '/',
            });
            return res.status(401).json({ message: 'Session expired. Please log in again.' });
        }
    };
};

module.exports = auth;
