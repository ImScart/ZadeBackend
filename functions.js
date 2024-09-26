// Import modules
const keys = require('./config/keys.js');
const jwt = require('jsonwebtoken');

// Functions
function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer token

    if (!token) {
        return res.status(401).send({ code: 1, message: 'Access token required' });
    }

    jwt.verify(token, keys.secretKey, (err, user) => {
        if (err) {
            return res.status(403).send({ code: 1, message: 'Invalid access token' });
        }
        req.user = user; // The decoded token payload
        next();
    });
}

module.exports = {
authenticate
};
