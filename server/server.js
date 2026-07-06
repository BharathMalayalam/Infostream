require('dotenv').config();

// Override DNS to use Google's public DNS — fixes SRV lookup failures
// on ISP/router DNS servers that don't support SRV record queries
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// CORS — allow credentials (cookies) from the client
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,          // required for cookies to be sent cross-origin
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());        // parse cookies from incoming requests

mongoose.connect(process.env.MONGODB_URI, {
    family: 4,               // force IPv4 — prevents Atlas rejection of IPv6-mapped addresses
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
})
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB connection error:', err.message));

app.use('/api/auth', require('./routes/auth'));
app.use('/api',      require('./routes/api'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
