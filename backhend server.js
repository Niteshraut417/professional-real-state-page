require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db'); // Your database connection pool

const app = express();
app.use(cors());
app.use(express.json());

// Signup Endpoint
app.post('/api/signup', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users(email, password_hash, role) VALUES($1, $2, $3)', [email, hash, role]);
        res.status(201).json({ message: "User registered" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (user && await bcrypt.compare(password, user.password_hash)) {
        const token = jwt.sign({ email: user.email, role: user.role }, process.env.JWT_SECRET);
        res.json({ token, role: user.role });
    } else {
        res.status(401).json({ error: "Invalid credentials" });
    }
});

app.listen(3000, () => console.log('Backend active on port 3000'));
