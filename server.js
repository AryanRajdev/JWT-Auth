const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// In-memory "database" of users
const users = []; // [{ username, password, refreshToken }]

const JWT_SECRET = 'my_super_secret_key';
const REFRESH_SECRET = 'my_super_refresh_secret_key';

// =================== SIGNUP ===================
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const accessToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: '7d' });

  users.push({ username, password: hashedPassword, refreshToken });

  res.status(201).json({ message: 'Signup successful!', accessToken, refreshToken });
});

// =================== LOGIN ===================
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const accessToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET, { expiresIn: '7d' });

  user.refreshToken = refreshToken;

  res.json({ message: 'Login successful!', accessToken, refreshToken });
});

// =================== REFRESH TOKEN ===================
app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ message: 'Refresh token required' });

  const user = users.find(user => user.refreshToken === refreshToken);
  if (!user) return res.status(403).json({ message: 'Invalid refresh token' });

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const newAccessToken = jwt.sign({ username: decoded.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});

// =================== AUTHENTICATE TOKEN MIDDLEWARE ===================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// =================== PROTECTED ROUTE ===================
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}! This is your profile.` });
});

// =================== START SERVER ===================
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
