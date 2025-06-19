const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts, please try again later."
});

// Example: Signup route
router.post('/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isStrongPassword(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const hashedPassword = await bcrypt.hash(req.body.password, 12);
  const user = new User({
    email: req.body.email,
    password: hashedPassword,
  });
  await user.save();
  res.status(201).json({ msg: "User created" });
});

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ msg: "Invalid credentials" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(401).json({ msg: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h', algorithm: 'HS256' });
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ token });
});

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

const allowedRedirects = ['/dashboard', '/profile'];
if (!allowedRedirects.includes(req.query.redirect)) {
  return res.status(400).json({ msg: "Invalid redirect" });
}

module.exports = { router, authMiddleware };