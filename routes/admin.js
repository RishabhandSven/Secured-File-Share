const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth'); // Your JWT/session auth middleware
const isAdmin = require('../middleware/isAdmin');

// Example admin dashboard route
router.get('/dashboard', auth, isAdmin, (req, res) => {
  res.json({ msg: "Welcome to the admin panel!" });
});

// Add more admin-only routes here

module.exports = router;