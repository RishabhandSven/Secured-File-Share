const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const checkRole = require('../middleware/checkRole');
const upload = require('../middleware/upload'); // Multer config
const { uploadHandler } = require('../controllers/main'); // Your upload logic

router.post(
  '/upload',
  auth,
  checkRole(['student', 'photographer', 'videographer', 'business', 'admin']), // adjust roles as needed
  upload.single('file'), // 'file' must match frontend input name
  uploadHandler
);

module.exports = router;