const express = require('express');
const router = express.Router();
const checkRole = require('../middleware/checkRole');
const auth = require('../middleware/auth'); // You must have an auth middleware
const uploadHandler = require('../controllers/main'); // Your upload logic

// Example: Only designers and photographers can upload
router.post('/upload', auth, checkRole(['designer', 'photographer']), uploadHandler);

router.get('/download/:fileId', auth, async (req, res) => {
  const file = await File.findById(req.params.fileId);
  if (!file) return res.status(404).json({ msg: 'File not found' });
  if (file.owner.toString() !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ msg: 'Forbidden' });
  }
  if (req.user.credits < 10) return res.status(400).json({ msg: 'Insufficient credits' });
  req.user.credits -= 10;
  await req.user.save();
  res.download(file.path, file.originalName);
});

module.exports = router;