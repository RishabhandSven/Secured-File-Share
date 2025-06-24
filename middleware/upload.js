const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    // Sanitize filename
    const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, `${uuidv4()}-${safeName}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Restrict file types as needed
  const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'video/mp4', 'application/zip'];
  if (!allowed.includes(file.mimetype)) return cb(new Error('Invalid file type'), false);
  cb(null, true);
};

module.exports = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB