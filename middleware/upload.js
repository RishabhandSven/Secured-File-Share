const multer = require('multer');
const path = require('path');
const { v4: uuid } = require('uuid');

// Restrict MIME types and extensions per role (expand as needed)
const allowedMimeTypes = {
  student: ['application/pdf', 'application/vnd.ms-powerpoint'],
  photographer: ['image/jpeg', 'image/png', 'image/heic'],
  designer: ['image/svg+xml', 'application/zip', 'application/x-adobe-illustrator'],
  videographer: ['video/mp4', 'video/mpeg', 'video/quicktime'],
  business: ['application/pdf', 'application/zip', 'application/msword']
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    // Sanitize filename, prevent directory traversal
    const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, `${uuid()}-${safeName}`);
  }
});

const fileFilter = (req, file, cb) => {
  const role = req.user?.role;
  const allowed = allowedMimeTypes[role] || [];
  if (!allowed.includes(file.mimetype)) return cb(new Error('Invalid file type'), false);
  const ext = path.extname(file.originalname).toLowerCase();
  if (['.php', '.exe', '.sh', '.bat', '.js', '.py', '.pl', '..', '/'].some(bad => ext.includes(bad))) return cb(new Error('Forbidden file extension'), false);
  cb(null, true);
};

module.exports = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit