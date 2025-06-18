const multer = require('multer');
const path = require('path');
const { v4: uuid } = require('uuid');

const allowedMimeTypes = [
  'application/pdf', 'image/jpeg', 'image/png', 'image/svg+xml',
  'application/zip', 'application/x-adobe-illustrator', 'video/mp4',
  'video/mpeg', 'video/quicktime', 'application/msword', 'application/vnd.ms-powerpoint'
];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, `${uuid()}-${safeName}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (!allowedMimeTypes.includes(file.mimetype)) return cb(new Error('Invalid file type'), false);
  const ext = path.extname(file.originalname).toLowerCase();
  if (['.php', '.exe', '.sh', '.bat', '.js', '.py', '.pl'].includes(ext)) return cb(new Error('Forbidden file extension'), false);
  cb(null, true);
};

module.exports = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } });