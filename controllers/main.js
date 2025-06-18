const User = require('../models/User');

// Example upload handler
const uploadHandler = async (req, res) => {
  // ...your existing upload logic...

  // Deduct credits
  if (req.user.credits < 10) return res.status(400).json({ msg: 'Insufficient credits' });
  req.user.credits -= 10;
  await req.user.save();

  // ...rest of your upload logic...
};

module.exports = uploadHandler;