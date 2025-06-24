module.exports = (req, res, next) => {
  // Assumes req.user is set by your auth middleware
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ msg: "Admins only" });
  }
  next();
};