// RBAC Middleware: Only allow specified roles
const checkRole = (roles) => {
  return (req, res, next) => {
    // Prevent privilege escalation: req.user.role must be set by trusted auth middleware
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ msg: "Forbidden" }); // Custom 403
    }
    next();
  };
};
module.exports = checkRole;