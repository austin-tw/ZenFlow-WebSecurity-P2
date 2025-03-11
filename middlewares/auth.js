function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/error");
}

function ensureSuperUser(req, res, next) {
  if (req.isAuthenticated() && req.user.role === "superuser") {
    return next();
  }
  res.status(403).send("Access denied: Super Users only.");
}

module.exports = { ensureAuthenticated, ensureSuperUser };
