const jwt = require("jsonwebtoken");
const jwtConfig = require("../config/jwt.config.js");
const db = require("../db/database.js");

const verifyToken = (req, res, next) => {
  let token = req.headers["authorization"];

  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }

  if (token.startsWith('Bearer ')) {
    token = token.slice(7, token.length);
  }

  jwt.verify(token, jwtConfig.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized! Invalid Token." });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

const isAdmin = (req, res, next) => {
  db.get("SELECT role FROM users WHERE id = ?", [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(500).send({ message: "Error fetching user role or user not found." });
    }
    if (user.role === "admin") {
      next();
      return;
    }
    res.status(403).send({ message: "Require Admin Role!" });
  });
};

const authMiddleware = {
  verifyToken,
  isAdmin,
};

module.exports = authMiddleware;
