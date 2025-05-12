const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db/database.js');
const jwtConfig = require('../config/jwt.config.js');
const path = require('path');
const { mkdirp } = require('mkdirp');
const { userFilesBasePath } = require('../config/storage.config');

// Ensure user directory exists or create it
const ensureUserStorage = async (userId) => {
  const userDir = path.join(userFilesBasePath, String(userId));
  try {
    await mkdirp(userDir);
    console.log(`Storage directory for user ${userId} ensured at ${userDir}`);
  } catch (err) {
    console.error(`Failed to create storage directory for user ${userId}:`, err);
    // Depending on severity, you might want to throw this error
  }
};

exports.register = (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ message: "Username and password are required." });
  }

  const hashedPassword = bcrypt.hashSync(password, 8);

  db.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
    [username, hashedPassword, 'user'], // Default role 'user'
    function (err) { // Use function keyword to get 'this.lastID'
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).send({ message: "Failed! Username is already in use!" });
        }
        return res.status(500).send({ message: err.message });
      }
      const userId = this.lastID;
      ensureUserStorage(userId)
        .then(() => {
          res.send({ message: "User was registered successfully!", userId: userId });
        })
        .catch(storageErr => {
          // Potentially rollback user creation or log critical error
          console.error("Storage creation failed for new user:", storageErr);
          res.status(500).send({ message: "User registered, but failed to create storage. Please contact admin." });
        });
    }
  );
};

exports.login = (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ message: "Username and password are required." });
  }

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.status(500).send({ message: err.message });
    }
    if (!user) {
      return res.status(404).send({ message: "User Not found." });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password_hash);
    if (!passwordIsValid) {
      return res.status(401).send({ accessToken: null, message: "Invalid Password!" });
    }

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, jwtConfig.secret, {
      expiresIn: jwtConfig.jwtExpiration
    });

    res.status(200).send({
      id: user.id,
      username: user.username,
      role: user.role,
      accessToken: token
    });
  });
};

exports.getCurrentUser = (req, res) => {
    // req.userId and req.userRole are set by authMiddleware.verifyToken
    if (!req.userId) {
        return res.status(401).send({ message: "Not authenticated" });
    }
    db.get("SELECT id, username, role, created_at FROM users WHERE id = ?", [req.userId], (err, user) => {
        if (err) {
            return res.status(500).send({ message: "Error retrieving user." });
        }
        if (!user) {
            return res.status(404).send({ message: "User not found." });
        }
        res.status(200).send(user);
    });
};
