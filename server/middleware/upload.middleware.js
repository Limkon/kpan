const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { mkdirp } = require('mkdirp');
const { userFilesBasePath } = require('../config/storage.config');

// Function to ensure user directory exists
const ensureUserDir = (userId) => {
  const userDir = path.join(userFilesBasePath, String(userId));
  if (!fs.existsSync(userDir)) {
    mkdirp.sync(userDir);
  }
  return userDir;
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userId = req.userId; // Assumes verifyToken middleware has run
    if (!userId) {
      return cb(new Error("User not authenticated for upload"), false);
    }
    const userPath = req.query.path || ''; // Relative path within user's directory
    const userDir = ensureUserDir(userId);
    const destinationPath = path.join(userDir, userPath);

    // Ensure subdirectories exist
    if (!fs.existsSync(destinationPath)) {
      try {
        mkdirp.sync(destinationPath);
      } catch (err) {
         return cb(new Error("Could not create destination directory: " + err.message), false);
      }
    }
    cb(null, destinationPath);
  },
  filename: (req, file, cb) => {
    // You might want to sanitize file.originalname or implement conflict resolution
    cb(null, file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 } // Example: 100MB limit
});

module.exports = upload;
