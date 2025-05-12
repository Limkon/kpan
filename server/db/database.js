const sqlite3 = require('sqlite3').verbose();
const { SQLITE_DB_PATH } = require('../config/db.config');
const { userFilesBasePath } = require('../config/storage.config');
const fs = require('fs');
const { mkdirp } = require('mkdirp');


// Create base uploads directory if it doesn't exist
if (!fs.existsSync(userFilesBasePath)) {
  mkdirp.sync(userFilesBasePath);
  console.log(`Base upload directory created at: ${userFilesBasePath}`);
}


const db = new sqlite3.Database(SQLITE_DB_PATH, (err) => {
  if (err) {
    console.error("Error opening database " + err.message);
  } else {
    console.log("Connected to SQLite database.");
    initializeDb();
  }
});

const initializeDb = () => {
  db.serialize(() => {
    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user', -- 'user' or 'admin'
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error("Error creating users table", err);
      else console.log("Users table checked/created.");
    });

    // Shares Table (Placeholder for future implementation)
    db.run(`CREATE TABLE IF NOT EXISTS shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      file_path_relative TEXT NOT NULL,
      share_token TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
      if (err) console.error("Error creating shares table", err);
      else console.log("Shares table checked/created.");
    });

    // File Metadata Table (Optional, for more detailed tracking than just FS)
    // This is an example, you might not need it if fs operations are sufficient
    db.run(`CREATE TABLE IF NOT EXISTS file_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_path TEXT UNIQUE NOT NULL, -- Full path on server to the file/folder
        original_name TEXT NOT NULL,
        is_folder BOOLEAN DEFAULT FALSE,
        mime_type TEXT,
        size_bytes INTEGER,
        parent_folder_id INTEGER, -- For folder structure, references another file_metadata(id)
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (parent_folder_id) REFERENCES file_metadata(id) ON DELETE CASCADE
    )`, (err) => {
        if (err) console.error("Error creating file_metadata table", err);
        else console.log("File_metadata table checked/created.");
    });

    // Create an initial admin user if one doesn't exist (for testing/setup)
    // In a real app, this might be done via a setup script or a special first-run UI
    const bcrypt = require('bcryptjs');
    const adminUsername = 'admin';
    const adminPassword = 'adminpassword'; // Change this!

    db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, row) => {
      if (err) return console.error("Error checking for admin user", err);
      if (!row) {
        const hashedPassword = bcrypt.hashSync(adminPassword, 8);
        db.run('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
          [adminUsername, hashedPassword, 'admin'],
          (insertErr) => {
            if (insertErr) return console.error("Error creating admin user", insertErr);
            console.log(`Admin user '${adminUsername}' created with default password.`);
          }
        );
      }
    });
  });
};

module.exports = db;
