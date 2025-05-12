require('dotenv').config(); // Load .env variables first
const express = require('express');
const cors = require('cors');
const path = require('path');
const mainRouter = require('./routes/index');
const db = require('./db/database'); // Ensures DB is initialized when server starts

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors()); // Configure CORS appropriately for your frontend's origin in production
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API Routes
app.use('/api', mainRouter);

// Basic Error Handling Middleware (very simple)
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack || err);
  res.status(err.status || 500).send({
    message: err.message || "An unexpected error occurred.",
    // stack: process.env.NODE_ENV === 'development' ? err.stack : undefined // Optionally include stack in dev
  });
});

// Handle 404 for API routes not found
app.use('/api/*', (req, res) => {
    res.status(404).send({ message: "API endpoint not found." });
});

// Serve a simple message for the root path
app.get('/', (req, res) => {
  res.send('LocalDrive Backend is running. Connect via API endpoints.');
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
  console.log(`User files will be stored in: ${require('./config/storage.config').userFilesBasePath}`);
  console.log(`Database file is at: ${require('./config/db.config').SQLITE_DB_PATH}`);
  console.log(`Connect to APIs at http://localhost:${PORT}/api`);
});
