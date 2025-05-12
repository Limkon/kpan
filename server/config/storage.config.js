require('dotenv').config();
const path = require('path');

const userFilesBasePath = process.env.USER_FILES_BASE_PATH || path.join(__dirname, '..', 'uploads');

module.exports = {
  userFilesBasePath: path.resolve(userFilesBasePath), // Ensure it's an absolute path
};
