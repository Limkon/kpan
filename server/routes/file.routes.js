const express = require('express');
const router = express.Router();
const fileController = require('../controllers/file.controller');
const { verifyToken } = require('../middleware/auth.middleware');
const upload = require('../middleware/upload.middleware'); // Multer instance

// All file routes are protected
router.use(verifyToken);

router.get('/list', fileController.listDirectory);
// 'upload.array('files', 10)' allows up to 10 files with field name 'files'
router.post('/upload', upload.array('files', 10), fileController.uploadFile);
router.get('/download', fileController.downloadFile);
router.post('/folder', fileController.createFolder);
router.delete('/item', fileController.deleteItem); // For files or folders
router.put('/rename', fileController.renameItem); // Placeholder

// TODO: Add routes for sharing, text editing

module.exports = router;
