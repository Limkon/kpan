const express = require('express');
const router = express.Router();

const authRoutes = require('./auth.routes');
const fileRoutes = require('./file.routes');
// const adminRoutes = require('./admin.routes'); // Future: for admin specific tasks

router.use('/auth', authRoutes);
router.use('/files', fileRoutes);
// router.use('/admin', adminRoutes);

module.exports = router;
