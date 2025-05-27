// server.js (SQLite 版本 - 使用 yazl)
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises; // fs.promises 用於異步文件操作
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const yazl = require('yazl'); // 引入 yazl
const crypto = require('crypto'); // For generating unique tokens

const app = express();
const port = process.env.PORT || 3000;

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];
const ALLOWED_VIDEO_EXTENSIONS = ['.mp4', '.webm', '.ogg', '.mov'];
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_very_strong_and_unique_secret_CHANGE_THIS_NOW';
const USER_QUOTA_MB = 90;
const USER_QUOTA_BYTES = USER_QUOTA_MB * 1024 * 1024;

// --- 目錄初始化 ---
[DATA_DIR, UPLOAD_DIR_BASE].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`已自動創建目錄: ${dir}`);
    }
});

// --- SQLite 資料庫設置 ---
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) { console.error('無法連接到 SQLite 資料庫:', err.message); throw err; }
    console.log('已成功連接到 SQLite 資料庫。');
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )`, (err) => {
            if (err) console.error('創建 users 表格失敗:', err.message);
            else {
                console.log("'users' 表格已準備就緒。");
                const initialAdminUsername = 'admin';
                const initialAdminPassword = 'admin';
                db.get("SELECT * FROM users WHERE username = ?", [initialAdminUsername], (err, adminUser) => {
                    if (err) {
                        console.error('检查初始管理员时出错:', err.message);
                        return;
                    }
                    if (!adminUser) {
                        const hashedPassword = bcrypt.hashSync(initialAdminPassword, 12);
                        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                            [initialAdminUsername, hashedPassword, 'admin'],
                            function (err) {
                                if (err) console.error('创建初始管理员失败:', err.message);
                                else {
                                    console.log(`初始管理员 '${initialAdminUsername}' 已创建。`);
                                    getUserUploadRoot(initialAdminUsername); // 確保管理員目錄存在
                                }
                            }
                        );
                    }
                });
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            shared_with_id INTEGER NOT NULL,
            file_path TEXT NOT NULL, 
            is_directory BOOLEAN NOT NULL DEFAULT 0,
            permissions TEXT NOT NULL DEFAULT 'read-only',
            shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE (owner_id, shared_with_id, file_path)
        )`, (err) => {
            if (err) console.error('創建 shared_files 表格失敗:', err.message);
            else console.log("'shared_files' 表格已準備就緒。");
        });

        // --- 新增: public_links 表格 ---
        db.run(`CREATE TABLE IF NOT EXISTS public_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            file_path TEXT NOT NULL, -- 相對於擁有者根目錄的路徑
            is_directory BOOLEAN NOT NULL DEFAULT 0,
            token TEXT UNIQUE NOT NULL, -- 用於公開鏈接的唯一令牌
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            -- expires_at DATETIME NULL, -- 可選：鏈接過期時間
            -- password_hash TEXT NULL, -- 可選：受密碼保護的鏈接
            allow_download BOOLEAN NOT NULL DEFAULT 1,
            -- allow_view BOOLEAN NOT NULL DEFAULT 1, -- 視文件類型而定，通常在路由中處理
            access_count INTEGER DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) console.error('創建 public_links 表格失敗:', err.message);
            else console.log("'public_links' 表格已準備就緒。");
        });
    });
});

// --- 中間件設置 ---
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files like CSS, client-side JS
app.use('/uploads', isAuthenticated, (req, res, next) => { // Protect raw uploads directory listing
    // This middleware specifically targets the /uploads route.
    // If you have express.static(UPLOAD_DIR_BASE) or similar, that might serve files if not protected.
    // The goal here is to prevent direct browsing of the /uploads directory itself if it's mapped.
    // Individual file access (download, view, stream) is handled by specific routes.
    console.log(`[Security] Attempt to access /uploads by ${req.session.user.username}. This route should ideally not serve a directory listing.`);
    // It's better to not have a route that directly serves UPLOAD_DIR_BASE.
    // If you must, ensure directory listing is disabled for it.
    // For now, just block general access to a route named /uploads if it's not a specific file request handled by other routes.
    return res.status(403).send('禁止直接訪問上傳目錄。');
});


app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax' // Or 'strict' for better security if applicable
    }
}));


// --- 輔助函數 ---
function generateUniqueToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

function getUserUploadRoot(username) {
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

function resolvePathForUser(usernameForPath, relativePath = '/') {
    if (typeof usernameForPath !== 'string' || usernameForPath.includes('..') || usernameForPath.includes('/') || usernameForPath.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(usernameForPath) || usernameForPath.length > 50) {
        console.error(`[SecurityResolve] 無效的目標用戶名嘗試: ${usernameForPath}`);
        throw new Error('無效的目標用戶名。');
    }
    const userRoot = getUserUploadRoot(usernameForPath);
    let cleanRelativePath = relativePath;
    if (typeof relativePath === 'string' && relativePath.includes('?')) {
        cleanRelativePath = relativePath.split('?')[0];
    }
    const normalizedRelativePath = path.posix.normalize(cleanRelativePath).replace(/^(\.\.([/\\]|$))+/, '');
    const requestedPath = path.join(userRoot, normalizedRelativePath);

    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        console.error(`[SecurityResolve] 試圖訪問無效路徑！用戶根目錄: ${userRoot}, 請求路徑: ${requestedPath}, 解析後: ${path.resolve(requestedPath)}`);
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

function getVideoMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
        case '.mp4': return 'video/mp4';
        case '.webm': return 'video/webm';
        case '.ogg': return 'video/ogg';
        case '.mov': return 'video/quicktime';
        default: return 'application/octet-stream'; // Should not happen if filtered by ALLOWED_VIDEO_EXTENSIONS
    }
}

async function getDirectorySizeRecursive(directoryPath) {
    let totalSize = 0;
    try {
        const entries = await fsp.readdir(directoryPath, { withFileTypes: true });
        for (const entry of entries) {
            const entryPath = path.join(directoryPath, entry.name);
            if (entry.isFile()) {
                try {
                    const stats = await fsp.stat(entryPath);
                    totalSize += stats.size;
                } catch (statErr) {
                    console.error(`[DirSize] 計算文件大小錯誤 ${entryPath}:`, statErr.message);
                }
            } else if (entry.isDirectory()) {
                if (entry.name === '.' || entry.name === '..') continue;
                totalSize += await getDirectorySizeRecursive(entryPath);
            }
        }
    } catch (err) {
        if (err.code === 'ENOENT') { return 0; }
        console.error(`[DirSize] 讀取目錄錯誤 ${directoryPath}:`, err.message);
    }
    return totalSize;
}


async function searchFilesRecursively(directoryToSearch, keyword, currentRelativePath = '/', userUploadRoot) {
    let foundItems = [];
    const lowerCaseKeyword = keyword.toLowerCase();
    try {
        if (!path.resolve(directoryToSearch).startsWith(path.resolve(userUploadRoot))) {
            console.warn(`[Security] 搜索尝试超出用户允许的目录: ${directoryToSearch}`);
            return [];
        }
        const entries = await fsp.readdir(directoryToSearch, { withFileTypes: true });
        for (const entry of entries) {
            const entryAbsolutePath = path.join(directoryToSearch, entry.name);
            const entryRelativePath = path.posix.join(currentRelativePath, entry.name);
            let stats;
            const fileExt = path.extname(entry.name).toLowerCase();

            if (entry.isFile()) {
                if (entry.name.toLowerCase().includes(lowerCaseKeyword)) {
                    try { stats = await fsp.stat(entryAbsolutePath); }
                    catch (statErr) {
                        console.error(`[Search Stat Error] for file ${entryAbsolutePath}:`, statErr.message);
                        stats = { size: null, mtime: null };
                    }
                    const isPlayableVideo = ALLOWED_VIDEO_EXTENSIONS.includes(fileExt);
                    foundItems.push({
                        name: entry.name, isDir: false, path: entryRelativePath,
                        encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(entryRelativePath),
                        size: stats.size, lastModified: stats.mtime, isPlayableVideo: isPlayableVideo,
                        videoType: isPlayableVideo ? getVideoMimeType(entry.name) : null
                    });
                }
            } else if (entry.isDirectory()) {
                if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
                if (entry.name.toLowerCase().includes(lowerCaseKeyword)) {
                    try { stats = await fsp.stat(entryAbsolutePath); }
                    catch (statErr) {
                        console.error(`[Search Stat Error] for directory ${entryAbsolutePath}:`, statErr.message);
                        stats = { size: null, mtime: null };
                    }
                    foundItems.push({
                        name: entry.name, isDir: true, path: entryRelativePath,
                        encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(entryRelativePath),
                        size: null, lastModified: stats.mtime, isPlayableVideo: false
                    });
                }
                const subDirectoryItems = await searchFilesRecursively(entryAbsolutePath, keyword, entryRelativePath, userUploadRoot);
                foundItems = foundItems.concat(subDirectoryItems);
            }
        }
    } catch (err) { console.error(`[Search] 讀取目錄 ${directoryToSearch} 時發生錯誤:`, err.message); }
    return foundItems;
}


async function getDirectoryTreeRecursive(directoryToScan, userUploadRoot, currentRelativePath = '/', pathsToExclude = []) {
    let tree = [];
    try {
        if (!path.resolve(directoryToScan).startsWith(path.resolve(userUploadRoot))) {
            console.warn(`[Security] 目录树扫描尝试超出用户允许的目录: ${directoryToScan}`);
            return [];
        }
        const entries = await fsp.readdir(directoryToScan, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
                const entryRelativePath = path.posix.join(currentRelativePath, entry.name);
                if (pathsToExclude.some(excludePath => entryRelativePath === excludePath || entryRelativePath.startsWith(excludePath + '/'))) continue;
                const children = await getDirectoryTreeRecursive(path.join(directoryToScan, entry.name), userUploadRoot, entryRelativePath, pathsToExclude);
                tree.push({ name: entry.name, path: entryRelativePath, children: children });
            }
        }
    } catch (err) { console.error(`[DirTree] 讀取目錄 ${directoryToScan} 時發生錯誤:`, err.message); }
    return tree.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
}

async function checkSharePermission(actingUserId, ownerUserId, relativeFilePath, isDirectory = false) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT id FROM shared_files 
                WHERE owner_id = ? AND shared_with_id = ? AND file_path = ? AND is_directory = ?`,
            [ownerUserId, actingUserId, relativeFilePath, isDirectory ? 1 : 0], (err, row) => {
                if (err) {
                    console.error("檢查分享權限錯誤:", err);
                    return reject(err);
                }
                resolve(!!row);
            });
    });
}


// --- Multer 設置 ---
const storage = multer.diskStorage({
    destination: async function (req, file, cb) {
        console.log(`[Multer Destination] Received file: ${file.originalname}, webkitRelativePath: ${file.webkitRelativePath}`);
        const actingUsername = req.session.user.username;
        let tempTargetUsername = actingUsername;

        if (req.session.user.role === 'admin' && req.body.targetUsername) {
            tempTargetUsername = req.body.targetUsername;
        }

        if (typeof tempTargetUsername !== 'string' || tempTargetUsername.includes('..') || tempTargetUsername.includes('/') || tempTargetUsername.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTargetUsername) || tempTargetUsername.length > 50) {
            console.error(`[Multer Security] 無效的目標用戶名嘗試: ${tempTargetUsername}`);
            const securityError = new Error('上傳操作因無效的目標用戶名被拒絕。');
            securityError.code = 'INVALID_TARGET_USERNAME_UPLOAD';
            return cb(securityError);
        }
        const targetUsername = tempTargetUsername;

        let userUploadRootForQuotaCheck;
        try {
            userUploadRootForQuotaCheck = getUserUploadRoot(targetUsername);
            const currentDirectorySize = await getDirectorySizeRecursive(userUploadRootForQuotaCheck);
            if (currentDirectorySize >= USER_QUOTA_BYTES) {
                console.warn(`[Multer Quota] 用戶 ${targetUsername} 超出配額。目錄大小: ${currentDirectorySize} 字節。配額: ${USER_QUOTA_BYTES} 字節。`);
                const quotaError = new Error(`上傳目錄空間已滿 (超過 ${USER_QUOTA_MB}MB)，請聯繫管理員。`);
                quotaError.code = 'USER_QUOTA_EXCEEDED';
                return cb(quotaError);
            }
        } catch (quotaCheckError) {
            console.error(`[Multer Quota] 檢查用戶 ${targetUsername} 配額時發生錯誤:`, quotaCheckError);
            const checkError = new Error('檢查存儲空間時發生錯誤，無法上傳。');
            checkError.code = 'QUOTA_CHECK_ERROR';
            return cb(checkError);
        }

        const baseUploadPath = req.body.currentPath || '/';
        console.log(`[Multer Destination] actingUsername: ${actingUsername}, targetUsername: ${targetUsername}, baseUploadPath: ${baseUploadPath}`);
        let finalDestinationPath = baseUploadPath;

        if (file.webkitRelativePath && typeof file.webkitRelativePath === 'string') {
            const relativeFolderPath = path.dirname(file.webkitRelativePath);
            console.log(`[Multer Destination] file.webkitRelativePath: ${file.webkitRelativePath}, parsed relativeFolderPath: ${relativeFolderPath}`);
            if (relativeFolderPath && relativeFolderPath !== '.') {
                finalDestinationPath = path.posix.join(baseUploadPath, relativeFolderPath);
            }
        }
        console.log(`[Multer Destination] Calculated finalDestinationPath: ${finalDestinationPath}`);

        try {
            const resolvedUploadDir = resolvePathForUser(targetUsername, finalDestinationPath);
            console.log(`[Multer Destination] Resolved upload directory: ${resolvedUploadDir}`);
            if (!fs.existsSync(resolvedUploadDir)) {
                await fsp.mkdir(resolvedUploadDir, { recursive: true });
                console.log(`[Multer Destination] Created directory: ${resolvedUploadDir}`);
            }
            cb(null, resolvedUploadDir);
        } catch (err) {
            console.error(`[Multer Destination ERROR] For target ${targetUsername} at path ${finalDestinationPath}:`, err);
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        const safeFilename = path.basename(file.originalname);
        console.log(`[Multer Filename] originalname: ${file.originalname}, safeFilename: ${safeFilename}`);
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            console.warn(`[Multer FileFilter] Invalid characters in filename: ${file.originalname}`);
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit per file
});

// --- 認證中間件 ---
function isAuthenticated(req, res, next) { if (req.session.user) return next(); res.redirect('/login'); }
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).render('error', {
        user: req.session.user, message: '禁止訪問：僅限管理員。',
        csrfToken: res.locals.csrfToken
    });
}

// --- 路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

app.get('/register', (req, res) => res.render('register', { error: null, csrfToken: res.locals.csrfToken }));
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。', csrfToken: res.locals.csrfToken });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。', csrfToken: res.locals.csrfToken });
    if (username.includes('/') || username.includes('..') || username.includes('\\') || username.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return res.render('register', { error: '用戶名包含無效字符、過長或格式不正確。', csrfToken: res.locals.csrfToken });
    }
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) { console.error("註冊時查詢用戶錯誤:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。', csrfToken: res.locals.csrfToken }); }
        if (row) return res.render('register', { error: '用戶名已存在。', csrfToken: res.locals.csrfToken });
        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) { console.error("註冊時查詢用戶總數錯誤:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。', csrfToken: res.locals.csrfToken }); }
            const hashedPassword = bcrypt.hashSync(password, 12);
            const userRole = 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) { console.error("註冊時插入用戶錯誤:", err); return res.render('register', { error: '註冊失敗，請稍後再試。', csrfToken: res.locals.csrfToken }); }
                getUserUploadRoot(username);
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message, csrfToken: res.locals.csrfToken }));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) { console.error("登錄時查詢用戶錯誤:", err); return res.render('login', { error: '登錄錯誤，請稍後再試。', csrfToken: res.locals.csrfToken }); }
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。', csrfToken: res.locals.csrfToken });
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error("登出時銷毀 session 錯誤:", err);
        res.redirect('/login');
    });
});

app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null, csrfToken: res.locals.csrfToken }));
app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;
    if (!currentPassword || !newPassword || !confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error', csrfToken: res.locals.csrfToken });
    if (newPassword !== confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error', csrfToken: res.locals.csrfToken });
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, userRow) => {
        if (err || !userRow || !bcrypt.compareSync(currentPassword, userRow.password)) {
            if (err) console.error("修改密碼時查詢用戶錯誤:", err);
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error', csrfToken: res.locals.csrfToken });
        }
        const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) { console.error("修改密碼時更新數據庫錯誤:", err); return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error', csrfToken: res.locals.csrfToken }); }
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success', csrfToken: res.locals.csrfToken });
        });
    });
});

app.get('/files', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    let relativeQueryPath = req.query.path || '/';
    if (typeof relativeQueryPath === 'string' && relativeQueryPath.includes('?')) {
        relativeQueryPath = relativeQueryPath.split('?')[0];
    }
    relativeQueryPath = path.posix.normalize(relativeQueryPath);
    if (!relativeQueryPath || relativeQueryPath === '.') relativeQueryPath = '/';

    const searchQuery = req.query.q ? req.query.q.trim() : null;
    const viewMode = req.query.viewMode || 'myfiles'; 

    let contextUsername = actingUser.username;
    let contextUserId = actingUser.id;
    let isAdminViewingOther = false;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUser = await new Promise((resolve, reject) => {
            db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                if (err) reject(err);
                else if (row && /^[a-zA-Z0-9_.-]+$/.test(req.query.targetUsername) && !req.query.targetUsername.includes('..') && !req.query.targetUsername.includes('/') && !req.query.targetUsername.includes('\\')) {
                    resolve(row);
                } else {
                    resolve(null);
                }
            });
        }).catch(err => { console.error("檢查目標用戶是否存在時出錯:", err); return null; });

        if (targetUser) {
            contextUsername = targetUser.username;
            contextUserId = targetUser.id;
            isAdminViewingOther = true;
        } else {
            return res.redirect(`/files?message=目標用戶 ${encodeURIComponent(req.query.targetUsername || '')} 不存在或格式不正確。&messageType=error`);
        }
    }

    try {
        let items = [];
        let pageTitle = `${contextUsername} 的文件`;
        let isSearchResultView = false;
        let currentDisplayPath = relativeQueryPath;

        if (searchQuery && viewMode === 'myfiles') {
            isSearchResultView = true;
            const userUploadRootPath = getUserUploadRoot(contextUsername);
            items = await searchFilesRecursively(userUploadRootPath, searchQuery, '/', userUploadRootPath);
            currentDisplayPath = '/';
            pageTitle = `有關 "${searchQuery}" 的搜尋結果 (在 ${contextUsername} 的文件中)`;
        } else if (viewMode === 'myfiles') {
            const currentFullPath = resolvePathForUser(contextUsername, relativeQueryPath);
            const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
            items = await Promise.all(dirEntries.map(async entry => {
                const itemPath = path.posix.join(relativeQueryPath, entry.name);
                const fullEntryPath = path.join(currentFullPath, entry.name);
                const fileExt = path.extname(entry.name).toLowerCase();
                let stats;
                try { stats = await fsp.stat(fullEntryPath); }
                catch (statErr) {
                    console.error(`[Stat Error] for ${fullEntryPath}:`, statErr.message);
                    return {
                        name: entry.name, isDir: entry.isDirectory(), path: itemPath,
                        encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(itemPath),
                        size: null, lastModified: null,
                        isPlayableVideo: entry.isFile() && ALLOWED_VIDEO_EXTENSIONS.includes(fileExt),
                        videoType: entry.isFile() && ALLOWED_VIDEO_EXTENSIONS.includes(fileExt) ? getVideoMimeType(entry.name) : null
                    };
                }
                const isPlayableVideo = entry.isFile() && ALLOWED_VIDEO_EXTENSIONS.includes(fileExt);
                return {
                    name: entry.name, isDir: entry.isDirectory(), path: itemPath,
                    encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(itemPath),
                    size: entry.isFile() ? stats.size : null, lastModified: stats.mtime,
                    isPlayableVideo: isPlayableVideo,
                    videoType: isPlayableVideo ? getVideoMimeType(entry.name) : null
                };
            }));
            pageTitle = `${contextUsername} 的文件: ${relativeQueryPath}`;
        } else if (viewMode === 'sharedWithMe') {
            const userIdForSharedWithMe = isAdminViewingOther ? contextUserId : actingUser.id;
            const userForSharedWithMe = isAdminViewingOther ? contextUsername : actingUser.username;

            pageTitle = `與 ${userForSharedWithMe} 分享的項目`;
            currentDisplayPath = '/';
            const sharedEntries = await new Promise((resolve, reject) => {
                db.all(`SELECT sf.id as share_id, sf.file_path, sf.is_directory, sf.permissions, sf.shared_at, u_owner.username as owner_username
                        FROM shared_files sf
                        JOIN users u_owner ON sf.owner_id = u_owner.id
                        WHERE sf.shared_with_id = ?
                        ORDER BY sf.shared_at DESC`,
                    [userIdForSharedWithMe], (err, rows) => {
                        if (err) reject(err); else resolve(rows);
                    });
            });
            items = await Promise.all(sharedEntries.map(async entry => {
                const ownerUploadRoot = getUserUploadRoot(entry.owner_username);
                const fullSharedItemPath = path.join(ownerUploadRoot, entry.file_path);
                let stats;
                try { stats = await fsp.stat(fullSharedItemPath); }
                catch (e) { stats = { size: null, mtime: null }; console.warn(`Stat failed for shared item ${entry.file_path} from ${entry.owner_username}`); }

                const fileExt = path.extname(entry.file_path).toLowerCase();
                const isPlayableVideo = !entry.is_directory && ALLOWED_VIDEO_EXTENSIONS.includes(fileExt);

                return {
                    share_id: entry.share_id,
                    name: path.basename(entry.file_path),
                    isDir: !!entry.is_directory,
                    path: entry.file_path,
                    encodedName: encodeURIComponent(path.basename(entry.file_path)),
                    encodedPath: encodeURIComponent(entry.file_path),
                    size: !entry.is_directory ? stats.size : null,
                    lastModified: stats.mtime,
                    sharedAt: entry.shared_at,
                    ownerUsername: entry.owner_username,
                    permissions: entry.permissions,
                    isPlayableVideo: isPlayableVideo,
                    videoType: isPlayableVideo ? getVideoMimeType(entry.file_path) : null,
                };
            }));
        } else if (viewMode === 'userShares') {
            pageTitle = `${contextUsername} 分享的項目`;
            currentDisplayPath = '/';
            const userSharedEntries = await new Promise((resolve, reject) => {
                db.all(`SELECT sf.id as share_id, sf.file_path, sf.is_directory, sf.permissions, sf.shared_at, u_shared_with.username as shared_with_username
                        FROM shared_files sf
                        JOIN users u_shared_with ON sf.shared_with_id = u_shared_with.id
                        WHERE sf.owner_id = ?
                        ORDER BY sf.shared_at DESC`,
                    [contextUserId], (err, rows) => {
                        if (err) reject(err); else resolve(rows);
                    });
            });
            items = userSharedEntries.map(entry => ({
                share_id: entry.share_id,
                name: path.basename(entry.file_path),
                isDir: !!entry.is_directory,
                path: entry.file_path,
                encodedName: encodeURIComponent(path.basename(entry.file_path)),
                sharedWithUsername: entry.shared_with_username,
                sharedAt: entry.shared_at,
                permissions: entry.permissions,
            }));
        } else if (viewMode === 'publicLinks') { // New view mode for listing public links
            pageTitle = `${contextUsername} 的公開鏈接`;
            currentDisplayPath = '/'; // Public links are listed flat
            const publicLinkEntries = await new Promise((resolve, reject) => {
                db.all(`SELECT id, file_path, is_directory, token, created_at 
                        FROM public_links
                        WHERE owner_id = ?
                        ORDER BY created_at DESC`,
                    [contextUserId], (err, rows) => {
                        if (err) reject(err); else resolve(rows);
                    });
            });
            items = publicLinkEntries.map(entry => ({
                public_link_id: entry.id,
                name: path.basename(entry.file_path),
                isDir: !!entry.is_directory,
                path: entry.file_path, // Original path
                token: entry.token,
                createdAt: entry.created_at,
                publicUrl: `${req.protocol}://${req.get('host')}/public/s/${entry.token}`
            }));
        }


        if (viewMode === 'myfiles' && !searchQuery) {
            items.sort((a, b) => {
                if (a.isDir && !b.isDir) return -1;
                if (!a.isDir && b.isDir) return 1;
                return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
            });
        }


        res.render('files', {
            user: actingUser,
            viewContextUser: { username: contextUsername, id: contextUserId },
            isAdminViewingOther: isAdminViewingOther,
            items: items,
            currentPath: currentDisplayPath,
            actualRelativePath: relativeQueryPath,
            searchQuery: searchQuery,
            isSearchResult: isSearchResultView,
            pageTitle: pageTitle,
            viewMode: viewMode,
            ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS,
            ALLOWED_VIDEO_EXTENSIONS: ALLOWED_VIDEO_EXTENSIONS,
            csrfToken: res.locals.csrfToken,
            message: req.query.message, messageType: req.query.messageType,
            baseUrl: `${req.protocol}://${req.get('host')}` // For constructing full URLs
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${contextUsername} 的文件夾 (模式: ${viewMode}, 路徑: ${relativeQueryPath}, 搜索: ${searchQuery || '無'}) 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT' && !searchQuery) friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑') || err.message.includes('無效的目標用戶名')) friendlyMessage = '無權訪問指定路徑或用戶無效。';

        const baseRedirect = '/files';
        let redirectParams = [];
        if (isAdminViewingOther) redirectParams.push(`targetUsername=${encodeURIComponent(contextUsername)}`);
        if (searchQuery) redirectParams.push(`q=${encodeURIComponent(searchQuery)}`);
        else if (relativeQueryPath !== '/' && viewMode === 'myfiles') {
            const parentPath = path.posix.dirname(relativeQueryPath);
            if (parentPath !== '.' && parentPath !== '/') redirectParams.push(`path=${encodeURIComponent(parentPath)}`);
        }
        redirectParams.push(`viewMode=${viewMode}`);
        redirectParams.push(`message=${encodeURIComponent(friendlyMessage)}`, `messageType=error`);
        res.redirect(`${baseRedirect}?${redirectParams.join('&')}`);
    }
});

app.post('/upload', isAuthenticated, (req, res, next) => {
    console.log(`[POST /upload] Request received. User: ${req.session.user.username}, Body keys:`, Object.keys(req.body));
    upload.array('userFiles', 100)(req, res, (err) => {
        if (err) {
            console.error(`[POST /upload] Multer 上傳錯誤 for user ${req.session.user.username}:`, err.message, err.code ? `(Code: ${err.code})` : '', err.stack);
            const currentPath = req.body.currentPath || '/';
            const redirectParams = new URLSearchParams();
            if (currentPath !== '/') redirectParams.set('path', currentPath);

            if (req.session.user.role === 'admin' && req.body.targetUsername) {
                redirectParams.set('targetUsername', req.body.targetUsername);
            }

            let userMessage = err.message;
            if (err.code === 'USER_QUOTA_EXCEEDED') userMessage = `上傳失敗：您的存儲空間已滿 (超過 ${USER_QUOTA_MB}MB)。請清理空間或聯繫管理員。`;
            else if (err.code === 'LIMIT_FILE_SIZE') userMessage = '上傳失敗：文件大小超過單個文件100MB的限制。';
            else if (err.code === 'INVALID_TARGET_USERNAME_UPLOAD') userMessage = '上傳失敗：目標用戶信息無效。';
            else if (err.message.includes('文件名包含無效字符')) userMessage = '上傳失敗：文件名包含無效字符。';
            else if (err.message.includes('上傳目標路徑處理錯誤')) userMessage = '上傳失敗：無法處理上傳目標路徑。';
            else if (err.code === 'QUOTA_CHECK_ERROR') userMessage = '上傳失敗：檢查存儲空間時發生內部錯誤，請稍後再試。';

            redirectParams.set('message', encodeURIComponent(userMessage));
            redirectParams.set('messageType', 'error');
            return res.redirect(`/files?${redirectParams.toString()}`);
        }

        console.log(`[POST /upload] Multer processed ${req.files ? req.files.length : 0} files for user ${req.session.user.username}.`);
        const currentPath = req.body.currentPath || '/';
        const redirectParams = new URLSearchParams();
        if (currentPath !== '/') redirectParams.set('path', currentPath);

        if (req.session.user.role === 'admin' && req.body.targetUsername) {
            redirectParams.set('targetUsername', req.body.targetUsername);
        }

        if (!req.files || req.files.length === 0) {
            redirectParams.set('message', encodeURIComponent('沒有選擇文件或文件夾。'));
            redirectParams.set('messageType', 'warning');
            return res.redirect(`/files?${redirectParams.toString()}`);
        }

        redirectParams.set('message', encodeURIComponent('項目上傳成功。'));
        redirectParams.set('messageType', 'success');
        res.redirect(`/files?${redirectParams.toString()}`);
    });
});

app.post('/create-folder', isAuthenticated, async (req, res) => {
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    let targetUsername = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=無效的目標用戶名格式。&messageType=error`);
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (!targetUserExists) {
            return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=目標用戶不存在。&messageType=error`);
        }
        targetUsername = tempTarget;
    }

    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);


    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\') || folderName.length > 100 || !/^[^\/\\]+$/.test(folderName.trim()) || folderName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的文件夾名稱 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    const finalFolderName = folderName.trim();
    try {
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, finalFolderName));
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${finalFolderName}" 已存在。&messageType=error`);
        }
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${finalFolderName}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文件夾錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=創建文件夾失敗: ${err.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : '內部錯誤。'}&messageType=error`);
    }
});

app.post('/rename', isAuthenticated, async (req, res) => {
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    let targetUsername = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=無效的目標用戶名格式。&messageType=error`);
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (!targetUserExists) {
            return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=目標用戶不存在。&messageType=error`);
        }
        targetUsername = tempTarget;
    }

    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255 || !/^[^\/\\]+$/.test(newName.trim()) || newName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    const finalNewName = newName.trim();
    if (!relativeOldPath) { return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`); }

    try {
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        const parentDirOfOld = path.posix.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.posix.join(parentDirOfOld, finalNewName));

        if (!fs.existsSync(fullOldPath)) { return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`); }
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) {
            return res.redirect(`/files?${redirectPathQuery}&message=名稱 "${finalNewName}" 已存在。&messageType=error`);
        }
        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗: ${err.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : '內部錯誤。'}&messageType=error`);
    }
});

app.get('/download', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const ownerUsernameQuery = req.query.ownerUsername;

    let fileOwnerUsername = actingUser.username;
    let fileOwnerId = actingUser.id;

    if (!relativeFilePath) {
        return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。', csrfToken: res.locals.csrfToken });
    }
    
    try {
        if (ownerUsernameQuery && ownerUsernameQuery !== actingUser.username) {
            const owner = await new Promise((resolve, reject) => {
                db.get("SELECT id, username FROM users WHERE username = ?", [ownerUsernameQuery], (err, row) => {
                    if (err) reject(err); else resolve(row);
                });
            });

            if (!owner) {
                return res.status(404).render('error', { user: actingUser, message: '文件擁有者不存在。', csrfToken: res.locals.csrfToken });
            }
            fileOwnerUsername = owner.username;
            fileOwnerId = owner.id;

            const fullPathToCheck = resolvePathForUser(fileOwnerUsername, relativeFilePath);
            const statsForType = await fsp.stat(fullPathToCheck);
            const hasPermission = await checkSharePermission(actingUser.id, fileOwnerId, relativeFilePath, statsForType.isDirectory());
            if (!hasPermission) {
                return res.status(403).render('error', { user: actingUser, message: '您沒有權限下載此分享文件。', csrfToken: res.locals.csrfToken });
            }
        } else if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
            const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
            if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
            fileOwnerUsername = targetUser.username;
        }


        const fullFilePath = resolvePathForUser(fileOwnerUsername, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (stats.isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) {
                    console.error(`[${actingUser.username}] 為 ${fileOwnerUsername} 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) { res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。', csrfToken: res.locals.csrfToken }); }
                }
            });
        } else {
            res.status(400).render('error', { user: actingUser, message: '請求的資源不是一個有效文件 (不能下載文件夾，請使用打包下載)。', csrfToken: res.locals.csrfToken });
        }
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${fileOwnerUsername} 準備下載 ${relativeFilePath} 時出錯:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken });
        if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) return res.status(403).render('error', { user: actingUser, message: '禁止訪問。', csrfToken: res.locals.csrfToken });
        res.status(500).render('error', { user: actingUser, message: '處理下載請求時出錯。', csrfToken: res.locals.csrfToken });
    }
});


async function addDirectoryToZip(zipfile, dirPathOnServer, pathInZipBase, userRootForSecurityCheck) {
    if (!path.resolve(dirPathOnServer).startsWith(path.resolve(userRootForSecurityCheck))) {
        console.warn(`[Zip Security] 嘗試添加用戶目錄 (${userRootForSecurityCheck}) 之外的路徑到壓縮包: ${dirPathOnServer}`);
        zipfile.addBuffer(Buffer.from(`錯誤：嘗試打包一個不被允許的路徑: ${pathInZipBase}\n`), `打包安全警告/${path.basename(pathInZipBase)}-路徑錯誤.txt`);
        return;
    }

    const entries = await fsp.readdir(dirPathOnServer, { withFileTypes: true });
    for (const entry of entries) {
        const entryPathOnServer = path.join(dirPathOnServer, entry.name);
        let entryPathInZip = path.posix.join(pathInZipBase, entry.name);
        if (pathInZipBase === '/' && entryPathInZip.startsWith('//')) entryPathInZip = entryPathInZip.substring(1);
        else if (entryPathInZip.startsWith('/')) entryPathInZip = entryPathInZip.substring(1);

        if (entry.isFile()) {
            zipfile.addFile(entryPathOnServer, entryPathInZip);
        } else if (entry.isDirectory()) {
            await addDirectoryToZip(zipfile, entryPathOnServer, entryPathInZip, userRootForSecurityCheck);
        }
    }
}


app.post('/download-archive', isAuthenticated, async (req, res) => {
    console.log("[/download-archive] Received request.");
    const actingUser = req.session.user;
    const itemsToArchiveString = req.body.items;
    let itemsToArchive;

    if (itemsToArchiveString && typeof itemsToArchiveString === 'string') {
        try { itemsToArchive = JSON.parse(itemsToArchiveString); }
        catch (e) { return res.redirect((req.headers.referer || '/files') + '?message=打包下載失敗：項目列表格式錯誤。&messageType=error'); }
    } else if (req.body.items && Array.isArray(req.body.items)) {
        itemsToArchive = req.body.items;
    } else {
        return res.redirect((req.headers.referer || '/files') + '?message=打包下載失敗：未提供項目列表。&messageType=error');
    }

    let archiveOwnerUsername = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
         if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.redirect((req.headers.referer || '/files') + '?message=打包下載失敗：無效的目標用戶名格式。&messageType=error');
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (targetUserExists) {
            archiveOwnerUsername = tempTarget;
        } else {
            return res.redirect((req.headers.referer || '/files') + '?message=打包下載失敗：目標用戶不存在。&messageType=error');
        }
    }
    
    if (!itemsToArchive || !Array.isArray(itemsToArchive) || itemsToArchive.length === 0) {
        let redirectUrl = req.headers.referer || '/files';
        const errorParams = new URLSearchParams({ message: '未選擇要下載的項目。', messageType: 'error' }).toString();
        redirectUrl = redirectUrl.includes('?') ? `${redirectUrl.split('?')[0]}?${errorParams}` : `${redirectUrl}?${errorParams}`;
        return res.redirect(redirectUrl);
    }

    const archiveName = `archive-${archiveOwnerUsername}-${Date.now()}.zip`;
    const zipfile = new yazl.ZipFile();

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(archiveName)}"`);
    res.setHeader('Content-Type', 'application/zip');
    zipfile.outputStream.pipe(res);
    zipfile.outputStream.on('error', (err) => {
        console.error('Yazl outputStream error:', err);
        if (!res.headersSent) res.status(500).send('創建壓縮文件時發生錯誤。');
        else if (!res.writableEnded) res.end();
    });
    res.on('error', (err) => console.error('Response stream error during zip download:', err));
    res.on('close', function () { console.log(`響應流已關閉，壓縮文件: ${archiveName}`); });

    try {
        for (const item of itemsToArchive) {
            if (!item || typeof item.path !== 'string' || typeof item.name !== 'string') {
                console.warn(`[/download-archive] Invalid item structure:`, item);
                zipfile.addBuffer(Buffer.from(`錯誤：一個無效的項目結構被傳遞。\nItem: ${JSON.stringify(item)}\n`), "打包錯誤日誌.txt");
                continue;
            }

            let currentItemOwnerUsername = item.ownerUsername || archiveOwnerUsername;
            let currentItemOwnerId;
            const ownerUserObj = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [currentItemOwnerUsername], (err, row) => resolve(row)));
            if (!ownerUserObj) {
                 zipfile.addBuffer(Buffer.from(`錯誤：項目 ${item.name} 的擁有者 ${currentItemOwnerUsername} 未找到。\n`), `打包錯誤日誌/${item.name}-用戶未找到.txt`);
                 continue;
            }
            currentItemOwnerId = ownerUserObj.id;

            if (item.ownerUsername && item.ownerUsername !== actingUser.username) {
                 const fullPathToCheck = resolvePathForUser(item.ownerUsername, item.path);
                 const statsForType = await fsp.stat(fullPathToCheck);
                 const hasPermission = await checkSharePermission(actingUser.id, currentItemOwnerId, item.path, statsForType.isDirectory());
                 if (!hasPermission) {
                     zipfile.addBuffer(Buffer.from(`錯誤：您沒有權限打包分享的項目 ${item.name} (來自 ${item.ownerUsername})。\n`), `打包錯誤日誌/${item.name}-無權限.txt`);
                     continue;
                 }
            }

            const fullPathOnServer = resolvePathForUser(currentItemOwnerUsername, item.path);
            const userUploadRootForZip = getUserUploadRoot(currentItemOwnerUsername);

            let correctedPathInZip = item.path;
            if (correctedPathInZip.startsWith('/')) correctedPathInZip = correctedPathInZip.substring(1);

            if (!fs.existsSync(fullPathOnServer)) {
                console.warn(`打包下載：項目 ${item.path} (伺服器路徑: ${fullPathOnServer}) 不存在，已跳過。`);
                zipfile.addBuffer(Buffer.from(`錯誤：項目 ${item.name} (位於 ${item.path}) 未找到或無法訪問。\n`), `打包錯誤日誌/${item.name}-未找到.txt`);
                continue;
            }
            const stat = await fsp.stat(fullPathOnServer);
            if (stat.isFile()) {
                zipfile.addFile(fullPathOnServer, correctedPathInZip || item.name);
            } else if (stat.isDirectory()) {
                await addDirectoryToZip(zipfile, fullPathOnServer, correctedPathInZip || item.name, userUploadRootForZip);
            }
        }
        zipfile.end();
        console.log(`[/download-archive] 所有項目已添加到 yazl，正在完成壓縮: ${archiveName}`);
    } catch (error) {
        console.error('添加文件到壓縮包時出錯:', error);
        try { zipfile.addBuffer(Buffer.from(`內部錯誤：處理某些文件時發生問題。\n${error.message}\n`), "內部伺服器錯誤日誌.txt"); }
        catch (zipError) { console.error("向 zip 添加錯誤日誌時也發生錯誤:", zipError); }
        if (!res.headersSent) res.status(500).send(`創建壓縮文件時發生內部錯誤: ${error.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : error.message}`);
        else if (!res.writableEnded) {
            console.log("錯誤發生，但響應已開始，嘗試結束流。");
            try { zipfile.outputStream.unpipe(res); } catch(e){}
            res.end();
        }
        if (zipfile && typeof zipfile.end === 'function' && !zipfile.ended) zipfile.end();
    }
});


app.get('/delete', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    let targetUsername = actingUser.username;

    if (actingUser.role === 'admin' && req.query.targetUsername) {
        const tempTarget = req.query.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.redirect(`/files?message=無效的目標用戶名格式。&messageType=error`);
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (!targetUserExists) return res.redirect(`/files?message=目標用戶不存在。&messageType=error`);
        targetUsername = tempTarget;
    }

    if (!relativeItemPath) return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);

    const parentRelativePath = path.posix.dirname(relativeItemPath);
    let redirectQuery = (parentRelativePath === '.' || parentRelativePath === '/' || parentRelativePath === '') ? '' : `path=${encodeURIComponent(parentRelativePath)}`;
    const adminQuery = (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (adminQuery) redirectQuery = redirectQuery ? `${redirectQuery}${adminQuery}` : (adminQuery.startsWith('&') ? adminQuery.substring(1) : adminQuery);

    try {
        const fullItemPath = resolvePathForUser(targetUsername, relativeItemPath);
        if (!fs.existsSync(fullItemPath)) return res.redirect(`/files?${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);

        if (isDir) { await fsp.rm(fullItemPath, { recursive: true, force: true }); }
        else { await fsp.unlink(fullItemPath); }

        const ownerUser = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [targetUsername], (err, row) => resolve(row)));
        if (ownerUser) {
            db.run("DELETE FROM shared_files WHERE owner_id = ? AND file_path = ?", [ownerUser.id, relativeItemPath], (delErr) => {
                if (delErr) console.error(`刪除 ${targetUsername} 的 ${relativeItemPath} 的分享記錄時出錯:`, delErr);
                else console.log(`已刪除 ${targetUsername} 的 ${relativeItemPath} 的相關分享記錄。`);
            });
            // Also delete public links for this item
            db.run("DELETE FROM public_links WHERE owner_id = ? AND file_path = ?", [ownerUser.id, relativeItemPath], (delErr) => {
                if (delErr) console.error(`刪除 ${targetUsername} 的 ${relativeItemPath} 的公開鏈接記錄時出錯:`, delErr);
                else console.log(`已刪除 ${targetUsername} 的 ${relativeItemPath} 的相關公開鏈接記錄。`);
            });
        }

        res.redirect(`/files?${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files?${redirectQuery}&message=刪除項目失敗: ${err.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : '內部錯誤。'}&messageType=error`);
    }
});

app.get('/view', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const ownerUsernameQuery = req.query.ownerUsername;

    let fileOwnerUsername = actingUser.username;
    let fileOwnerId = actingUser.id;
    let viewTargetUsernameForTemplate = null;

    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定查看文件路徑。', csrfToken: res.locals.csrfToken });

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('error', { user: actingUser, message: `不支援預覽此文件類型 (${fileExt})。您可以嘗試下載它。`, csrfToken: res.locals.csrfToken });
    }

    try {
        if (ownerUsernameQuery && ownerUsernameQuery !== actingUser.username) {
            const owner = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [ownerUsernameQuery], (err, row) => resolve(row)));
            if (!owner) return res.status(404).render('error', { user: actingUser, message: '文件擁有者不存在。', csrfToken: res.locals.csrfToken });
            
            fileOwnerUsername = owner.username;
            fileOwnerId = owner.id;
            viewTargetUsernameForTemplate = owner.username;

            const fullPathToCheck = resolvePathForUser(fileOwnerUsername, relativeFilePath);
            const statsForType = await fsp.stat(fullPathToCheck);
            const hasPermission = await checkSharePermission(actingUser.id, fileOwnerId, relativeFilePath, statsForType.isDirectory());
            if (!hasPermission) {
                return res.status(403).render('error', { user: actingUser, message: '您沒有權限查看此分享文件。', csrfToken: res.locals.csrfToken });
            }
        } else if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
            const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
            if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
            fileOwnerUsername = targetUser.username;
            if (fileOwnerUsername !== actingUser.username) viewTargetUsernameForTemplate = fileOwnerUsername;
        }

        const fullFilePath = resolvePathForUser(fileOwnerUsername, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (!stats.isFile()) return res.status(400).render('error', { user: actingUser, message: '請求的路徑不是一個文件。', csrfToken: res.locals.csrfToken });
        
        const content = await fsp.readFile(fullFilePath, 'utf8');
        res.render('view-file', {
            user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate,
            filename: filename, content: content, currentPath: relativeFilePath,
            fileOwnerIfShared: (ownerUsernameQuery && ownerUsernameQuery !== actingUser.username) ? ownerUsernameQuery : null,
            fileExtension: fileExt, ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS,
            csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${fileOwnerUsername} 讀取文件 ${relativeFilePath} 查看錯誤:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken });
        if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) return res.status(403).render('error', { user: actingUser, message: '禁止訪問。', csrfToken: res.locals.csrfToken });
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。', csrfToken: res.locals.csrfToken });
    }
});

app.get('/edit', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const ownerUsernameQuery = req.query.ownerUsername;

    let fileOwnerUsername = actingUser.username;
    let viewTargetUsernameForTemplate = null;

    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。', csrfToken: res.locals.csrfToken });

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。`, csrfToken: res.locals.csrfToken });

    try {
        if (ownerUsernameQuery && ownerUsernameQuery !== actingUser.username) {
             return res.status(403).render('error', { user: actingUser, message: '不允許直接編輯分享的文件。請先下載。', csrfToken: res.locals.csrfToken });
        } else if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
            const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
            if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
            fileOwnerUsername = targetUser.username;
            if (fileOwnerUsername !== actingUser.username) viewTargetUsernameForTemplate = fileOwnerUsername;
        }

        const fullFilePath = resolvePathForUser(fileOwnerUsername, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (!stats.isFile()) return res.status(400).render('error', { user: actingUser, message: '請求的路徑不是一個文件。', csrfToken: res.locals.csrfToken });
        
        const content = await fsp.readFile(fullFilePath, 'utf8');
        res.render('edit-file', {
            user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate,
            filename: filename, content: content, currentPath: relativeFilePath,
            fileOwnerIfShared: null,
            csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${fileOwnerUsername} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken });
        if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) return res.status(403).render('error', { user: actingUser, message: '禁止訪問。', csrfToken: res.locals.csrfToken });
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。', csrfToken: res.locals.csrfToken });
    }
});

app.post('/save/:encodedPath(*)', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath);
    const { fileContent } = req.body;
    let targetUsernameForSave = actingUser.username;
    let viewTargetUsernameForTemplate = null;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.status(400).render('edit-file', { user: actingUser, viewTargetUsername: tempTarget, filename: path.basename(relativeFilePath), content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken, message: '保存失敗：無效的目標用戶名格式。', messageType: 'error' });
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (!targetUserExists) return res.status(404).render('edit-file', { user: actingUser, viewTargetUsername: tempTarget, filename: path.basename(relativeFilePath), content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken, message: '保存失敗：目標用戶不存在。', messageType: 'error' });
        targetUsernameForSave = tempTarget;
        if (targetUsernameForSave !== actingUser.username) viewTargetUsernameForTemplate = targetUsernameForSave;
    }

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('edit-file', { user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate, filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken, message: `不支援保存此文件類型 (${fileExt})。`, messageType: 'error' });
    }

    try {
        const fullFilePath = resolvePathForUser(targetUsernameForSave, relativeFilePath);
        const parentDirOfFile = path.dirname(fullFilePath);
        if (!fs.existsSync(parentDirOfFile)) {
            console.error(`[${actingUser.username}] 尝试保存文件到不存在的父目录: ${parentDirOfFile}`);
            return res.status(400).render('edit-file', { user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate, filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken, message: '保存路徑無效 (父目錄不存在)。', messageType: 'error' });
        }
        await fsp.writeFile(fullFilePath, fileContent, 'utf8');

        const parentDirForRedirect = path.posix.dirname(relativeFilePath) || '/';
        let adminQuery = '';
        if (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) {
            adminQuery = `&targetUsername=${encodeURIComponent(req.body.targetUsername)}`;
        }
        res.redirect(`/files?path=${encodeURIComponent(parentDirForRedirect)}${adminQuery}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsernameForSave} 保存文件 ${relativeFilePath} 錯誤:`, err);
        let errorMessage = '保存文件失敗。';
        if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) errorMessage = '保存失敗：權限不足或路徑無效。';
        res.status(500).render('edit-file', { user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate, filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken, message: errorMessage, messageType: 'error' });
    }
});

app.post('/create-text-file', isAuthenticated, async (req, res) => {
    const { newFileName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    let targetUsername = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=無效的目標用戶名格式。&messageType=error`);
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (!targetUserExists) return res.redirect(`/files?${relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : ''}&message=目標用戶不存在。&messageType=error`);
        targetUsername = tempTarget;
    }

    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQueryForRedirect = (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQueryForRedirect) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQueryForRedirect}` : adminQueryForRedirect.substring(1);

    if (!newFileName || newFileName.includes('/') || newFileName.includes('..') || newFileName.includes('\\') || newFileName.length > 100 || !/^[^\/\\]+$/.test(newFileName.trim()) || newFileName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的文件名 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    let finalFileName = newFileName.trim();
    const fileExt = path.extname(finalFileName).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) finalFileName += '.txt';

    try {
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, finalFileName));
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?${redirectPathQuery}&message=文件 "${finalFileName}" 已存在。&messageType=error`);
        }
        await fsp.writeFile(fullPathToCreate, '', 'utf8');

        const editPath = path.posix.join(relativeCurrentPath, finalFileName);
        let editRedirectQuery = `path=${encodeURIComponent(editPath)}`;
        if (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) {
            editRedirectQuery += `&targetUsername=${encodeURIComponent(req.body.targetUsername)}`;
        }
        res.redirect(`/edit?${editRedirectQuery}&message=文件 "${finalFileName}" 創建成功，開始編輯。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文本文件錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=創建文本文件失敗: ${err.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : '內部錯誤。'}&messageType=error`);
    }
});

app.get('/api/directories', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    let targetUsernameForTree = actingUser.username;

    if (actingUser.role === 'admin' && req.query.targetUsername) {
        const tempTarget = req.query.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.status(400).json({ success: false, message: '無效的目標用戶名格式。' });
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (targetUserExists) targetUsernameForTree = tempTarget;
        else return res.status(404).json({ success: false, message: '目標用戶不存在。' });
    }

    const userUploadRoot = getUserUploadRoot(targetUsernameForTree);
    let pathsToExclude = [];
    if (req.query.excludePaths && typeof req.query.excludePaths === 'string') {
        pathsToExclude = req.query.excludePaths.split(',').map(p => path.posix.normalize(p.trim())).filter(p => p && p !== '/');
    }

    try {
        const directoryTree = await getDirectoryTreeRecursive(userUploadRoot, userUploadRoot, '/', pathsToExclude);
        res.json(directoryTree);
    } catch (error) {
        console.error(`[API DirTree] 獲取用戶 ${targetUsernameForTree} 的目錄樹時出錯:`, error);
        res.status(500).json({ success: false, message: '無法獲取目錄列表。' });
    }
});

app.post('/move-items', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { sourcePaths, destinationPath } = req.body;
    let targetUsernameForMove = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const tempTarget = req.body.targetUsername;
        if (typeof tempTarget !== 'string' || tempTarget.includes('..') || tempTarget.includes('/') || tempTarget.includes('\\') || !/^[a-zA-Z0-9_.-]+$/.test(tempTarget) || tempTarget.length > 50) {
            return res.status(400).json({ success: false, message: '無效的目標用戶名格式。' });
        }
        const targetUserExists = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [tempTarget], (err, row) => resolve(!!row)));
        if (targetUserExists) targetUsernameForMove = tempTarget;
        else return res.status(400).json({ success: false, message: '目標用戶不存在。' });
    }

    if (!sourcePaths || !Array.isArray(sourcePaths) || sourcePaths.length === 0 || !destinationPath || typeof destinationPath !== 'string') {
        return res.status(400).json({ success: false, message: '源路徑列表和目標路徑為必填項且格式正確。' });
    }

    try {
        const fullDestinationPath = resolvePathForUser(targetUsernameForMove, destinationPath);
        const destStat = await fsp.stat(fullDestinationPath).catch(() => null);
        if (!destStat || !destStat.isDirectory()) {
            return res.status(400).json({ success: false, message: '目標路徑不是一個有效的目錄。' });
        }

        let errors = []; let successes = 0;
        for (const sourceRelPath of sourcePaths) {
            if (typeof sourceRelPath !== 'string') {
                errors.push(`無效的源路徑格式: ${JSON.stringify(sourceRelPath)}`); continue;
            }
            const fullSourcePath = resolvePathForUser(targetUsernameForMove, sourceRelPath);
            const itemName = path.basename(fullSourcePath);
            const fullNewPath = path.join(fullDestinationPath, itemName);

            if (fs.existsSync(fullSourcePath) && (await fsp.stat(fullSourcePath)).isDirectory()) {
                if (path.resolve(fullNewPath).startsWith(path.resolve(fullSourcePath) + path.sep) || path.resolve(fullNewPath) === path.resolve(fullSourcePath)) {
                    errors.push(`無法將文件夾 "${itemName}" 移動到其自身或其子文件夾中。`); continue;
                }
            }
            if (fs.existsSync(fullNewPath)) {
                if (path.resolve(fullSourcePath).toLowerCase() !== path.resolve(fullNewPath).toLowerCase()) {
                    errors.push(`目標位置已存在同名項目 "${itemName}"。`); continue;
                }
            }
            try {
                await fsp.rename(fullSourcePath, fullNewPath);
                const ownerUser = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [targetUsernameForMove], (err, row) => resolve(row)));
                if(ownerUser){
                    const newRelativePath = path.posix.join(destinationPath, itemName);
                    db.run("UPDATE shared_files SET file_path = ? WHERE owner_id = ? AND file_path = ?",
                        [newRelativePath, ownerUser.id, sourceRelPath],
                        (updErr) => {
                            if(updErr) console.error(`更新 ${targetUsernameForMove} 的 ${sourceRelPath} 分享路徑至 ${newRelativePath} 時出錯:`, updErr);
                            else console.log(`已更新 ${targetUsernameForMove} 的 ${sourceRelPath} 分享路徑至 ${newRelativePath}`);
                        }
                    );
                    // Also update public_links path
                    db.run("UPDATE public_links SET file_path = ? WHERE owner_id = ? AND file_path = ?",
                        [newRelativePath, ownerUser.id, sourceRelPath],
                        (updErr) => {
                            if(updErr) console.error(`更新 ${targetUsernameForMove} 的 ${sourceRelPath} 公開鏈接路徑至 ${newRelativePath} 時出錯:`, updErr);
                            else console.log(`已更新 ${targetUsernameForMove} 的 ${sourceRelPath} 公開鏈接路徑至 ${newRelativePath}`);
                        }
                    );
                }
                successes++;
            } catch (moveError) {
                console.error(`[Move] 移動項目 "${sourceRelPath}" 到 "${destinationPath}" 失敗:`, moveError);
                errors.push(`移動 "${itemName}" 失敗: ${moveError.code === 'ENOENT' ? '源文件未找到' : (moveError.message.includes('cross-device link not permitted') ? '不支持跨設備移動' : '內部錯誤')}`);
            }
        }

        if (errors.length > 0) {
            const message = `移動操作部分完成。成功 ${successes} 項。錯誤: ${errors.join('; ')}`;
            return res.status(successes > 0 ? 207 : (errors.some(e => e.includes("權限")) ? 403 : 500)).json({ success: successes > 0, message: message, errors: errors });
        }
        res.json({ success: true, message: `成功移動 ${successes} 個項目。` });

    } catch (error) {
        console.error(`[Move API] 移動項目時發生錯誤:`, error);
        let statusCode = 500; let userMessage = error.message || '移動項目時發生內部伺服器錯誤。';
        if (error.message.includes('無效的目標用戶名') || error.message.includes('試圖訪問無效路徑')) { statusCode = 403; userMessage = '權限不足或訪問路徑無效。'; }
        else if (error.code === 'ENOENT') { statusCode = 404; userMessage = '一個或多個指定路徑未找到。'; }
        res.status(statusCode).json({ success: false, message: userMessage });
    }
});


app.get('/stream/:encodedPath(*)', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath);
    const ownerUsernameQuery = req.query.ownerUsername;

    let fileOwnerUsername = actingUser.username;
    let fileOwnerId = actingUser.id;

    if (!relativeFilePath) return res.status(400).send('未指定文件路徑。');

    try {
        if (ownerUsernameQuery && ownerUsernameQuery !== actingUser.username) {
            const owner = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [ownerUsernameQuery], (err, row) => resolve(row)));
            if (!owner) return res.status(404).send('文件擁有者不存在。');
            fileOwnerUsername = owner.username;
            fileOwnerId = owner.id;

            const fullPathToCheck = resolvePathForUser(fileOwnerUsername, relativeFilePath);
            const statsForType = await fsp.stat(fullPathToCheck);
            const hasPermission = await checkSharePermission(actingUser.id, fileOwnerId, relativeFilePath, statsForType.isDirectory());
            if (!hasPermission) return res.status(403).send('您沒有權限串流此分享文件。');

        } else if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
            const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
            if (!targetUser) return res.status(404).send('目標用戶不存在。');
            fileOwnerUsername = targetUser.username;
        }

        const fullFilePath = resolvePathForUser(fileOwnerUsername, relativeFilePath);
        const stat = await fsp.stat(fullFilePath);
        const fileSize = stat.size;
        const range = req.headers.range;

        if (!stat.isFile()) return res.status(404).send('請求的資源不是文件。');
        const mimeType = getVideoMimeType(fullFilePath);
        if (!ALLOWED_VIDEO_EXTENSIONS.includes(path.extname(fullFilePath).toLowerCase())) return res.status(403).send('不支持的視頻文件類型。');

        if (range) {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10);
            let end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            if (start >= fileSize || end >= fileSize || start > end) {
                res.status(416).send('請求範圍不滿足'); return;
            }
            if (end > fileSize - 1) end = fileSize - 1;
            const chunksize = (end - start) + 1;
            const file = fs.createReadStream(fullFilePath, { start, end });
            const head = {
                'Content-Range': `bytes ${start}-${end}/${fileSize}`, 'Accept-Ranges': 'bytes',
                'Content-Length': chunksize, 'Content-Type': mimeType,
            };
            res.writeHead(206, head);
            file.pipe(res);
        } else {
            const head = { 'Content-Length': fileSize, 'Content-Type': mimeType, 'Accept-Ranges': 'bytes' };
            res.writeHead(200, head);
            fs.createReadStream(fullFilePath).pipe(res);
        }
    } catch (err) {
        console.error(`[${actingUser.username}] 視頻流錯誤 for ${fileOwnerUsername}/${relativeFilePath}:`, err.message);
        if (err.code === 'ENOENT') res.status(404).send('找不到文件。');
        else if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) res.status(403).send('禁止訪問。');
        else res.status(500).send('伺服器內部錯誤。');
    }
});

// --- User-to-User Sharing Routes ---
app.post('/actions/share-file', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { filePathToShare, usernameToShareWith, isDirectory } = req.body;
    const isDirBool = isDirectory === 'true';

    let ownerIdToUse = actingUser.id;
    let ownerUsernameToUse = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) {
        const ownerUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => resolve(row)));
        if (!ownerUser) {
            return res.redirect(`/files?path=${encodeURIComponent(path.dirname(filePathToShare))}&targetUsername=${encodeURIComponent(req.body.targetUsername)}&message=分享失敗：文件擁有者不存在。&messageType=error`);
        }
        ownerIdToUse = ownerUser.id;
        ownerUsernameToUse = ownerUser.username;
    }
    
    const sharedWithUser = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [usernameToShareWith], (err, row) => resolve(row)));

    let redirectPath = path.posix.dirname(filePathToShare) || '/';
    let redirectParams = new URLSearchParams();
    if (redirectPath !== '/') redirectParams.set('path', redirectPath);
    if (actingUser.role === 'admin' && req.body.targetUsername) {
        redirectParams.set('targetUsername', req.body.targetUsername);
    }


    if (!filePathToShare || !usernameToShareWith) {
        redirectParams.set('message', '分享失敗：未提供文件路徑或目標用戶名。');
        redirectParams.set('messageType', 'error');
        return res.redirect(`/files?${redirectParams.toString()}`);
    }
    if (!sharedWithUser) {
        redirectParams.set('message', `分享失敗：用戶 "${usernameToShareWith}" 不存在。`);
        redirectParams.set('messageType', 'error');
        return res.redirect(`/files?${redirectParams.toString()}`);
    }
    if (sharedWithUser.id === ownerIdToUse) {
        redirectParams.set('message', '不能與自己分享文件。');
        redirectParams.set('messageType', 'warning');
        return res.redirect(`/files?${redirectParams.toString()}`);
    }

    try {
        const fullPath = resolvePathForUser(ownerUsernameToUse, filePathToShare);
        if (!fs.existsSync(fullPath)) {
            redirectParams.set('message', '分享失敗：指定的文件或目錄不存在。');
            redirectParams.set('messageType', 'error');
            return res.redirect(`/files?${redirectParams.toString()}`);
        }
        const stat = await fsp.stat(fullPath);
        if (isDirBool !== stat.isDirectory()){
            redirectParams.set('message', `分享失敗：項目類型不匹配 (文件/目錄)。`);
            redirectParams.set('messageType', 'error');
            return res.redirect(`/files?${redirectParams.toString()}`);
        }


        db.run(`INSERT INTO shared_files (owner_id, shared_with_id, file_path, is_directory, permissions) 
                VALUES (?, ?, ?, ?, ?)`,
            [ownerIdToUse, sharedWithUser.id, filePathToShare, isDirBool ? 1 : 0, 'read-only'],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                         redirectParams.set('message', `此項目已分享給用戶 "${usernameToShareWith}"。`);
                         redirectParams.set('messageType', 'warning');
                    } else {
                        console.error("分享文件時插入數據庫錯誤:", err);
                        redirectParams.set('message', '分享失敗：數據庫錯誤。');
                        redirectParams.set('messageType', 'error');
                    }
                } else {
                    redirectParams.set('message', `成功將 "${path.basename(filePathToShare)}" 分享給 ${usernameToShareWith}。`);
                    redirectParams.set('messageType', 'success');
                }
                res.redirect(`/files?${redirectParams.toString()}`);
            }
        );
    } catch (err) {
        console.error("分享文件時發生錯誤:", err);
        redirectParams.set('message', `分享失敗：${err.message}`);
        redirectParams.set('messageType', 'error');
        res.redirect(`/files?${redirectParams.toString()}`);
    }
});

app.post('/actions/revoke-share', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { shareId } = req.body;

    let targetUsernameForRedirect = null;
    let ownerIdToCheck = actingUser.id;

    if (actingUser.role === 'admin' && req.body.contextUsername) {
        const contextOwner = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [req.body.contextUsername], (err,row) => resolve(row)));
        if (contextOwner) {
            ownerIdToCheck = contextOwner.id;
            targetUsernameForRedirect = req.body.contextUsername;
        } else {
            return res.redirect(`/files?viewMode=userShares&message=撤銷分享失敗：上下文用戶不存在。&messageType=error`);
        }
    }


    if (!shareId) {
        return res.redirect(`/files?viewMode=userShares${targetUsernameForRedirect ? `&targetUsername=${targetUsernameForRedirect}`:''}&message=撤銷分享失敗：未提供分享ID。&messageType=error`);
    }

    db.run("DELETE FROM shared_files WHERE id = ? AND owner_id = ?", [shareId, ownerIdToCheck], function (err) {
        let message = '';
        let messageType = '';
        if (err) {
            console.error("撤銷分享時數據庫錯誤:", err);
            message = '撤銷分享失敗：數據庫錯誤。';
            messageType = 'error';
        } else if (this.changes === 0) {
            message = '撤銷分享失敗：未找到分享記錄或您沒有權限撤銷此分享。';
            messageType = 'warning';
        } else {
            message = '成功撤銷分享。';
            messageType = 'success';
        }
        let redirectUrl = `/files?viewMode=userShares&message=${encodeURIComponent(message)}&messageType=${messageType}`;
        if (targetUsernameForRedirect) {
            redirectUrl += `&targetUsername=${encodeURIComponent(targetUsernameForRedirect)}`;
        }
        res.redirect(redirectUrl);
    });
});

// --- Public Link Sharing Routes ---
app.post('/actions/create-public-link', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { filePathToShare, isDirectory } = req.body; // isDirectory is 'true' or 'false' (string)
    const isDirBool = isDirectory === 'true';

    let ownerIdToUse = actingUser.id;
    let ownerUsernameToUse = actingUser.username;

    // If admin is creating link on behalf of another user
    if (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) {
        const ownerUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => resolve(row)));
        if (!ownerUser) {
            return res.status(404).json({ success: false, message: '創建公開鏈接失敗：文件擁有者不存在。' });
        }
        ownerIdToUse = ownerUser.id;
        ownerUsernameToUse = ownerUser.username;
    }

    if (!filePathToShare) {
        return res.status(400).json({ success: false, message: '創建公開鏈接失敗：未提供文件路徑。' });
    }

    try {
        const fullPath = resolvePathForUser(ownerUsernameToUse, filePathToShare);
        if (!fs.existsSync(fullPath)) {
            return res.status(404).json({ success: false, message: '創建公開鏈接失敗：指定的文件或目錄不存在。' });
        }
        const stat = await fsp.stat(fullPath);
        if (isDirBool !== stat.isDirectory()) {
            return res.status(400).json({ success: false, message: '創建公開鏈接失敗：項目類型不匹配。' });
        }

        const token = generateUniqueToken();
        db.run(`INSERT INTO public_links (owner_id, file_path, is_directory, token, allow_download) 
                VALUES (?, ?, ?, ?, ?)`,
            [ownerIdToUse, filePathToShare, isDirBool ? 1 : 0, token, 1], // Default allow_download to true
            function (err) {
                if (err) {
                    console.error("創建公開鏈接時插入數據庫錯誤:", err);
                    return res.status(500).json({ success: false, message: '創建公開鏈接失敗：數據庫錯誤。' });
                }
                const publicUrl = `${req.protocol}://${req.get('host')}/public/s/${token}`;
                res.json({ success: true, message: '公開鏈接創建成功！', publicUrl: publicUrl, token: token });
            }
        );
    } catch (err) {
        console.error("創建公開鏈接時發生錯誤:", err);
        res.status(500).json({ success: false, message: `創建公開鏈接失敗：${err.message}` });
    }
});

app.post('/actions/revoke-public-link', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { tokenToRevoke } = req.body; // Can be token or ID, but token is better for UI consistency

    if (!tokenToRevoke) {
        return res.redirect(`/files?viewMode=publicLinks&message=撤銷鏈接失敗：未提供鏈接標識。&messageType=error`);
    }
    
    let ownerIdToCheck = actingUser.id;
    // If admin is revoking for another user, they must provide targetUsername
    if (actingUser.role === 'admin' && req.body.contextUsername && req.body.contextUsername !== actingUser.username) {
        const contextOwner = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [req.body.contextUsername], (err,row) => resolve(row)));
        if (contextOwner) {
            ownerIdToCheck = contextOwner.id;
        } else {
            return res.redirect(`/files?viewMode=publicLinks&targetUsername=${encodeURIComponent(req.body.contextUsername)}&message=撤銷鏈接失敗：上下文用戶不存在。&messageType=error`);
        }
    }

    db.run("DELETE FROM public_links WHERE token = ? AND owner_id = ?", [tokenToRevoke, ownerIdToCheck], function (err) {
        let message = '';
        let messageType = '';
        if (err) {
            console.error("撤銷公開鏈接時數據庫錯誤:", err);
            message = '撤銷鏈接失敗：數據庫錯誤。';
            messageType = 'error';
        } else if (this.changes === 0) {
            message = '撤銷鏈接失敗：未找到鏈接記錄或您沒有權限撤銷此鏈接。';
            messageType = 'warning';
        } else {
            message = '成功撤銷公開鏈接。';
            messageType = 'success';
        }
        let redirectUrl = `/files?viewMode=publicLinks&message=${encodeURIComponent(message)}&messageType=${messageType}`;
        if (actingUser.role === 'admin' && req.body.contextUsername && req.body.contextUsername !== actingUser.username) {
            redirectUrl += `&targetUsername=${encodeURIComponent(req.body.contextUsername)}`;
        }
        res.redirect(redirectUrl);
    });
});


// --- Public Access Routes (NO AUTHENTICATION) ---
// Middleware to fetch public link details
async function getPublicLinkDetails(req, res, next) {
    const token = req.params.token;
    if (!token) return res.status(400).render('error-public', { message: '無效的分享鏈接。' });

    db.get("SELECT pl.*, u.username as owner_username FROM public_links pl JOIN users u ON pl.owner_id = u.id WHERE pl.token = ?", [token], async (err, link) => {
        if (err) {
            console.error("獲取公開鏈接詳情錯誤:", err);
            return res.status(500).render('error-public', { message: '訪問分享鏈接時發生內部錯誤。' });
        }
        if (!link) {
            return res.status(404).render('error-public', { message: '分享鏈接不存在或已過期。' });
        }
        // Optional: Check expiration, password here if implemented
        req.publicLink = link;
        try {
            req.publicLink.fullPathOnServer = resolvePathForUser(link.owner_username, link.file_path);
            if (!fs.existsSync(req.publicLink.fullPathOnServer)) {
                 console.warn(`公開鏈接 ${token} 指向的文件/目錄在服務器上不存在: ${req.publicLink.fullPathOnServer}`);
                 return res.status(404).render('error-public', { message: '分享的項目已不存在。' });
            }
            req.publicLink.stats = await fsp.stat(req.publicLink.fullPathOnServer);
             // Increment access count (fire and forget)
            db.run("UPDATE public_links SET access_count = access_count + 1 WHERE id = ?", [link.id], (acErr) => {
                if (acErr) console.error(`更新公開鏈接 ${token} 訪問計數時出錯:`, acErr);
            });
            next();
        } catch (resolveErr) {
            console.error(`解析公開鏈接路徑錯誤 for token ${token}:`, resolveErr);
            return res.status(500).render('error-public', { message: '無法訪問分享的項目。' });
        }
    });
}

// Public share landing page
app.get('/public/s/:token', getPublicLinkDetails, async (req, res) => {
    const { publicLink } = req;
    const itemName = path.basename(publicLink.file_path);
    let itemsInDir = [];

    if (publicLink.is_directory) {
        try {
            const dirEntries = await fsp.readdir(publicLink.fullPathOnServer, { withFileTypes: true });
            itemsInDir = await Promise.all(dirEntries.map(async entry => {
                const itemRelPath = path.posix.join(publicLink.file_path, entry.name); // Path relative to owner's root
                const fullEntryPath = path.join(publicLink.fullPathOnServer, entry.name);
                const fileExt = path.extname(entry.name).toLowerCase();
                let stats;
                try { stats = await fsp.stat(fullEntryPath); } catch (e) { stats = { size: null, mtime: null }; }
                const isPlayableVideo = entry.isFile() && ALLOWED_VIDEO_EXTENSIONS.includes(fileExt);
                return {
                    name: entry.name,
                    isDir: entry.isDirectory(),
                    pathInShare: entry.name, // Path relative to the shared directory root for public links
                    encodedPathInShare: encodeURIComponent(entry.name),
                    size: entry.isFile() ? stats.size : null,
                    lastModified: stats.mtime,
                    isPlayableVideo: isPlayableVideo,
                    videoType: isPlayableVideo ? getVideoMimeType(entry.name) : null,
                    isViewableText: entry.isFile() && ALLOWED_TEXT_EXTENSIONS.includes(fileExt)
                };
            }));
            itemsInDir.sort((a,b) => { // Sort items within the public directory view
                if (a.isDir && !b.isDir) return -1;
                if (!a.isDir && b.isDir) return 1;
                return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
            });
        } catch (dirErr) {
            console.error(`讀取公開分享的文件夾 ${publicLink.fullPathOnServer} 內容時出錯:`, dirErr);
            return res.status(500).render('error-public', { message: '無法讀取分享的文件夾內容。' });
        }
    }

    res.render('public-share-page', {
        link: publicLink,
        itemName: itemName,
        itemsInDir: itemsInDir, // Will be empty if not a directory
        ALLOWED_TEXT_EXTENSIONS, // Pass to template for conditional rendering
        ALLOWED_VIDEO_EXTENSIONS,
        baseUrl: `${req.protocol}://${req.get('host')}`
    });
});

// Public download route
app.get('/public/dl/:token/:itemNameInPath?', getPublicLinkDetails, async (req, res) => {
    const { publicLink } = req;
    const { itemNameInPath } = req.params; // For files within a shared directory

    if (!publicLink.allow_download) {
        return res.status(403).render('error-public', { message: '此鏈接不允許下載。' });
    }

    let pathToDownload = publicLink.fullPathOnServer;
    let downloadAsName = path.basename(publicLink.file_path);

    if (publicLink.is_directory) {
        if (itemNameInPath) { // Downloading a specific file from a shared directory
            const decodedItemName = decodeURIComponent(itemNameInPath);
            // Security: Ensure itemNameInPath does not contain '..' or other traversal attempts
            if (decodedItemName.includes('..') || decodedItemName.includes('/') || decodedItemName.includes('\\')) {
                return res.status(400).render('error-public', { message: '無效的文件名。' });
            }
            pathToDownload = path.join(publicLink.fullPathOnServer, decodedItemName);
            downloadAsName = decodedItemName;
            try {
                const itemStat = await fsp.stat(pathToDownload);
                if (!itemStat.isFile()) {
                    return res.status(400).render('error-public', { message: '請求的項目不是一個文件。' });
                }
            } catch (e) {
                return res.status(404).render('error-public', { message: '在分享的文件夾中未找到指定文件。' });
            }
        } else { // Downloading the entire shared directory as a zip
            const archiveName = `${path.basename(publicLink.file_path) || 'shared-archive'}-${publicLink.token.substring(0,8)}.zip`;
            const zipfile = new yazl.ZipFile();
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(archiveName)}"`);
            res.setHeader('Content-Type', 'application/zip');
            zipfile.outputStream.pipe(res);
            zipfile.outputStream.on('error', (err) => { console.error('Public Yazl outputStream error:', err); if (!res.headersSent) res.status(500).send('創建壓縮文件時發生錯誤。'); else if (!res.writableEnded) res.end(); });
            res.on('error', (err) => console.error('Public Response stream error during zip download:', err));
            
            try {
                // The userRootForSecurityCheck should be the owner's actual root, not the shared directory itself.
                const ownerRoot = getUserUploadRoot(publicLink.owner_username);
                await addDirectoryToZip(zipfile, publicLink.fullPathOnServer, path.basename(publicLink.file_path) || 'shared_items', ownerRoot);
                zipfile.end();
                return; // Handled by pipe
            } catch (zipErr) {
                console.error('公開鏈接打包下載錯誤:', zipErr);
                if (!res.headersSent) res.status(500).send('打包文件夾時發生內部錯誤。');
                else if (!res.writableEnded) res.end();
                if (zipfile && typeof zipfile.end === 'function' && !zipfile.ended) zipfile.end();
                return;
            }
        }
    }
    // If it's a single file (either directly shared or from a folder)
    res.download(pathToDownload, downloadAsName, (err) => {
        if (err) {
            console.error(`公開鏈接下載文件 ${downloadAsName} 出錯:`, err);
            if (!res.headersSent) { res.status(500).render('error-public', { message: '下載文件時發生內部錯誤。' }); }
        }
    });
});


// Public view route (for text files)
app.get('/public/view/:token/:itemNameInPath?', getPublicLinkDetails, async (req, res) => {
    const { publicLink } = req;
    const { itemNameInPath } = req.params;

    let pathToFileToView = publicLink.fullPathOnServer;
    let filenameToView = path.basename(publicLink.file_path);

    if (publicLink.is_directory) {
        if (!itemNameInPath) return res.status(400).render('error-public', { message: '未指定要查看的文件。' });
        const decodedItemName = decodeURIComponent(itemNameInPath);
        if (decodedItemName.includes('..') || decodedItemName.includes('/') || decodedItemName.includes('\\')) {
            return res.status(400).render('error-public', { message: '無效的文件名。' });
        }
        pathToFileToView = path.join(publicLink.fullPathOnServer, decodedItemName);
        filenameToView = decodedItemName;
        try {
            const itemStat = await fsp.stat(pathToFileToView);
            if (!itemStat.isFile()) return res.status(400).render('error-public', { message: '請求的項目不是一個文件。' });
        } catch (e) {
            return res.status(404).render('error-public', { message: '在分享的文件夾中未找到指定文件。' });
        }
    } else if (itemNameInPath && path.basename(publicLink.file_path) !== decodeURIComponent(itemNameInPath)) {
        // This case should ideally not be hit if URL structure is /public/view/:token for single files
        // and /public/view/:token/:itemName for files in dir.
        return res.status(400).render('error-public', { message: '鏈接與文件名不匹配。' });
    }


    const fileExt = path.extname(filenameToView).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('error-public', { message: `不支持預覽此文件類型 (${fileExt})。` });
    }

    try {
        const content = await fsp.readFile(pathToFileToView, 'utf8');
        res.render('view-file-public', { // A new template for public viewing
            filename: filenameToView,
            content: content,
            link: publicLink, // Pass link for breadcrumbs or download options
            fileExtension: fileExt,
            itemNameInPath: itemNameInPath ? encodeURIComponent(itemNameInPath) : null
        });
    } catch (err) {
        console.error(`公開鏈接讀取文件 ${filenameToView} 查看錯誤:`, err);
        res.status(500).render('error-public', { message: '讀取文件內容失敗。' });
    }
});

// Public stream route (for videos)
app.get('/public/stream/:token/:itemNameInPath?', getPublicLinkDetails, async (req, res) => {
    const { publicLink } = req;
    const { itemNameInPath } = req.params;

    let pathToFileToStream = publicLink.fullPathOnServer;
    let filenameToStream = path.basename(publicLink.file_path);

    if (publicLink.is_directory) {
        if (!itemNameInPath) return res.status(400).send('未指定要串流的文件。');
         const decodedItemName = decodeURIComponent(itemNameInPath);
        if (decodedItemName.includes('..') || decodedItemName.includes('/') || decodedItemName.includes('\\')) {
            return res.status(400).send('無效的文件名。');
        }
        pathToFileToStream = path.join(publicLink.fullPathOnServer, decodedItemName);
        filenameToStream = decodedItemName;
         try {
            const itemStat = await fsp.stat(pathToFileToStream);
            if (!itemStat.isFile()) return res.status(400).send('請求的項目不是一個文件。');
        } catch (e) {
            return res.status(404).send('在分享的文件夾中未找到指定文件。');
        }
    } else if (itemNameInPath && path.basename(publicLink.file_path) !== decodeURIComponent(itemNameInPath)) {
        return res.status(400).send('鏈接與文件名不匹配。');
    }

    const fileExt = path.extname(filenameToStream).toLowerCase();
    if (!ALLOWED_VIDEO_EXTENSIONS.includes(fileExt)) {
        return res.status(403).send('不支持的視頻文件類型。');
    }
    
    try {
        const stat = await fsp.stat(pathToFileToStream);
        const fileSize = stat.size;
        const range = req.headers.range;
        const mimeType = getVideoMimeType(pathToFileToStream);

        if (range) {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10);
            let end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            if (start >= fileSize || end >= fileSize || start > end) {
                res.status(416).send('請求範圍不滿足'); return;
            }
             if (end > fileSize - 1) end = fileSize - 1;
            const chunksize = (end - start) + 1;
            const file = fs.createReadStream(pathToFileToStream, { start, end });
            const head = {
                'Content-Range': `bytes ${start}-${end}/${fileSize}`, 'Accept-Ranges': 'bytes',
                'Content-Length': chunksize, 'Content-Type': mimeType,
            };
            res.writeHead(206, head);
            file.pipe(res);
        } else {
            const head = { 'Content-Length': fileSize, 'Content-Type': mimeType, 'Accept-Ranges': 'bytes' };
            res.writeHead(200, head);
            fs.createReadStream(pathToFileToStream).pipe(res);
        }
    } catch (err) {
        console.error(`公開鏈接視頻流錯誤 for ${filenameToStream}:`, err.message);
        if (err.code === 'ENOENT') res.status(404).send('找不到文件。');
        else res.status(500).send('伺服器內部錯誤。');
    }
});


// --- 管理員路由 ---
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) { console.error("獲取用戶列表錯誤:", err); return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。', csrfToken: res.locals.csrfToken }); }
        res.render('admin', {
            users, currentUser: req.session.user, csrfToken: res.locals.csrfToken,
            message: req.query.message, messageType: req.query.messageType
        });
    });
});

app.post('/admin/add-user', isAuthenticated, isAdmin, (req, res) => {
    const { newUsername, newPassword, confirmNewPassword, role } = req.body;
    if (!newUsername || !newPassword || !confirmNewPassword || !role) return res.redirect('/admin?message=所有新用戶欄位（包括角色）均為必填項。&messageType=error');
    if (role !== 'user' && role !== 'admin') return res.redirect('/admin?message=無效的用戶角色。&messageType=error');
    if (newPassword !== confirmNewPassword) return res.redirect('/admin?message=新用戶的兩次密碼輸入不匹配。&messageType=error');
    if (newUsername.includes('/') || newUsername.includes('..') || newUsername.includes('\\') || newUsername.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(newUsername)) {
        return res.redirect('/admin?message=新用戶名包含無效字符、過長或格式不正確。&messageType=error');
    }
    db.get("SELECT * FROM users WHERE username = ?", [newUsername], (err, existingUser) => {
        if (err) { console.error("管理員添加用戶時檢查用戶名錯誤:", err); return res.redirect('/admin?message=添加用戶失敗，請稍後再試。&messageType=error'); }
        if (existingUser) return res.redirect(`/admin?message=用戶名 "${newUsername}" 已存在。&messageType=error`);
        const hashedPassword = bcrypt.hashSync(newPassword, 12);
        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [newUsername, hashedPassword, role], function (err) {
            if (err) { console.error("管理員添加用戶時插入數據庫錯誤:", err); return res.redirect('/admin?message=添加用戶失敗，請稍後再試。&messageType=error'); }
            getUserUploadRoot(newUsername);
            res.redirect(`/admin?message=用戶 "${newUsername}" (角色: ${role}) 已成功創建。&messageType=success`);
        });
    });
});

app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;
    if (isNaN(userIdToReset)) return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    if (req.session.user.id === userIdToReset) return res.redirect('/admin?message=不能通過此介面重置自己的密碼。請使用“修改密碼”功能。&messageType=error');
    if (!newPassword || newPassword.length < 6) return res.redirect(`/admin?message=新密碼不能為空且長度至少為6位。&messageType=error`);
    const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
    db.run("UPDATE users SET password = ? WHERE id = ? AND id != ?", [hashedNewPassword, userIdToReset, req.session.user.id], function (err) {
        if (err || this.changes === 0) {
            if (err) console.error("管理員重置密碼錯誤:", err);
            return res.redirect('/admin?message=重置密碼失敗 (用戶不存在或試圖重置當前管理員)。&messageType=error');
        }
        db.get("SELECT username FROM users WHERE id = ?", [userIdToReset], (err, targetUser) => {
            if (err) console.error("管理員重置密碼後查詢用戶名錯誤:", err);
            res.redirect(`/admin?message=用戶 ${targetUser ? targetUser.username : `ID ${userIdToReset}`} 的密碼已成功重置。&messageType=success`);
        });
    });
});

app.get('/admin/delete/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    if (req.session.user.id === userIdToDelete) return res.redirect('/admin?message=不能刪除自己。&messageType=error');

    try {
        const user = await new Promise((resolve, reject) => {
            db.get("SELECT username FROM users WHERE id = ? AND id != ?", [userIdToDelete, req.session.user.id], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });
        if (!user) return res.redirect('/admin?message=未找到用戶或試圖刪除當前管理員。&messageType=error');

        const userDirToDelete = getUserUploadRoot(user.username);
        await new Promise((resolve, reject) => {
            db.parallelize(() => {
                db.run("DELETE FROM shared_files WHERE owner_id = ? OR shared_with_id = ?", [userIdToDelete, userIdToDelete], (err) => { if(err) console.error("刪除用戶時清理其分享記錄錯誤:", err);});
                db.run("DELETE FROM public_links WHERE owner_id = ?", [userIdToDelete], (err) => { if(err) console.error("刪除用戶時清理其公開鏈接錯誤:", err);});
                resolve();
            });
        });

        const dbChanges = await new Promise((resolve, reject) => {
            db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], function (err) {
                if (err) reject(err); else resolve(this.changes);
            });
        });

        if (dbChanges > 0) {
            if (fs.existsSync(userDirToDelete)) await fsp.rm(userDirToDelete, { recursive: true, force: true });
            res.redirect(`/admin?message=用戶 ${user.username}、其文件及相關分享記錄已刪除。&messageType=success`);
        } else {
            res.redirect('/admin?message=刪除用戶失敗 (用戶可能已被刪除)。&messageType=error');
        }
    } catch (err) {
        console.error("管理員刪除用戶時發生錯誤:", err);
        res.redirect('/admin?message=刪除用戶過程中發生錯誤。&messageType=error');
    }
});


// --- 錯誤處理 ---
// Public error page (simple, no session user)
app.use('/public', (err, req, res, next) => { // Specific error handler for /public routes
    console.error(`[Public Route Error] ${req.method} ${req.originalUrl}:`, err.stack || err.message || err);
    let publicMessage = '訪問分享內容時發生錯誤。';
    if (process.env.NODE_ENV !== 'production' && err.message) publicMessage = err.message;
    if (err.publicMessage) publicMessage = err.publicMessage; // Custom public message if set on error
    if (res.headersSent) return next(err);
    res.status(err.status || 500).render('error-public', { message: publicMessage });
});

app.use((req, res, next) => { // 404 handler for authenticated routes
    res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。', csrfToken: res.locals.csrfToken });
});
app.use((err, req, res, next) => { // General error handler for authenticated routes
    const usernameForLog = req.session.user ? req.session.user.username : '未認證用戶';
    console.error(`[${usernameForLog}] 全局錯誤處理: ${req.method} ${req.originalUrl}`, err.stack || err.message || err);

    let publicMessage = '伺服器內部錯誤 (500)。';
    if (process.env.NODE_ENV !== 'production' && err.message) publicMessage = err.message;
    if (err.publicMessage) publicMessage = err.publicMessage;

    if (err instanceof multer.MulterError) {
        publicMessage = `上傳錯誤: ${err.message}`;
        if (err.code === 'LIMIT_FILE_SIZE') publicMessage = '文件大小超過限制。';
        if (err.code === 'LIMIT_UNEXPECTED_FILE') publicMessage = '上傳了非預期的文件欄位。';
    } else if (err.code === 'USER_QUOTA_EXCEEDED' || err.code === 'QUOTA_CHECK_ERROR' || err.code === 'INVALID_TARGET_USERNAME_UPLOAD') {
        publicMessage = err.message;
    }

    if (res.headersSent) return next(err);
    res.status(err.status || 500).render('error', {
        user: req.session.user, message: publicMessage, csrfToken: res.locals.csrfToken
    });
});

app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));
process.on('SIGINT', () => {
    console.log('收到 SIGINT 信號，正在關閉伺服器...');
    db.close((err) => {
        if (err) { console.error('關閉 SQLite 資料庫時出錯:', err.message); process.exit(1); }
        console.log('SQLite 資料庫已關閉。');
        process.exit(0);
    });
});
