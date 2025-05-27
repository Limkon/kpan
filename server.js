// server.js (SQLite 版本 - 使用 yazl 和 uuid)
require('dotenv').config();
const express = require('express');
const session = require('express-session');
// const multer = require('multer'); // Corrected: actual multer instance is defined below
const fs = require('fs');
const fsp = fs.promises; // fs.promises 用於異步文件操作
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const yazl = require('yazl'); // 引入 yazl
const { v4: uuidv4 } = require('uuid'); // 引入 uuid 生成 token

const app = express();
const port = process.env.PORT || 3000;

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];
const ALLOWED_VIDEO_EXTENSIONS = ['.mp4', '.webm', '.ogg', '.mov'];
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_very_strong_and_unique_secret_CHANGE_THIS_NOW_REALLY';
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
const db = new sqlite3.Database(DB_FILE, (dbConnectErr) => {
    if (dbConnectErr) {
        console.error('無法連接到 SQLite 資料庫:', dbConnectErr.message);
        process.exit(1); // Exit if DB connection fails
    }
    console.log('已成功連接到 SQLite 資料庫。');

    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )`, (userTableErr) => {
            if (userTableErr) console.error('創建 users 表格失敗:', userTableErr.message);
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
                            function (insertAdminErr) {
                                if (insertAdminErr) console.error('创建初始管理员失败:', insertAdminErr.message);
                                else {
                                    console.log(`初始管理员 '${initialAdminUsername}' 已创建。`);
                                    getUserUploadRoot(initialAdminUsername);
                                }
                            }
                        );
                    }
                });
            }
        });

        // Public links table schema migration
        const publicLinksTableDefinition = `
            CREATE TABLE IF NOT EXISTS public_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                is_directory BOOLEAN NOT NULL DEFAULT 0,
                token TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                expires_at DATETIME,
                allow_download BOOLEAN NOT NULL DEFAULT 1,
                allow_view BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                visit_count INTEGER DEFAULT 0,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `;

        db.run(publicLinksTableDefinition, (createErr) => {
            if (createErr) {
                console.error('創建/確保 public_links 表格時失敗:', createErr.message);
            }
            console.log("'public_links' 表格定義已執行。");

            db.all("PRAGMA table_info(public_links)", (pragmaErr, columns) => {
                if (pragmaErr) {
                    console.error("無法獲取 public_links 表格信息以進行遷移檢查:", pragmaErr.message);
                    return;
                }

                const requiredColumns = {
                    'password_hash': 'TEXT', 
                    'allow_view': 'BOOLEAN NOT NULL DEFAULT 1',
                    'expires_at': 'DATETIME', 
                    'visit_count': 'INTEGER DEFAULT 0'
                };

                let migrationsToRun = [];
                for (const colName in requiredColumns) {
                    if (!columns.some(c => c.name === colName)) {
                        migrationsToRun.push({ name: colName, definition: requiredColumns[colName] });
                    }
                }

                if (migrationsToRun.length === 0) {
                    console.log("public_links 表格結構已是最新。");
                    return;
                }

                function applyNextMigration(index) {
                    if (index >= migrationsToRun.length) {
                        console.log("所有 public_links 表格遷移已完成。");
                        return;
                    }
                    const migration = migrationsToRun[index];
                    console.log(`'public_links' 表格缺少 '${migration.name}' 欄位，正在添加...`);
                    db.run(`ALTER TABLE public_links ADD COLUMN ${migration.name} ${migration.definition}`, (alterErr) => {
                        if (alterErr) {
                            console.error(`為 'public_links' 添加 '${migration.name}' 失敗:`, alterErr.message);
                        } else {
                            console.log(`'${migration.name}' 欄位已成功添加到 'public_links'。`);
                        }
                        applyNextMigration(index + 1); 
                    });
                }
                applyNextMigration(0);
            });
        });
    }); 
}); 

// --- 中間件設置 ---
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', 
        httpOnly: true,
        sameSite: 'lax' 
    }
}));

// --- 輔助函數 ---
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
        default: return 'application/octet-stream'; 
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
                    // console.error(`[DirSize] 計算文件大小錯誤 ${entryPath}:`, statErr.message);
                }
            } else if (entry.isDirectory()) {
                if (entry.name === '.' || entry.name === '..') continue;
                totalSize += await getDirectorySizeRecursive(entryPath);
            }
        }
    } catch (err) {
        if (err.code === 'ENOENT') { return 0; } 
        // console.error(`[DirSize] 讀取目錄錯誤 ${directoryPath}:`, err.message);
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
                        // console.error(`[Search Stat Error] for file ${entryAbsolutePath}:`, statErr.message);
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
                        // console.error(`[Search Stat Error] for directory ${entryAbsolutePath}:`, statErr.message);
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


// --- Multer 設置 ---
const actualMulter = require('multer'); 
const storage = actualMulter.diskStorage({
    destination: async function (req, file, cb) {
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
        let finalDestinationPath = baseUploadPath;

        if (file.webkitRelativePath && typeof file.webkitRelativePath === 'string') {
            const relativeFolderPath = path.dirname(file.webkitRelativePath);
            if (relativeFolderPath && relativeFolderPath !== '.') {
                finalDestinationPath = path.posix.join(baseUploadPath, relativeFolderPath);
            }
        }

        try {
            const resolvedUploadDir = resolvePathForUser(targetUsername, finalDestinationPath);
            if (!fs.existsSync(resolvedUploadDir)) {
                await fsp.mkdir(resolvedUploadDir, { recursive: true });
            }
            cb(null, resolvedUploadDir);
        } catch (err) {
            console.error(`[Multer Destination ERROR] For target ${targetUsername} at path ${finalDestinationPath}:`, err);
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        const safeFilename = path.basename(file.originalname); 
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8')); 
    }
});

const upload = actualMulter({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            console.warn(`[Multer FileFilter] Invalid characters in filename: ${file.originalname}`);
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true); 
    },
    limits: { fileSize: 100 * 1024 * 1024 } 
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
        
        const hashedPassword = bcrypt.hashSync(password, 12);
        const userRole = 'user'; 
        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
            if (err) { console.error("註冊時插入用戶錯誤:", err); return res.render('register', { error: '註冊失敗，請稍後再試。', csrfToken: res.locals.csrfToken }); }
            getUserUploadRoot(username); 
            res.redirect('/login?message=註冊成功，請登錄。');
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
                    // console.error(`[Stat Error] for ${fullEntryPath}:`, statErr.message);
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
        } else if (viewMode === 'userShares') { 
            pageTitle = `${contextUsername} 的公開分享連結`;
            currentDisplayPath = '/'; 
            items = await new Promise((resolve, reject) => {
                db.all(`SELECT id as link_id, file_path, is_directory, token, created_at, expires_at, password_hash, visit_count 
                        FROM public_links 
                        WHERE owner_id = ? 
                        ORDER BY created_at DESC`,
                    [contextUserId], (err, rows) => {
                        if (err) reject(err); else resolve(rows);
                    });
            });
            items = items.map(link => ({
                link_id: link.link_id,
                name: path.basename(link.file_path), 
                isDir: !!link.is_directory,
                path: link.file_path, 
                token: link.token,
                publicUrl: `/public/${link.token}`, 
                createdAt: link.created_at,
                expiresAt: link.expires_at,
                hasPassword: !!link.password_hash,
                visitCount: link.visit_count,
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
            message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${contextUsername} 的文件夾 (模式: ${viewMode}, 路徑: ${relativeQueryPath}, 搜索: ${searchQuery || '無'}) 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT' && !searchQuery) friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑') || err.message.includes('無效的目標用戶名')) friendlyMessage = '無權訪問指定路徑或用戶無效。';
        else if (err.code === 'SQLITE_ERROR' && err.message.includes('no such column')) { // More specific error for user
            friendlyMessage = '資料庫結構錯誤，請聯繫管理員。可能需要重啟應用程式以更新資料庫。';
        }


        const baseRedirect = '/files';
        let redirectParams = [];
        if (isAdminViewingOther) redirectParams.push(`targetUsername=${encodeURIComponent(contextUsername)}`);
        
        if (viewMode !== 'myfiles' || (err.code !== 'ENOENT' && !err.message.includes('無效路徑'))) {
             if (relativeQueryPath !== '/' && viewMode === 'myfiles' && !searchQuery) {
                const parentPath = path.posix.dirname(relativeQueryPath);
                if (parentPath !== '.' && parentPath !== '/') redirectParams.push(`path=${encodeURIComponent(parentPath)}`);
            }
        }
        if (searchQuery) redirectParams.push(`q=${encodeURIComponent(searchQuery)}`);
        
        redirectParams.push(`viewMode=${viewMode}`); 
        redirectParams.push(`message=${encodeURIComponent(friendlyMessage)}`, `messageType=error`);
        res.redirect(`${baseRedirect}?${redirectParams.join('&')}`);
    }
});

app.post('/upload', isAuthenticated, (req, res, next) => {
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

        const ownerUser = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [targetUsername], (err, row) => resolve(row)));
        if (ownerUser) {
            const newRelativePathForLink = path.posix.join(parentDirOfOld, finalNewName);
            db.run("UPDATE public_links SET file_path = ? WHERE owner_id = ? AND file_path = ?",
                [newRelativePathForLink, ownerUser.id, relativeOldPath],
                (updErr) => {
                    if (updErr) console.error(`重命名時更新 ${targetUsername} 的 ${relativeOldPath} 公開連結路徑至 ${newRelativePathForLink} 時出錯:`, updErr);
                    else console.log(`已更新 ${targetUsername} 的 ${relativeOldPath} 公開連結路徑至 ${newRelativePathForLink}`);
                }
            );
        }

        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗: ${err.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : '內部錯誤。'}&messageType=error`);
    }
});

app.get('/download', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    let targetUsernameForDownload = actingUser.username; 

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
        if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
        targetUsernameForDownload = targetUser.username;
    }
    
    if (!relativeFilePath) {
        return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。', csrfToken: res.locals.csrfToken });
    }
    
    try {
        const fullFilePath = resolvePathForUser(targetUsernameForDownload, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (stats.isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => { 
                if (err) {
                    console.error(`[${actingUser.username}] 為 ${targetUsernameForDownload} 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) { res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。', csrfToken: res.locals.csrfToken }); }
                }
            });
        } else { 
            res.status(400).render('error', { user: actingUser, message: '請求的資源不是一個有效文件 (不能直接下載文件夾，請使用打包下載)。', csrfToken: res.locals.csrfToken });
        }
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsernameForDownload} 準備下載 ${relativeFilePath} 時出錯:`, err);
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
            const fullPathOnServer = resolvePathForUser(archiveOwnerUsername, item.path);
            const userUploadRootForZip = getUserUploadRoot(archiveOwnerUsername); 

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

        if (!res.headersSent) {
            res.status(500).send(`創建壓縮文件時發生內部錯誤: ${error.message.includes('無效的目標用戶名') ? '目標用戶驗證失敗。' : error.message}`);
        } else if (!res.writableEnded) {
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
            db.run("DELETE FROM public_links WHERE owner_id = ? AND file_path = ?", [ownerUser.id, relativeItemPath], (delErr) => {
                if (delErr) console.error(`刪除 ${targetUsername} 的 ${relativeItemPath} 的公開連結時出錯:`, delErr);
                else console.log(`已刪除 ${targetUsername} 的 ${relativeItemPath} 的相關公開連結。`);
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
    let targetUsernameForView = actingUser.username;
    let viewTargetUsernameForTemplate = null; 

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
        if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
        targetUsernameForView = targetUser.username;
        if (targetUsernameForView !== actingUser.username) viewTargetUsernameForTemplate = targetUsernameForView;
    }

    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定查看文件路徑。', csrfToken: res.locals.csrfToken });

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('error', { user: actingUser, message: `不支援預覽此文件類型 (${fileExt})。您可以嘗試下載它。`, csrfToken: res.locals.csrfToken });
    }

    try {
        const fullFilePath = resolvePathForUser(targetUsernameForView, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (!stats.isFile()) return res.status(400).render('error', { user: actingUser, message: '請求的路徑不是一個文件。', csrfToken: res.locals.csrfToken });
        
        const content = await fsp.readFile(fullFilePath, 'utf8');
        res.render('view-file', {
            user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate,
            filename: filename, content: content, currentPath: relativeFilePath,
            fileExtension: fileExt, ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS,
            csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsernameForView} 讀取文件 ${relativeFilePath} 查看錯誤:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken });
        if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) return res.status(403).render('error', { user: actingUser, message: '禁止訪問。', csrfToken: res.locals.csrfToken });
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。', csrfToken: res.locals.csrfToken });
    }
});

app.get('/edit', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    let targetUsernameForEdit = actingUser.username;
    let viewTargetUsernameForTemplate = null;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
        if (!targetUser) return res.status(404).render('error', { user: actingUser, message: '目標用戶不存在。', csrfToken: res.locals.csrfToken });
        targetUsernameForEdit = targetUser.username;
        if (targetUsernameForEdit !== actingUser.username) viewTargetUsernameForTemplate = targetUsernameForEdit;
    }

    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。', csrfToken: res.locals.csrfToken });

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。`, csrfToken: res.locals.csrfToken });

    try {
        const fullFilePath = resolvePathForUser(targetUsernameForEdit, relativeFilePath);
        const stats = await fsp.stat(fullFilePath);
        if (!stats.isFile()) return res.status(400).render('error', { user: actingUser, message: '請求的路徑不是一個文件。', csrfToken: res.locals.csrfToken });
        
        const content = await fsp.readFile(fullFilePath, 'utf8');
        res.render('edit-file', {
            user: actingUser, viewTargetUsername: viewTargetUsernameForTemplate,
            filename: filename, content: content, currentPath: relativeFilePath,
            csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsernameForEdit} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
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
                if (ownerUser) {
                    const newRelativePathForLink = path.posix.join(destinationPath, itemName);
                    db.run("UPDATE public_links SET file_path = ? WHERE owner_id = ? AND file_path = ?",
                        [newRelativePathForLink, ownerUser.id, sourceRelPath],
                        (updErr) => {
                            if (updErr) console.error(`移動時更新 ${targetUsernameForMove} 的 ${sourceRelPath} 公開連結路徑至 ${newRelativePathForLink} 時出錯:`, updErr);
                            else console.log(`已更新 ${targetUsernameForMove} 的 ${sourceRelPath} 公開連結路徑至 ${newRelativePathForLink}`);
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
    let targetUsernameForStream = actingUser.username;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => resolve(row)));
        if (!targetUser) return res.status(404).send('目標用戶不存在。');
        targetUsernameForStream = targetUser.username;
    }

    if (!relativeFilePath) return res.status(400).send('未指定文件路徑。');

    try {
        const fullFilePath = resolvePathForUser(targetUsernameForStream, relativeFilePath);
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
        console.error(`[${actingUser.username}] 視頻流錯誤 for ${targetUsernameForStream}/${relativeFilePath}:`, err.message);
        if (err.code === 'ENOENT') res.status(404).send('找不到文件。');
        else if (err.message.includes('無效的目標用戶名') || err.message.includes('試圖訪問無效路徑')) res.status(403).send('禁止訪問。');
        else res.status(500).send('伺服器內部錯誤。');
    }
});

// --- 新增: 公開分享連結路由 ---
app.post('/actions/create-public-link', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { filePathToShare, isDirectory: isDirStr, allowDownload: allowDownloadStr, allowView: allowViewStr, expiresAt: expiresAtStr } = req.body;
    const isDirectory = isDirStr === 'true';
    const allowDownload = allowDownloadStr !== 'false'; 
    const allowView = allowViewStr !== 'false';     
    let expiresAt = null;
    if (expiresAtStr) {
        const parsedDate = new Date(expiresAtStr);
        if (!isNaN(parsedDate.getTime())) {
            expiresAt = parsedDate.toISOString();
        } else {
            console.warn("無效的過期日期格式:", expiresAtStr);
        }
    }


    let ownerIdToUse = actingUser.id;
    let ownerUsernameToUse = actingUser.username;

    if (actingUser.role === 'admin' && req.body.targetUsername && req.body.targetUsername !== actingUser.username) {
        const ownerUser = await new Promise((resolve) => db.get("SELECT id, username FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => resolve(row)));
        if (!ownerUser) {
            return res.status(400).json({ success: false, message: '分享失敗：文件擁有者不存在。' });
        }
        ownerIdToUse = ownerUser.id;
        ownerUsernameToUse = ownerUser.username;
    }
    
    if (!filePathToShare) {
        return res.status(400).json({ success: false, message: '分享失敗：未提供文件路徑。' });
    }

    try {
        const fullPath = resolvePathForUser(ownerUsernameToUse, filePathToShare);
        if (!fs.existsSync(fullPath)) {
            return res.status(404).json({ success: false, message: '分享失敗：指定的文件或目錄不存在。' });
        }
        const stat = await fsp.stat(fullPath);
        if (isDirectory !== stat.isDirectory()){
            return res.status(400).json({ success: false, message: `分享失敗：項目類型不匹配 (文件/目錄)。` });
        }

        const token = uuidv4(); 

        db.run(`INSERT INTO public_links (owner_id, file_path, is_directory, token, allow_download, allow_view, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [ownerIdToUse, filePathToShare, isDirectory ? 1 : 0, token, allowDownload ? 1 : 0, allowView ? 1 : 0, expiresAt],
            function (err) {
                if (err) {
                    console.error("創建公開連結時插入數據庫錯誤:", err);
                    return res.status(500).json({ success: false, message: '分享失敗：數據庫錯誤。' });
                }
                const publicUrl = `${req.protocol}://${req.get('host')}/public/${token}`;
                res.json({ success: true, message: '公開連結創建成功！', publicUrl: publicUrl, token: token });
            }
        );
    } catch (err) {
        console.error("創建公開連結時發生錯誤:", err);
        res.status(500).json({ success: false, message: `分享失敗：${err.message}` });
    }
});

app.post('/actions/revoke-public-link', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { link_id, token } = req.body; 

    let ownerIdToCheck = actingUser.id;
    let targetUsernameForRedirect = null;

    if (actingUser.role === 'admin' && req.body.contextUsername) {
        const contextOwner = await new Promise((resolve) => db.get("SELECT id FROM users WHERE username = ?", [req.body.contextUsername], (err,row) => resolve(row)));
        if (contextOwner) {
            ownerIdToCheck = contextOwner.id;
            targetUsernameForRedirect = req.body.contextUsername;
        } else {
            return res.redirect(`/files?viewMode=userShares&message=撤銷連結失敗：上下文用戶不存在。&messageType=error`);
        }
    }

    if (!link_id && !token) {
        return res.redirect(`/files?viewMode=userShares${targetUsernameForRedirect ? `&targetUsername=${targetUsernameForRedirect}`:''}&message=撤銷連結失敗：未提供連結標識。&messageType=error`);
    }

    const query = link_id ? "DELETE FROM public_links WHERE id = ? AND owner_id = ?" : "DELETE FROM public_links WHERE token = ? AND owner_id = ?";
    const params = link_id ? [link_id, ownerIdToCheck] : [token, ownerIdToCheck];

    db.run(query, params, function (err) {
        let message = '';
        let messageType = '';
        if (err) {
            console.error("撤銷公開連結時數據庫錯誤:", err);
            message = '撤銷連結失敗：數據庫錯誤。';
            messageType = 'error';
        } else if (this.changes === 0) {
            message = '撤銷連結失敗：未找到連結記錄或您沒有權限撤銷此連結。';
            messageType = 'warning';
        } else {
            message = '成功撤銷公開連結。';
            messageType = 'success';
        }
        let redirectUrl = `/files?viewMode=userShares&message=${encodeURIComponent(message)}&messageType=${messageType}`;
        if (targetUsernameForRedirect) {
            redirectUrl += `&targetUsername=${encodeURIComponent(targetUsernameForRedirect)}`;
        }
        res.redirect(redirectUrl);
    });
});

// 新增: 批量撤銷公開連結路由
app.post('/actions/revoke-public-links-batch', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { link_ids } = req.body; // Expecting an array of link_id

    if (!link_ids || !Array.isArray(link_ids) || link_ids.length === 0) {
        return res.status(400).json({ success: false, message: '未選擇要撤銷的連結。' });
    }

    let ownerIdToCheck = actingUser.id;
    // If admin is revoking for another user, the contextUsername should be passed and validated
    if (actingUser.role === 'admin' && req.body.contextUsername) {
        const contextOwner = await new Promise((resolve) => 
            db.get("SELECT id FROM users WHERE username = ?", [req.body.contextUsername], (err, row) => resolve(row))
        );
        if (contextOwner) {
            ownerIdToCheck = contextOwner.id;
        } else {
            return res.status(403).json({ success: false, message: '上下文用戶無效，無法執行操作。' });
        }
    }

    const placeholders = link_ids.map(() => '?').join(',');
    const query = `DELETE FROM public_links WHERE id IN (${placeholders}) AND owner_id = ?`;
    const params = [...link_ids, ownerIdToCheck];

    db.run(query, params, function (err) {
        if (err) {
            console.error("批量撤銷公開連結時數據庫錯誤:", err);
            return res.status(500).json({ success: false, message: '批量撤銷連結失敗：數據庫錯誤。' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ success: false, message: '沒有找到可撤銷的連結，或您沒有權限操作。' });
        }
        res.json({ success: true, message: `成功撤銷 ${this.changes} 個公開連結。` });
    });
});


// --- 公開連結訪問路由 ---
app.get('/public/:token', async (req, res) => {
    const { token } = req.params;
    const { relPath } = req.query; 

    try {
        const link = await new Promise((resolve, reject) => {
            db.get("SELECT pl.*, u.username as owner_username FROM public_links pl JOIN users u ON pl.owner_id = u.id WHERE pl.token = ?", [token], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });

        if (!link) {
            return res.status(404).render('error', { message: '分享連結不存在或已過期。', user: null, csrfToken: null });
        }
        if (link.expires_at && new Date(link.expires_at) < new Date()) {
            return res.status(403).render('error', { message: '此分享連結已過期。', user: null, csrfToken: null });
        }


        db.run("UPDATE public_links SET visit_count = visit_count + 1 WHERE id = ?", [link.id]);

        const ownerUsername = link.owner_username;
        let itemRelativePath = link.file_path; 
        if (link.is_directory && relPath) { 
            itemRelativePath = path.posix.join(link.file_path, relPath);
        }
        
        const fullItemPath = resolvePathForUser(ownerUsername, itemRelativePath);
        const stats = await fsp.stat(fullItemPath);

        if (stats.isFile()) {
            if (!link.allow_view && !link.allow_download) {
                 return res.status(403).render('error', { message: '此連結不允許查看或下載。', user: null, csrfToken: null });
            }
            if (link.allow_download) { 
                return res.download(fullItemPath, path.basename(itemRelativePath), (err) => {
                    if (err) {
                        console.error(`公開連結下載錯誤 (${token}, path: ${itemRelativePath}):`, err);
                        if (!res.headersSent) res.status(500).render('error', { message: '下載文件時發生錯誤。', user: null, csrfToken: null });
                    }
                });
            } else { 
                 const fileExt = path.extname(itemRelativePath).toLowerCase();
                 if (link.allow_view && ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
                    const content = await fsp.readFile(fullItemPath, 'utf8');
                    return res.render('public-view-file', { 
                        filename: path.basename(itemRelativePath),
                        content: content,
                        fileExtension: fileExt,
                        link: link, 
                        user: null, 
                        csrfToken: null,
                        req: req 
                    });
                 }
                 return res.status(403).render('error', { message: '此連結不允許查看此文件類型。', user: null, csrfToken: null });
            }
        } else if (stats.isDirectory()) {
            if (!link.allow_view) { 
                return res.status(403).render('error', { message: '此連結不允許查看目錄內容。', user: null, csrfToken: null });
            }
            const dirEntries = await fsp.readdir(fullItemPath, { withFileTypes: true });
            const items = await Promise.all(dirEntries.map(async entry => {
                const entryRelPath = path.posix.join(relPath || '', entry.name); 
                const fullEntryPath = path.join(fullItemPath, entry.name);
                let entryStats;
                try { entryStats = await fsp.stat(fullEntryPath); } catch (e) { entryStats = {size: null, mtime: null}; }
                
                return {
                    name: entry.name,
                    isDir: entry.isDirectory(),
                    path: entryRelPath, 
                    encodedName: encodeURIComponent(entry.name),
                    size: entry.isFile() ? entryStats.size : null,
                    lastModified: entryStats.mtime,
                };
            }));
            items.sort((a, b) => { 
                if (a.isDir && !b.isDir) return -1; if (!a.isDir && b.isDir) return 1;
                return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
            });

            return res.render('public-directory', { 
                link: link,
                directoryName: path.basename(link.file_path) + (relPath ? '/' + relPath : ''),
                items: items,
                currentRelPath: relPath || '', 
                user: null, csrfToken: null
            });
        } else {
            return res.status(404).render('error', { message: '分享的項目類型未知。', user: null, csrfToken: null });
        }

    } catch (err) {
        console.error(`訪問公開連結 ${token} 錯誤:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { message: '分享的項目未找到。', user: null, csrfToken: null });
        res.status(500).render('error', { message: '處理分享連結時發生錯誤。', user: null, csrfToken: null });
    }
});

app.get('/public/download/:token', async (req, res) => {
    const { token } = req.params;
    const { relPath } = req.query; 

    try {
        const link = await new Promise((resolve, reject) => {
            db.get("SELECT pl.*, u.username as owner_username FROM public_links pl JOIN users u ON pl.owner_id = u.id WHERE pl.token = ?", [token], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });

        if (!link || !link.allow_download) { 
            return res.status(403).render('error', { message: '此連結不存在、已過期或不允許下載。', user: null, csrfToken: null });
        }
        if (link.expires_at && new Date(link.expires_at) < new Date()) {
            return res.status(403).render('error', { message: '此分享連結已過期。', user: null, csrfToken: null });
        }
        
        let itemRelativePathForDownload = link.file_path; 
        if (link.is_directory && relPath) { 
            itemRelativePathForDownload = path.posix.join(link.file_path, relPath);
        } else if (link.is_directory && !relPath) { 
            return res.status(400).render('error', { message: '不能直接下載整個分享目錄，請打包下載或進入目錄單獨下載文件。', user: null, csrfToken: null });
        }

        const fullItemPathToDownload = resolvePathForUser(link.owner_username, itemRelativePathForDownload);
        const statsDownload = await fsp.stat(fullItemPathToDownload);

        if (!statsDownload.isFile()) {
            return res.status(400).render('error', { message: '請求下載的不是一個有效文件。', user: null, csrfToken: null });
        }
        
        res.download(fullItemPathToDownload, path.basename(itemRelativePathForDownload), (downloadErr) => {
            if (downloadErr) {
                console.error(`公開連結下載錯誤 (/public/download/${token}, path: ${itemRelativePathForDownload}):`, downloadErr);
                if (!res.headersSent) {
                    res.status(500).render('error', { message: '下載文件時發生內部錯誤。', user: null, csrfToken: null });
                }
            }
        });

    } catch (err) {
        console.error(`處理公開下載請求 /public/download/${token} 錯誤:`, err);
        if (err.code === 'ENOENT') return res.status(404).render('error', { message: '請求下載的文件未找到。', user: null, csrfToken: null });
        res.status(500).render('error', { message: '處理下載請求時發生錯誤。', user: null, csrfToken: null });
    }
});


app.get('/public/stream/:token', async (req, res) => {
    const { token } = req.params;
    const { relPath } = req.query; 

    try {
        const link = await new Promise((resolve, reject) => {
            db.get("SELECT pl.*, u.username as owner_username FROM public_links pl JOIN users u ON pl.owner_id = u.id WHERE pl.token = ?", [token], (err, row) => {
                if (err) reject(err); else resolve(row);
            });
        });

        if (!link || !link.allow_view) { 
            return res.status(404).send('分享連結不存在、已過期或不允許查看。');
        }
        if (link.expires_at && new Date(link.expires_at) < new Date()) {
            return res.status(403).send('此分享連結已過期。');
        }
        
        let itemRelativePath = link.file_path;
        if (link.is_directory && relPath) {
            itemRelativePath = path.posix.join(link.file_path, relPath);
        } else if (link.is_directory && !relPath) {
            return res.status(400).send('請求串流整個目錄是不被允許的。');
        }


        const fullFilePath = resolvePathForUser(link.owner_username, itemRelativePath);
        const stat = await fsp.stat(fullFilePath);
        if (!stat.isFile() || !ALLOWED_VIDEO_EXTENSIONS.includes(path.extname(fullFilePath).toLowerCase())) {
            return res.status(403).send('請求的資源不是可串流的視頻文件。');
        }
        
        db.run("UPDATE public_links SET visit_count = visit_count + 1 WHERE id = ?", [link.id]);

        const fileSize = stat.size;
        const range = req.headers.range;
        const mimeType = getVideoMimeType(fullFilePath);

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
        console.error(`公開連結串流錯誤 (${token}, relPath: ${relPath}):`, err.message);
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
            db.run("DELETE FROM public_links WHERE owner_id = ?", [userIdToDelete], (err) => { 
                if(err) { console.error("刪除用戶時清理其擁有的公開連結錯誤:", err); reject(err); }
                else resolve();
            });
        });

        const dbChanges = await new Promise((resolve, reject) => {
            db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], function (err) {
                if (err) reject(err); else resolve(this.changes);
            });
        });

        if (dbChanges > 0) {
            if (fs.existsSync(userDirToDelete)) await fsp.rm(userDirToDelete, { recursive: true, force: true });
            res.redirect(`/admin?message=用戶 ${user.username}、其文件及相關公開連結已刪除。&messageType=success`);
        } else {
            res.redirect('/admin?message=刪除用戶失敗 (用戶可能已被刪除)。&messageType=error');
        }
    } catch (err) {
        console.error("管理員刪除用戶時發生錯誤:", err);
        res.redirect('/admin?message=刪除用戶過程中發生錯誤。&messageType=error');
    }
});


// --- 錯誤處理 ---
app.use((req, res, next) => { 
    res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。', csrfToken: res.locals.csrfToken });
});
app.use((err, req, res, next) => { 
    const usernameForLog = req.session.user ? req.session.user.username : '未認證用戶';
    console.error(`[${usernameForLog}] 全局錯誤處理: ${req.method} ${req.originalUrl}`, err.stack || err.message || err);

    let publicMessage = '伺服器內部錯誤 (500)。';
    if (process.env.NODE_ENV !== 'production' && err.message) publicMessage = err.message; 
    if (err.publicMessage) publicMessage = err.publicMessage; 

    if (err instanceof actualMulter.MulterError) { 
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

app.listen(port, () => {
    console.log(`伺服器運行在 http://localhost:${port}`);
    console.log("注意: 資料庫遷移邏輯會在首次查詢或操作 'public_links' 表之前異步執行。");
    console.log("如果遇到 'no such column' 錯誤，請重啟伺服器一次以確保遷移完成。");
});

process.on('SIGINT', () => {
    console.log('收到 SIGINT 信號，正在關閉伺服器...');
    db.close((err) => {
        if (err) { console.error('關閉 SQLite 資料庫時出錯:', err.message); process.exit(1); }
        console.log('SQLite 資料庫已關閉。');
        process.exit(0);
    });
});

