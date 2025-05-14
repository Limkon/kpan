// server.js (完整功能版)
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const archiver = require('archiver');

const app = express();
const port = 8100; // 您指定的端口

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];

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
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )`, (err) => {
        if (err) console.error('創建 users 表格失敗:', err.message);
        else console.log("'users' 表格已準備就緒。");
    });
});

// --- 中間件設置 ---
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your_super_strong_secret_key_please_change_this_ASAP_v_final', // 強烈建議更改此密鑰
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' } // 生產環境中 secure 應設為 true (HTTPS)
}));

// --- 輔助函數 ---
function getUserUploadRoot(username) {
    if (typeof username !== 'string' || !username.match(/^[a-zA-Z0-9_-]+$/) || username.length > 50) { // 更嚴格的用戶名驗證
        console.error(`無效的用戶名用於獲取根目錄: ${username}`);
        throw new Error('無效的用戶名格式或長度。');
    }
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

function resolvePathForUser(usernameForPath, relativePath = '/') {
    if (typeof usernameForPath !== 'string' || !usernameForPath.match(/^[a-zA-Z0-9_-]+$/) || usernameForPath.length > 50) {
        throw new Error('無效的目標用戶名格式或長度。');
    }
    // 清理和規範化 relativePath，防止 '..' 等字符導致路徑遍歷
    const normalizedRelativePath = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
    const userRoot = getUserUploadRoot(usernameForPath); // 確保用戶根目錄存在
    const requestedPath = path.join(userRoot, normalizedRelativePath);

    // 最終安全檢查：確保解析後的絕對路徑仍然在用戶的根目錄下
    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        console.warn(`路徑遍歷嘗試或無效路徑: username='${usernameForPath}', relativePath='${relativePath}', normalized='${normalizedRelativePath}', resolved='${path.resolve(requestedPath)}', userRoot='${path.resolve(userRoot)}'`);
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

// --- Multer 設置 ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const actingUsername = req.session.user.username;
        const targetUsername = (req.session.user.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUsername;
        const currentUploadPath = req.body.currentPath || '/';
        try {
            const resolvedUploadDir = resolvePathForUser(targetUsername, currentUploadPath);
            if (!fs.existsSync(resolvedUploadDir)) {
                fs.mkdirSync(resolvedUploadDir, { recursive: true });
            }
            cb(null, resolvedUploadDir);
        } catch (err) {
            console.error(`[${actingUsername}] Multer destination error for target ${targetUsername} at path ${currentUploadPath}:`, err);
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        const safeFilename = path.basename(file.originalname.replace(/[/\\]/g, '_')); // 移除路徑分隔符
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const dangerousChars = /[/\\]|\.\./; // 不允許路徑分隔符和 '..'
        if (dangerousChars.test(file.originalname)) {
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    }
});

// --- 認證中間件 ---
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).render('error', { user: req.session.user, message: '禁止訪問：僅限管理員。' });
}

// --- 基礎路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));
app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message }));
app.post('/login', (req, res) => { /* ... (與之前版本相同，確保錯誤處理) ... */
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) { console.error("Login DB error:", err); return res.render('login', { error: '登錄錯誤，請稍後再試。' }); }
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。' });
        }
    });
});
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => { /* ... (與之前版本相同，確保用戶名驗證和目錄創建) ... */
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。' });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。' });
    if (!username.match(/^[a-zA-Z0-9_-]+$/) || username.length > 50 || username.length < 3) {
        return res.render('register', { error: '用戶名只能包含字母、數字、下劃線和連字符，長度3-50位。'});
    }
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) { console.error("Register DB select error:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。' }); }
        if (row) return res.render('register', { error: '用戶名已存在。' });
        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) { console.error("Register DB count error:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。' }); }
            const hashedPassword = bcrypt.hashSync(password, 10);
            const userRole = countRow.count === 0 ? 'admin' : 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) { console.error("Register DB insert error:", err); return res.render('register', { error: '註冊失敗，請稍後再試。' }); }
                try { getUserUploadRoot(username); } catch (e) { console.error("創建用戶目錄失敗 on register for " + username + ":", e); /* non-fatal, but log */ }
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));
app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null }));
app.post('/change-password', isAuthenticated, (req, res) => { /* ... (與之前版本相同) ... */
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;
    if (!currentPassword || !newPassword || !confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error' });
    if (newPassword !== confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error' });
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user || !bcrypt.compareSync(currentPassword, user.password)) return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error' });
        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) { console.error("Update password DB error:", err); return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error' });}
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success' });
        });
    });
});

// --- 文件操作路由 ---
// GET /files (文件瀏覽)
app.get('/files', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeQueryPath = req.query.path || '/';
    let targetUsernameForView = actingUser.username;
    let viewAsAdminContext = false;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        try {
            const targetUserExists = await new Promise((resolve, reject) => {
                db.get("SELECT username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                    if (err) reject(err); else resolve(!!row);
                });
            });
            if (targetUserExists) {
                targetUsernameForView = req.query.targetUsername;
                viewAsAdminContext = true;
            } else {
                return res.redirect(`/files?message=目標用戶 ${encodeURIComponent(req.query.targetUsername)} 不存在。&messageType=error`);
            }
        } catch (dbErr) {
            console.error("檢查目標用戶是否存在時出錯:", dbErr);
            return res.redirect(`/files?message=檢查目標用戶時出錯。&messageType=error`);
        }
    }

    try {
        const currentFullPath = resolvePathForUser(targetUsernameForView, relativeQueryPath);
        if (!fs.existsSync(currentFullPath) || !(await fsp.stat(currentFullPath)).isDirectory()) {
            console.warn(`請求的路徑不是有效目錄: User='${targetUsernameForView}', Path='${relativeQueryPath}'`);
            const parentPath = path.dirname(relativeQueryPath) === '.' ? '/' : path.dirname(relativeQueryPath); // 確保父路徑是有效的
            const adminQuery = viewAsAdminContext ? `&targetUsername=${encodeURIComponent(targetUsernameForView)}` : '';
            return res.redirect(`/files?path=${encodeURIComponent(parentPath)}${adminQuery}&message=請求的路徑無效或不是文件夾。&messageType=error`);
        }

        const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
        const items = dirEntries.map(entry => {
            const itemPath = path.join(relativeQueryPath, entry.name); // 相對於用戶根的路徑
            return {
                name: entry.name,
                isDir: entry.isDirectory(),
                path: itemPath,
                encodedName: encodeURIComponent(entry.name),
                encodedPath: encodeURIComponent(itemPath)
            };
        }).sort((a, b) => {
            if (a.isDir && !b.isDir) return -1;
            if (!a.isDir && b.isDir) return 1;
            return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
        });

        res.render('files', {
            user: actingUser,
            viewTargetUsername: viewAsAdminContext ? targetUsernameForView : null,
            items: items,
            currentPath: relativeQueryPath,
            message: req.query.message,
            messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${targetUsernameForView} 的文件夾 ${relativeQueryPath} 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT') friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑') || err.message.includes('無效的目標用戶名') || err.message.includes('無效的用戶名')) friendlyMessage = '無權訪問或路徑/用戶名無效。';
        
        const adminQueryString = viewAsAdminContext ? `&targetUsername=${encodeURIComponent(targetUsernameForView)}` : '';
        const fallbackPath = (relativeQueryPath && relativeQueryPath !== '/') ? path.dirname(relativeQueryPath) : '/';
        res.redirect(`/files?path=${encodeURIComponent(fallbackPath === '.' ? '/' : fallbackPath)}${adminQueryString}&message=${encodeURIComponent(friendlyMessage)}&messageType=error`);
    }
});

// POST /upload (文件上傳)
app.post('/upload', isAuthenticated, (req, res, next) => {
    upload.array('userFiles', 20)(req, res, (err) => { // Max 20 files per upload
        const currentPath = req.body.currentPath || '/';
        const adminQuery = (req.session.user.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        const redirectPathBase = `/files?path=${encodeURIComponent(currentPath)}${adminQuery}`;
        if (err) {
            console.error(`[${req.session.user.username}] Multer 上傳錯誤:`, err.message);
            return res.redirect(`${redirectPathBase}&message=${encodeURIComponent(err.message)}&messageType=error`);
        }
        if (!req.files || req.files.length === 0) {
            return res.redirect(`${redirectPathBase}&message=沒有選擇文件。&messageType=error`);
        }
        res.redirect(`${redirectPathBase}&message=文件上傳成功。&messageType=success`);
    });
});

// POST /create-folder (創建文件夾)
app.post('/create-folder', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同，確保 targetUsername 和路徑處理正確) ... */
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPath = relativeCurrentPath || '/';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\') || folderName.length > 100 || folderName.trim() === "") {
        return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=無效的文件夾名稱。&messageType=error`);
    }
    try {
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, folderName.trim()));
        if (fs.existsSync(fullPathToCreate)) return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=文件夾 "${folderName.trim()}" 已存在。&messageType=error`);
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=文件夾 "${folderName.trim()}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文件夾錯誤:`, err);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=創建文件夾失敗。&messageType=error`);
    }
});

// POST /rename (重命名)
app.post('/rename', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同，確保 targetUsername 和路徑處理正確) ... */
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1); // Ensure '?' or '&' is correct

    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255 || newName.trim() === "") {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱。&messageType=error`);
    }
    if (!relativeOldPath) return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`);
    try {
        const trimmedNewName = newName.trim();
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        const parentDirOfOld = path.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.join(parentDirOfOld, trimmedNewName));
        if (!fs.existsSync(fullOldPath)) return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`);
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) return res.redirect(`/files?${redirectPathQuery}&message=名稱 "${trimmedNewName}" 已存在。&messageType=error`);
        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗。&messageType=error`);
    }
});

// GET /download (單個文件下載)
app.get('/download', isAuthenticated, (req, res) => { /* ... (與 v7 版本相同) ... */
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。' });
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) { console.error(`[${actingUser.username}] 為 ${targetUsername} 下載文件 ${relativeFilePath} 出錯:`, err); if (!res.headersSent) res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。' });}
            });
        } else res.status(404).render('error', { user: actingUser, message: '文件未找到或不是一個有效文件。' });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 準備下載 ${relativeFilePath} 時出錯:`, err);
        res.status(500).render('error', { user: actingUser, message: '處理下載請求時出錯。' });
    }
});

// GET /delete (單個項目刪除)
app.get('/delete', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同) ... */
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;

    let adminQuery = (actingUser.role === 'admin' && req.query.targetUsername) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (!relativeItemPath) return res.redirect(`/files?${adminQuery.substring(1)}&message=未指定要刪除的項目路徑。&messageType=error`);

    const parentRelativePath = path.dirname(relativeItemPath) === '.' ? '/' : path.dirname(relativeItemPath);
    let redirectQuery = `path=${encodeURIComponent(parentRelativePath)}`;
    if(adminQuery) redirectQuery += adminQuery;


    try {
        const fullItemPath = resolvePathForUser(targetUsername, relativeItemPath);
        if (!fs.existsSync(fullItemPath)) return res.redirect(`/files?${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);
        if (isDir) await fsp.rm(fullItemPath, { recursive: true, force: true });
        else await fsp.unlink(fullItemPath);
        res.redirect(`/files?${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files?${redirectQuery}&message=刪除項目失敗。&messageType=error`);
    }
});

// GET /edit, POST /save/:encodedPath (文本編輯)
// ... (與 v7 版本相同)
app.get('/edit', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。' });
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。`});
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            const content = await fsp.readFile(fullFilePath, 'utf8');
            res.render('edit-file', {
                user: actingUser, viewTargetUsername: (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : null,
                filename: filename, content: content, currentPath: relativeFilePath,
                message: req.query.message, messageType: req.query.messageType
            });
        } else res.status(404).render('error', { user: actingUser, message: '文件未找到。' });
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。' });
    }
});
app.post('/save/:encodedPath', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath);
    const { fileContent } = req.body;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) return res.status(403).render('edit-file', { user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null, filename, content: fileContent, currentPath: relativeFilePath, message: `不支援保存此文件類型 (${fileExt})。`, messageType: 'error' });
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (!fs.existsSync(path.dirname(fullFilePath))) return res.status(400).render('edit-file', { user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null, filename, content: fileContent, currentPath: relativeFilePath, message: '保存路徑無效。', messageType: 'error' });
        await fsp.writeFile(fullFilePath, fileContent, 'utf8');
        const parentDir = path.dirname(relativeFilePath) === '.' ? '/' : path.dirname(relativeFilePath);
        const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        res.redirect(`/files?path=${encodeURIComponent(parentDir)}${adminQuery}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 保存文件 ${relativeFilePath} 錯誤:`, err);
        res.status(500).render('edit-file', { user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null, filename, content: fileContent, currentPath: relativeFilePath, message: '保存文件失敗。', messageType: 'error' });
    }
});


// --- 批量操作路由 ---
// POST /batch-delete
app.post('/batch-delete', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同) ... */
    const actingUser = req.session.user;
    const { items, targetUsername: reqTargetUsername, currentPath } = req.body;
    const effectiveTargetUsername = (actingUser.role === 'admin' && reqTargetUsername) ? reqTargetUsername : actingUser.username;
    const adminQuery = (actingUser.role === 'admin' && reqTargetUsername) ? `&targetUsername=${encodeURIComponent(reqTargetUsername)}` : '';
    const baseRedirectPath = `/files?path=${encodeURIComponent(currentPath || '/')}${adminQuery}`;

    if (!Array.isArray(items) || items.length === 0) {
        return res.redirect(`${baseRedirectPath}&message=${encodeURIComponent('沒有選擇要刪除的項目。')}&messageType=error`);
    }
    let successCount = 0; let errorCount = 0; const errors = [];
    for (const item of items) {
        try {
            const fullItemPath = resolvePathForUser(effectiveTargetUsername, item.path);
            if (!fs.existsSync(fullItemPath)) { errors.push(`項目 "${path.basename(item.path)}" 未找到。`); errorCount++; continue; }
            if (item.isDir) await fsp.rm(fullItemPath, { recursive: true, force: true });
            else await fsp.unlink(fullItemPath);
            successCount++;
        } catch (err) { errors.push(`刪除 "${path.basename(item.path)}" 失敗。`); errorCount++; console.error(`批量刪除 ${item.path} 錯誤:`, err); }
    }
    let message = '';
    if (successCount > 0) message += `${successCount} 個項目已成功刪除。`;
    if (errorCount > 0) message += `${message ? ' ' : ''}${errorCount} 個項目刪除失敗。 ${errors.join('; ')}`;
    res.redirect(`${baseRedirectPath}&message=${encodeURIComponent(message)}&messageType=${errorCount > 0 ? 'error' : 'success'}`);
});

// POST /move-items
app.post('/move-items', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同) ... */
    const actingUser = req.session.user;
    const { items, destinationPath: relativeDestPath, targetUsername: reqTargetUsername, currentPath } = req.body;
    const effectiveTargetUsername = (actingUser.role === 'admin' && reqTargetUsername) ? reqTargetUsername : actingUser.username;
    const adminQuery = (actingUser.role === 'admin' && reqTargetUsername) ? `&targetUsername=${encodeURIComponent(reqTargetUsername)}` : '';
    const baseRedirect = `/files?path=${encodeURIComponent(currentPath || '/')}${adminQuery}`;

    if (!Array.isArray(items) || items.length === 0) return res.redirect(`${baseRedirect}&message=沒有選擇要移動的項目。&messageType=error`);
    if (!relativeDestPath || !relativeDestPath.startsWith('/')) return res.redirect(`${baseRedirect}&message=無效的目標路徑。目標路徑必須以 / 開頭。&messageType=error`);

    let successCount = 0; let errorCount = 0; const errors = [];
    try {
        const fullDestinationDir = resolvePathForUser(effectiveTargetUsername, relativeDestPath);
        if (!fs.existsSync(fullDestinationDir) || !(await fsp.stat(fullDestinationDir)).isDirectory()) {
            return res.redirect(`${baseRedirect}&message=目標文件夾 "${relativeDestPath}" 不存在或不是一個有效的文件夾。&messageType=error`);
        }
        for (const item of items) {
            try {
                const fullSourcePath = resolvePathForUser(effectiveTargetUsername, item.path);
                const itemName = path.basename(item.path);
                const fullNewPath = path.join(fullDestinationDir, itemName); // 不需要再用 resolvePathForUser，因為 fullDestinationDir 已經是絕對安全路徑
                if (!fs.existsSync(fullSourcePath)) { errors.push(`項目 "${itemName}" 未找到。`); errorCount++; continue; }
                if (fullSourcePath.toLowerCase() === fullNewPath.toLowerCase()) { errors.push(`不能將項目 "${itemName}" 移動到相同位置。`); errorCount++; continue; } // 防止移動到自身
                if (fs.existsSync(fullNewPath)) { errors.push(`目標位置已存在同名項目 "${itemName}"。`); errorCount++; continue; }
                if (item.isDir && (fullNewPath.startsWith(fullSourcePath + path.sep) || fullNewPath === fullSourcePath)) {
                    errors.push(`不能將文件夾 "${itemName}" 移動到其自身或其子文件夾中。`); errorCount++; continue;
                }
                await fsp.rename(fullSourcePath, fullNewPath);
                successCount++;
            } catch (err) { errors.push(`移動 "${path.basename(item.path)}" 失敗。`); errorCount++; console.error(`移動 ${item.path} 錯誤:`, err); }
        }
    } catch (err) { return res.redirect(`${baseRedirect}&message=處理目標路徑時出錯。&messageType=error`); }
    let message = '';
    if (successCount > 0) message += `${successCount} 個項目已成功移動到 "${relativeDestPath}"。`;
    if (errorCount > 0) message += `${message ? ' ' : ''}${errorCount} 個項目移動失敗。 ${errors.join('; ')}`;
    res.redirect(`${baseRedirect}&message=${encodeURIComponent(message)}&messageType=${errorCount > 0 ? 'error' : 'success'}`);
});

// POST /batch-download
app.post('/batch-download', isAuthenticated, async (req, res) => { /* ... (與 v7 版本相同) ... */
    const actingUser = req.session.user;
    const { paths, targetUsername: reqTargetUsername, currentPath } = req.body;
    const effectiveTargetUsername = (actingUser.role === 'admin' && reqTargetUsername) ? reqTargetUsername : actingUser.username;
    const adminQuery = (actingUser.role === 'admin' && reqTargetUsername) ? `&targetUsername=${encodeURIComponent(reqTargetUsername)}` : '';
    const errorRedirectPath = `/files?path=${encodeURIComponent(currentPath || '/')}${adminQuery}&messageType=error&message=`;

    if (!Array.isArray(paths) || paths.length === 0) return res.redirect(`${errorRedirectPath}${encodeURIComponent('沒有選擇要下載的項目。')}`);
    try {
        const archive = archiver('zip', { zlib: { level: 6 } }); // Adjusted compression level
        const zipName = `download_${effectiveTargetUsername.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.zip`;
        res.attachment(zipName); archive.pipe(res);
        for (const relativeItemPath of paths) {
            try {
                const fullItemPath = resolvePathForUser(effectiveTargetUsername, relativeItemPath);
                if (!fs.existsSync(fullItemPath)) { archive.append(`File not found: ${relativeItemPath}\n`, { name: `ERRORS_IN_ARCHIVE.txt` }); continue; }
                const stats = await fsp.stat(fullItemPath);
                // 將項目添加到 ZIP 文件時，使用其在用戶文件系統中的相對路徑作為 ZIP 內的路徑
                // 例如，如果 relativeItemPath 是 /folderA/file.txt，則在 ZIP 中也是 /folderA/file.txt
                // 如果 relativeItemPath 是 file.txt (在根目錄)，則在 ZIP 中也是 file.txt
                const entryName = relativeItemPath.startsWith('/') ? relativeItemPath.substring(1) : relativeItemPath;
                if (stats.isDirectory()) archive.directory(fullItemPath, entryName);
                else archive.file(fullItemPath, { name: entryName });
            } catch (itemErr) { archive.append(`Error processing file ${relativeItemPath}: ${itemErr.message}\n`, { name: `ERRORS_IN_ARCHIVE.txt` }); }
        }
        await archive.finalize();
    } catch (err) {
        console.error(`創建批量下載 ZIP 錯誤:`, err);
        if (!res.headersSent) res.redirect(`${errorRedirectPath}${encodeURIComponent('創建下載包失敗。')}`);
    }
});

// --- 管理員路由 ---
// (與 v7 版本相同)
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。' });
        res.render('admin', { users, currentUser: req.session.user, message: req.query.message, messageType: req.query.messageType });
    });
});
app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;
    if (req.session.user.id === userIdToReset) return res.redirect('/admin?message=不能重置自己的密碼。&messageType=error');
    if (!newPassword) return res.redirect(`/admin?message=新密碼不能為空。&messageType=error`);
    const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userIdToReset], function(err) {
        if (err || this.changes === 0) return res.redirect('/admin?message=重置密碼失敗。&messageType=error');
        db.get("SELECT username FROM users WHERE id = ?", [userIdToReset], (err, targetUser) => {
            res.redirect(`/admin?message=用戶 ${targetUser ? targetUser.username : `ID ${userIdToReset}`} 的密碼已成功重置。&messageType=success`);
        });
    });
});
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    if (req.session.user.id === userIdToDelete) return res.redirect('/admin?message=不能刪除自己。&messageType=error');
    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, user) => {
        if (err || !user) return res.redirect('/admin?message=未找到用戶。&messageType=error');
        let userDirToDelete;
        try { userDirToDelete = resolvePathForUser(user.username); }
        catch (resolveErr) { console.error(`解析用戶 ${user.username} 目錄錯誤:`, resolveErr); userDirToDelete = null; }
        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function(err) {
            if (err) return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');
            if (this.changes > 0) {
                if (userDirToDelete && fs.existsSync(userDirToDelete)) {
                    try { await fsp.rm(userDirToDelete, { recursive: true, force: true });
                        res.redirect(`/admin?message=用戶 ${user.username} 及其文件已刪除。&messageType=success`);
                    } catch (fsErr) { res.redirect(`/admin?message=用戶 ${user.username} 已刪除，但其文件夾刪除失敗。&messageType=error`); }
                } else res.redirect(`/admin?message=用戶 ${user.username} 已刪除。&messageType=success`);
            } else res.redirect('/admin?message=未找到用戶或刪除失敗。&messageType=error');
        });
    });
});

// --- 錯誤處理 ---
app.use((req, res, next) => res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。' }));
app.use((err, req, res, next) => {
    console.error(`[${req.session.user ? req.session.user.username : '未認證用戶'}] 全局錯誤處理: ${req.method} ${req.path}`, err);
    let publicMessage = err.publicMessage || err.message || '伺服器內部錯誤 (500)。';
    if (err.code === 'LIMIT_FILE_SIZE') publicMessage = '文件過大。';
    else if (err instanceof multer.MulterError) publicMessage = `文件上傳錯誤: ${err.message}`;
    else if (err.message && err.message.startsWith('上傳目標路徑處理錯誤')) publicMessage = err.message;
    res.status(err.status || 500).render('error', { user: req.session.user, message: publicMessage });
});

app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));
process.on('SIGINT', () => db.close(() => process.exit(0)));
