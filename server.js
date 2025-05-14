// server.js (SQLite 版本 - 移除獨立上傳頁面路由)
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8100;

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
    secret: 'a_very_strong_and_unique_secret_key_v6_final_final', // 請務必更改
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' }
}));

// --- 輔助函數 (與 v5 版本相同) ---
function getUserUploadRoot(username) {
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}
function resolvePathForUser(usernameForPath, relativePath = '/') {
    if (typeof usernameForPath !== 'string' || usernameForPath.includes('..') || usernameForPath.includes('/') || usernameForPath.includes('\\')) {
        throw new Error('無效的目標用戶名。');
    }
    const userRoot = getUserUploadRoot(usernameForPath);
    const requestedPath = path.join(userRoot, relativePath);
    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

// --- Multer 設置 (與 v5 版本相同) ---
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
            console.error(`[${actingUsername}] Multer destination error for target ${targetUsername}:`, err);
            // 向 multer 回調傳遞錯誤，以便它可以被捕獲
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        const safeFilename = path.basename(file.originalname);
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    }
});

// --- 認證中間件 (與 v5 版本相同) ---
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).render('error', { user: req.session.user, message: '禁止訪問：僅限管理員。' });
}

// --- 路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

// 用戶註冊 (與 v5 版本相同)
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。' });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。' });
    if (username.includes('/') || username.includes('..') || username.includes('\\') || username.length > 50) {
        return res.render('register', { error: '用戶名包含無效字符或過長。'});
    }
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) return res.render('register', { error: '註冊錯誤，請稍後再試。' });
        if (row) return res.render('register', { error: '用戶名已存在。' });
        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) return res.render('register', { error: '註冊錯誤，請稍後再試。' });
            const hashedPassword = bcrypt.hashSync(password, 10);
            const userRole = countRow.count === 0 ? 'admin' : 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) return res.render('register', { error: '註冊失敗，請稍後再試。' });
                getUserUploadRoot(username);
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

// 用戶登錄 (與 v5 版本相同)
app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message }));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) return res.render('login', { error: '登錄錯誤，請稍後再試。' });
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。' });
        }
    });
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// 修改密碼 (與 v5 版本相同)
app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null }));
app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;
    if (!currentPassword || !newPassword || !confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error' });
    if (newPassword !== confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error' });
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user || !bcrypt.compareSync(currentPassword, user.password)) return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error' });
        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error' });
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success' });
        });
    });
});

// 文件瀏覽 (與 v5 版本相同)
app.get('/files', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeQueryPath = req.query.path || '/';
    let targetUsernameForView = actingUser.username;
    let viewAsAdminContext = false;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) {
            targetUsernameForView = req.query.targetUsername;
            viewAsAdminContext = true;
        } else {
            return res.redirect(`/files?message=目標用戶 ${req.query.targetUsername} 不存在。&messageType=error`);
        }
    }
    try {
        const currentFullPath = resolvePathForUser(targetUsernameForView, relativeQueryPath);
        const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
        const items = dirEntries.map(entry => {
            const itemPath = path.join(relativeQueryPath, entry.name);
            return { name: entry.name, isDir: entry.isDirectory(), path: itemPath, encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(itemPath) };
        }).sort((a,b) => {
            if (a.isDir && !b.isDir) return -1; if (!a.isDir && b.isDir) return 1;
            return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
        });
        res.render('files', {
            user: actingUser, viewTargetUsername: viewAsAdminContext ? targetUsernameForView : null,
            items: items, currentPath: relativeQueryPath, message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${targetUsernameForView} 的文件夾 ${relativeQueryPath} 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT') friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑')) friendlyMessage = '無權訪問指定路徑。';
        const redirectBase = viewAsAdminContext ? `/files?targetUsername=${encodeURIComponent(targetUsernameForView)}&` : '/files?';
        res.redirect(`${redirectBase}message=${encodeURIComponent(friendlyMessage)}&messageType=error`);
    }
});

// 移除了 GET /upload-page 路由

// 文件上傳處理 (POST /upload)
// 使用 upload.array 中間件處理文件，然後是我們的路由處理器
app.post('/upload', isAuthenticated, (req, res, next) => {
    // 首先調用 multer 中間件
    upload.array('userFiles', 10)(req, res, (err) => {
        if (err) {
            // Multer 錯誤處理 (例如，來自 fileFilter 或 destination 的錯誤)
            console.error(`[${req.session.user.username}] Multer 上傳錯誤:`, err.message);
            const currentPath = req.body.currentPath || '/';
            const adminQuery = (req.session.user.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
            const redirectPath = `/files?path=${encodeURIComponent(currentPath)}${adminQuery}`;
            // 將 multer 的錯誤消息傳遞給用戶
            return res.redirect(`${redirectPath}&message=${encodeURIComponent(err.message)}&messageType=error`);
        }
        // 如果 multer 成功，繼續到我們的邏輯
        const currentPath = req.body.currentPath || '/';
        const adminQuery = (req.session.user.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        const redirectPath = `/files?path=${encodeURIComponent(currentPath)}${adminQuery}`;

        if (!req.files || req.files.length === 0) {
            return res.redirect(`${redirectPath}&message=沒有選擇文件。&messageType=error`);
        }
        res.redirect(`${redirectPath}&message=文件上傳成功。&messageType=success`);
    });
});


// 創建文件夾 (與 v5 版本相同)
app.post('/create-folder', isAuthenticated, async (req, res) => {
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPath = relativeCurrentPath || '/';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\') || folderName.length > 100) {
        return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=無效的文件夾名稱。&messageType=error`);
    }
    try {
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, folderName));
        if (fs.existsSync(fullPathToCreate)) return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=文件夾 "${folderName}" 已存在。&messageType=error`);
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=文件夾 "${folderName}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文件夾錯誤:`, err);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}${adminQuery}&message=創建文件夾失敗。&messageType=error`);
    }
});

// 重命名文件/文件夾 (與 v5 版本相同)
app.post('/rename', isAuthenticated, async (req, res) => {
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255) return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱。&messageType=error`);
    if (!relativeOldPath) return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`);
    try {
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        const parentDirOfOld = path.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.join(parentDirOfOld, newName));
        if (!fs.existsSync(fullOldPath)) return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`);
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) return res.redirect(`/files?${redirectPathQuery}&message=名稱 "${newName}" 已存在。&messageType=error`);
        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗。&messageType=error`);
    }
});

// 文件下載 (與 v5 版本相同)
app.get('/download', isAuthenticated, (req, res) => {
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

// 刪除文件或文件夾 (與 v5 版本相同)
app.get('/delete', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeItemPath) return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);
    const parentRelativePath = path.dirname(relativeItemPath);
    let redirectQuery = (parentRelativePath === '.' || parentRelativePath === '/') ? '' : `path=${encodeURIComponent(parentRelativePath)}`;
    const adminQuery = (actingUser.role === 'admin' && req.query.targetUsername) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (adminQuery) redirectQuery = redirectQuery ? `${redirectQuery}${adminQuery}` : adminQuery.substring(1);
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

// 編輯文本文件 - 顯示頁面 (與 v5 版本相同)
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

// 保存編輯後的文本文件 (與 v5 版本相同)
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
        const parentDir = path.dirname(relativeFilePath);
        const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        res.redirect(`/files?path=${encodeURIComponent(parentDir)}${adminQuery}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 保存文件 ${relativeFilePath} 錯誤:`, err);
        res.status(500).render('edit-file', { user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null, filename, content: fileContent, currentPath: relativeFilePath, message: '保存文件失敗。', messageType: 'error' });
    }
});

// 管理員功能 (與 v5 版本相同)
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
        const userDirToDelete = resolvePathForUser(user.username);
        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function(err) {
            if (err) return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');
            if (this.changes > 0) {
                try {
                    if (fs.existsSync(userDirToDelete)) await fsp.rm(userDirToDelete, { recursive: true, force: true });
                    res.redirect(`/admin?message=用戶 ${user.username} 及其文件已刪除。&messageType=success`);
                } catch (fsErr) {
                    console.error(`刪除用戶 ${user.username} 文件夾錯誤:`, fsErr);
                    res.redirect(`/admin?message=用戶 ${user.username} 已刪除，但其文件夾刪除失敗。&messageType=error`);
                }
            } else res.redirect('/admin?message=未找到用戶或刪除失敗。&messageType=error');
        });
    });
});

// 404 和全局錯誤處理 (與 v5 版本相同)
app.use((req, res, next) => res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。' }));
app.use((err, req, res, next) => {
    console.error(`[${req.session.user ? req.session.user.username : '未認證用戶'}] 全局錯誤處理: ${req.method} ${req.path}`, err);
    res.status(err.status || 500).render('error', { user: req.session.user, message: err.publicMessage || err.message || '伺服器內部錯誤 (500)。' });
});

app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));
process.on('SIGINT', () => db.close(() => process.exit(0)));
