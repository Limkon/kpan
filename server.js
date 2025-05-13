// server.js (SQLite 版本 - 包含文件夾、重命名等功能)
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises; // Using fs.promises for async file operations
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8100; // 您指定的端口

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads'); // 基礎上傳目錄
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
    if (err) {
        console.error('無法連接到 SQLite 資料庫:', err.message);
        throw err;
    }
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
    secret: 'a_much_stronger_secret_key_please_change_me_v3', // 請務必更改為更安全的密鑰
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' } // 生產環境中 secure 應設為 true (HTTPS)
}));

// --- Multer 設置 (文件上傳處理) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userRootPath = path.join(UPLOAD_DIR_BASE, req.session.user.username);
        const currentUploadPath = req.body.currentPath || '/'; // 從表單獲取當前路徑
        const resolvedUploadPath = path.join(userRootPath, currentUploadPath);

        // 確保上傳路徑在用戶的根目錄下，並創建（如果不存在）
        if (!resolvedUploadPath.startsWith(userRootPath)) {
            return cb(new Error('無效的上傳路徑。'));
        }
        if (!fs.existsSync(resolvedUploadPath)) {
            fs.mkdirSync(resolvedUploadPath, { recursive: true });
        }
        cb(null, resolvedUploadPath);
    },
    filename: function (req, file, cb) {
        // 防止文件名包含路徑字符或 ".."
        const safeFilename = path.basename(file.originalname);
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // 基礎的文件名驗證，防止如 '..' 或 '/'
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    }
});

// --- 輔助函數 ---
// 獲取用戶的根上傳目錄
function getUserUploadRoot(username) {
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

// 安全地解析用戶路徑，確保它在用戶的根目錄內
function resolveUserPath(username, relativePath = '/') {
    const userRoot = getUserUploadRoot(username);
    const requestedPath = path.join(userRoot, relativePath);
    // 關鍵：確保解析後的路徑仍然以用戶根目錄開頭
    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

// --- 認證中間件 ---
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    res.status(403).render('error', { user: req.session.user, message: '禁止訪問：僅限管理員。' });
}

// --- 路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

// 用戶註冊與登錄 (與之前版本類似，但確保錯誤處理和重定向正確)
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。' });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。' });
    if (username.includes('/') || username.includes('..') || username.includes('\\')) return res.render('register', { error: '用戶名包含無效字符。'});


    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) return res.render('register', { error: '註冊錯誤，請稍後再試。' });
        if (row) return res.render('register', { error: '用戶名已存在。' });

        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) return res.render('register', { error: '註冊錯誤，請稍後再試。' });
            const hashedPassword = bcrypt.hashSync(password, 10);
            const userRole = countRow.count === 0 ? 'admin' : 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) return res.render('register', { error: '註冊失敗，請稍後再試。' });
                getUserUploadRoot(username); // 註冊時創建用戶目錄
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

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

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// 修改密碼
app.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change-password', { user: req.session.user, message: null, messageType: null });
});
app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error' });
    }
    if (newPassword !== confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error' });
    }

    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user || !bcrypt.compareSync(currentPassword, user.password)) {
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error' });
        }
        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error' });
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success' });
        });
    });
});

// 文件瀏覽
app.get('/files', isAuthenticated, async (req, res) => {
    try {
        const username = req.session.user.username;
        const relativeQueryPath = req.query.path || '/'; // 用戶請求的相對路徑
        const currentFullPath = resolveUserPath(username, relativeQueryPath); // 解析為絕對安全路徑

        const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
        const items = dirEntries.map(entry => {
            const itemPath = path.join(relativeQueryPath, entry.name); // 保持相對路徑用於前端
            return {
                name: entry.name,
                isDir: entry.isDirectory(),
                path: itemPath, // 相對於用戶根目錄的路徑
                encodedName: encodeURIComponent(entry.name), // 用於重命名表單ID
                encodedPath: encodeURIComponent(itemPath) // 用於鏈接
            };
        }).sort((a,b) => { // 文件夾優先，然後按名稱排序
            if (a.isDir && !b.isDir) return -1;
            if (!a.isDir && b.isDir) return 1;
            return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
        });

        res.render('files', {
            user: req.session.user,
            items: items,
            currentPath: relativeQueryPath, // 將相對路徑傳遞給視圖
            message: req.query.message,
            messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${req.session.user.username}] 瀏覽文件夾錯誤 at path ${req.query.path || '/'}:`, err);
        // 根據錯誤類型給出更友好的提示
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT') friendlyMessage = '指定的路徑不存在。';
        else if (err.message === '試圖訪問無效路徑！') friendlyMessage = '無權訪問指定路徑。';
        res.redirect(`/files?message=${encodeURIComponent(friendlyMessage)}&messageType=error`);
    }
});

// 創建文件夾
app.post('/create-folder', isAuthenticated, async (req, res) => {
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const username = req.session.user.username;
    let redirectPath = relativeCurrentPath || '/';

    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\')) {
        return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}&message=無效的文件夾名稱。&messageType=error`);
    }
    try {
        const fullPathToCreate = resolveUserPath(username, path.join(relativeCurrentPath, folderName));
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?path=${encodeURIComponent(redirectPath)}&message=文件夾 "${folderName}" 已存在。&messageType=error`);
        }
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}&message=文件夾 "${folderName}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${username}] 創建文件夾錯誤:`, err);
        res.redirect(`/files?path=${encodeURIComponent(redirectPath)}&message=創建文件夾失敗。&messageType=error`);
    }
});

// 重命名文件/文件夾
app.post('/rename', isAuthenticated, async (req, res) => {
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath, isDir } = req.body;
    const username = req.session.user.username;
    let redirectPathQuery = relativeCurrentPath ? `?path=${encodeURIComponent(relativeCurrentPath)}&` : '?';


    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\')) {
        return res.redirect(`/files${redirectPathQuery}message=無效的新名稱。&messageType=error`);
    }
    if (!relativeOldPath) {
         return res.redirect(`/files${redirectPathQuery}message=未提供原始路徑。&messageType=error`);
    }

    try {
        const fullOldPath = resolveUserPath(username, relativeOldPath);
        const parentDirOfOld = path.dirname(relativeOldPath); // 獲取舊文件/文件夾的父目錄的相對路徑
        const fullNewPath = resolveUserPath(username, path.join(parentDirOfOld, newName));

        if (!fs.existsSync(fullOldPath)) {
            return res.redirect(`/files${redirectPathQuery}message=原始文件或文件夾未找到。&messageType=error`);
        }
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) { // 允許大小寫重命名
            return res.redirect(`/files${redirectPathQuery}message=名稱 "${newName}" 已存在。&messageType=error`);
        }

        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files${redirectPathQuery}message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${username}] 重命名錯誤:`, err);
        res.redirect(`/files${redirectPathQuery}message=重命名失敗。&messageType=error`);
    }
});


// 文件上傳
app.post('/upload', isAuthenticated, upload.array('userFiles', 10), (req, res) => {
    const currentPath = req.body.currentPath || '/';
    if (!req.files || req.files.length === 0) {
        return res.redirect(`/files?path=${encodeURIComponent(currentPath)}&message=沒有選擇文件。&messageType=error`);
    }
    res.redirect(`/files?path=${encodeURIComponent(currentPath)}&message=文件上傳成功。&messageType=success`);
});

// 文件下載
app.get('/download', isAuthenticated, (req, res) => {
    const username = req.session.user.username;
    const relativeFilePath = req.query.path;

    if (!relativeFilePath) {
        return res.status(400).render('error', { user: req.session.user, message: '未指定下載文件路徑。' });
    }

    try {
        const fullFilePath = resolveUserPath(username, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) {
                    console.error(`[${username}] 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) {
                        res.status(500).render('error', { user: req.session.user, message: '下載文件時發生內部錯誤。' });
                    }
                }
            });
        } else {
            res.status(404).render('error', { user: req.session.user, message: '文件未找到或不是一個有效文件。' });
        }
    } catch (err) {
        console.error(`[${username}] 準備下載 ${relativeFilePath} 時出錯:`, err);
        res.status(500).render('error', { user: req.session.user, message: '處理下載請求時出錯。' });
    }
});

// 刪除文件或文件夾
app.get('/delete', isAuthenticated, async (req, res) => {
    const username = req.session.user.username;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true'; // 來自查詢參數

    if (!relativeItemPath) {
        return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);
    }

    // 從項目路徑中提取父路徑，用於重定向
    const parentRelativePath = path.dirname(relativeItemPath);
    const redirectQuery = parentRelativePath === '.' || parentRelativePath === '/' ? '' : `?path=${encodeURIComponent(parentRelativePath)}`;


    try {
        const fullItemPath = resolveUserPath(username, relativeItemPath);
        if (!fs.existsSync(fullItemPath)) {
            return res.redirect(`/files${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);
        }

        if (isDir) {
            await fsp.rm(fullItemPath, { recursive: true, force: true });
        } else {
            await fsp.unlink(fullItemPath);
        }
        res.redirect(`/files${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${username}] 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files${redirectQuery}&message=刪除項目失敗。&messageType=error`);
    }
});

// 編輯文本文件 - 顯示頁面
app.get('/edit', isAuthenticated, async (req, res) => {
    const username = req.session.user.username;
    const relativeFilePath = req.query.path;

    if (!relativeFilePath) {
        return res.status(400).render('error', { user: req.session.user, message: '未指定編輯文件路徑。' });
    }
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();

    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('error', { user: req.session.user, message: `不支援編輯此文件類型 (${fileExt})。`});
    }

    try {
        const fullFilePath = resolveUserPath(username, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            const content = await fsp.readFile(fullFilePath, 'utf8');
            res.render('edit-file', { // 確保您有 views/edit-file.ejs
                user: req.session.user,
                filename: filename,
                content: content,
                currentPath: relativeFilePath, // 將完整相對路徑傳遞給保存操作
                message: req.query.message,
                messageType: req.query.messageType
            });
        } else {
            res.status(404).render('error', { user: req.session.user, message: '文件未找到。' });
        }
    } catch (err) {
        console.error(`[${username}] 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        res.status(500).render('error', { user: req.session.user, message: '讀取文件內容失敗。' });
    }
});

// 保存編輯後的文本文件
app.post('/save/:encodedPath', isAuthenticated, async (req, res) => { // 使用路徑參數
    const username = req.session.user.username;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath); // 解碼路徑
    const { fileContent } = req.body;
    const filename = path.basename(relativeFilePath);

    const fileExt = path.extname(filename).toLowerCase();
     if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('edit-file', {
            user: req.session.user,
            filename: filename,
            content: fileContent,
            currentPath: relativeFilePath,
            message: `不支援保存此文件類型 (${fileExt})。`,
            messageType: 'error'
        });
    }

    try {
        const fullFilePath = resolveUserPath(username, relativeFilePath);
        // 再次檢查路徑安全性，雖然 resolveUserPath 已經做了一層
        if (!fs.existsSync(path.dirname(fullFilePath))) {
             return res.status(400).render('edit-file', { user: req.session.user, filename: filename, content: fileContent, currentPath: relativeFilePath, message: '保存路徑無效。', messageType: 'error' });
        }

        await fsp.writeFile(fullFilePath, fileContent, 'utf8');
        // 重定向到文件所在的目錄
        const parentDir = path.dirname(relativeFilePath);
        res.redirect(`/files?path=${encodeURIComponent(parentDir)}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${username}] 保存文件 ${relativeFilePath} 錯誤:`, err);
        res.status(500).render('edit-file', {
            user: req.session.user,
            filename: filename,
            content: fileContent,
            currentPath: relativeFilePath,
            message: '保存文件失敗。',
            messageType: 'error'
        });
    }
});


// 管理員功能
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。' });
        res.render('admin', { users, currentUser: req.session.user, message: req.query.message, messageType: req.query.messageType });
    });
});

// 管理員重置用戶密碼
app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;

    if (req.session.user.id === userIdToReset) {
        return res.redirect('/admin?message=不能重置自己的密碼。&messageType=error');
    }
    if (!newPassword || newPassword.length < 6) { // 簡單的密碼策略
        return res.redirect(`/admin?message=新密碼至少需要6位。&messageType=error`);
    }

    const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userIdToReset], function(err) {
        if (err || this.changes === 0) {
            return res.redirect('/admin?message=重置密碼失敗。&messageType=error');
        }
        db.get("SELECT username FROM users WHERE id = ?", [userIdToReset], (err, targetUser) => {
            const targetUsername = targetUser ? targetUser.username : `ID ${userIdToReset}`;
            res.redirect(`/admin?message=用戶 ${targetUsername} 的密碼已成功重置。&messageType=success`);
        });
    });
});

// 管理員刪除用戶 (與之前版本類似，但確保消息和重定向正確)
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    if (req.session.user.id === userIdToDelete) return res.redirect('/admin?message=不能刪除自己。&messageType=error');

    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, user) => {
        if (err || !user) return res.redirect('/admin?message=未找到用戶。&messageType=error');
        const userDirToDelete = resolveUserPath(user.username); // 獲取用戶文件夾的完整路徑

        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function(err) {
            if (err) return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');
            if (this.changes > 0) {
                try {
                    if (fs.existsSync(userDirToDelete)) {
                        await fsp.rm(userDirToDelete, { recursive: true, force: true });
                    }
                    res.redirect(`/admin?message=用戶 ${user.username} 及其文件已刪除。&messageType=success`);
                } catch (fsErr) {
                    console.error(`刪除用戶 ${user.username} 文件夾錯誤:`, fsErr);
                    res.redirect(`/admin?message=用戶 ${user.username} 已刪除，但其文件夾刪除失敗。&messageType=error`);
                }
            } else {
                res.redirect('/admin?message=未找到用戶或刪除失敗。&messageType=error');
            }
        });
    });
});


// 404 和全局錯誤處理
app.use((req, res, next) => {
    res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。' });
});
app.use((err, req, res, next) => {
    console.error("全局錯誤處理:", req.path, err); // 記錄錯誤路徑和詳細信息
    res.status(err.status || 500).render('error', { user: req.session.user, message: err.message || '伺服器內部錯誤 (500)。' });
});

// 啟動伺服器
app.listen(port, () => {
    console.log(`伺服器運行在 http://localhost:${port}`);
});
process.on('SIGINT', () => db.close(() => process.exit(0)));
