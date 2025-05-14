// server.js (SQLite 版本 - 支持批量操作和移动)
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = process.env.PORT || 8100;

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_strong_and_unique_secret_key_v7_batch_move'; // 强烈建议从环境变量读取

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
app.use(express.json()); // For parsing application/json in POST requests (like /move-items)
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' }
}));
// 示例: 如果要使用 csurf 进行 CSRF 保护
// const csrf = require('csurf');
// app.use(csrf());
// app.use((req, res, next) => {
//     res.locals.csrfToken = req.csrfToken ? req.csrfToken() : null; // Make CSRF token available to templates
//     next();
// });


// --- 輔助函數 ---
function getUserUploadRoot(username) {
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

function resolvePathForUser(usernameForPath, relativePath = '/') {
    if (typeof usernameForPath !== 'string' || usernameForPath.includes('..') || usernameForPath.includes('/') || usernameForPath.includes('\\')) {
        console.error(`[Security] 無效的目標用戶名嘗試: ${usernameForPath}`);
        throw new Error('無效的目標用戶名。');
    }
    const userRoot = getUserUploadRoot(usernameForPath);
    const normalizedRelativePath = path.posix.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
    const requestedPath = path.join(userRoot, normalizedRelativePath);

    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        console.error(`[Security] 試圖訪問無效路徑！用戶根目錄: ${userRoot}, 請求路徑: ${requestedPath}, 解析後: ${path.resolve(requestedPath)}`);
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
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
            if (entry.isFile()) {
                if (entry.name.toLowerCase().includes(lowerCaseKeyword)) {
                    foundItems.push({
                        name: entry.name, isDir: false, path: entryRelativePath,
                        encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(entryRelativePath)
                    });
                }
            } else if (entry.isDirectory()) {
                const subDirectoryItems = await searchFilesRecursively(entryAbsolutePath, keyword, entryRelativePath, userUploadRoot);
                foundItems = foundItems.concat(subDirectoryItems);
            }
        }
    } catch (err) { console.error(`[Search] 讀取目錄 ${directoryToSearch} 時發生錯誤:`, err.message); }
    return foundItems;
}

/**
 * 递归获取目录树 (仅文件夹)
 * @param {string} directoryToScan - 要扫描的绝对路径
 * @param {string} userUploadRoot - 用户上传根目录的绝对路径
 * @param {string} currentRelativePath - 当前的相对路径
 * @param {string[]} pathsToExclude - 需要从树中排除的路径 (及其子路径)
 * @returns {Promise<Array<Object>>} - 目录结构数组
 */
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
                const entryRelativePath = path.posix.join(currentRelativePath, entry.name);
                // 检查此目录是否应被排除 (例如，它是正在移动的文件夹之一)
                if (pathsToExclude.some(excludePath => entryRelativePath === excludePath || entryRelativePath.startsWith(excludePath + '/'))) {
                    continue;
                }

                const children = await getDirectoryTreeRecursive(
                    path.join(directoryToScan, entry.name),
                    userUploadRoot,
                    entryRelativePath,
                    pathsToExclude
                );
                tree.push({
                    name: entry.name,
                    path: entryRelativePath, // 相对于用户根目录的路径
                    children: children
                });
            }
        }
    } catch (err) {
        console.error(`[DirTree] 讀取目錄 ${directoryToScan} 時發生錯誤:`, err.message);
    }
    return tree.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
}


// --- Multer 設置 ---
const storage = multer.diskStorage({ /* ... (与上一版本相同) ... */
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
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        const safeFilename = path.basename(file.originalname);
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage, /* ... (与上一版本相同) ... */
    fileFilter: (req, file, cb) => {
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 100 * 1024 * 1024 }
});

// --- 認證中間件 ---
function isAuthenticated(req, res, next) { /* ... (与上一版本相同) ... */
    if (req.session.user) return next();
    res.redirect('/login');
}
function isAdmin(req, res, next) { /* ... (与上一版本相同) ... */
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).render('error', { user: req.session.user, message: '禁止訪問：僅限管理員。' });
}

// --- 路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

// 用戶註冊 (与上一版本相同, 移除了密码长度限制)
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
            if (err) { console.error("註冊時查詢用戶總數錯誤:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。', csrfToken: res.locals.csrfToken });}
            const hashedPassword = bcrypt.hashSync(password, 12);
            const userRole = countRow.count === 0 ? 'admin' : 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) { console.error("註冊時插入用戶錯誤:", err); return res.render('register', { error: '註冊失敗，請稍後再試。', csrfToken: res.locals.csrfToken }); }
                getUserUploadRoot(username);
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

// 用戶登錄 (与上一版本相同)
app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message, csrfToken: res.locals.csrfToken }));
app.post('/login', (req, res) => { /* ... (与上一版本相同) ... */
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            console.error("登錄時查詢用戶錯誤:", err);
            return res.render('login', { error: '登錄錯誤，請稍後再試。', csrfToken: res.locals.csrfToken });
        }
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。', csrfToken: res.locals.csrfToken });
        }
    });
});

app.get('/logout', (req, res) => { /* ... (与上一版本相同) ... */
    req.session.destroy((err) => {
        if (err) {
            console.error("登出時銷毀 session 錯誤:", err);
        }
        res.redirect('/login');
    });
});

// 修改密碼 (与上一版本相同, 移除了密码长度限制)
app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null, csrfToken: res.locals.csrfToken }));
app.post('/change-password', isAuthenticated, (req, res) => { /* ... (与上一版本相同) ... */
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error', csrfToken: res.locals.csrfToken });
    }
    if (newPassword !== confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error', csrfToken: res.locals.csrfToken });
    }
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, userRow) => {
        if (err || !userRow || !bcrypt.compareSync(currentPassword, userRow.password)) {
            if(err) console.error("修改密碼時查詢用戶錯誤:", err);
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error', csrfToken: res.locals.csrfToken });
        }
        const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) {
                console.error("修改密碼時更新數據庫錯誤:", err);
                return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error', csrfToken: res.locals.csrfToken });
            }
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success', csrfToken: res.locals.csrfToken });
        });
    });
});

// --- 文件瀏覽 (与上一版本相同) ---
app.get('/files', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const actingUser = req.session.user;
    const relativeQueryPath = req.query.path || '/';
    const searchQuery = req.query.q ? req.query.q.trim() : null;

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
            return res.redirect(`/files?message=目標用戶 ${encodeURIComponent(req.query.targetUsername)} 不存在。&messageType=error`);
        }
    }

    try {
        const userUploadRootPath = getUserUploadRoot(targetUsernameForView);
        let items = [];
        let pageTitle = `${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件`;
        let isSearchResultView = false;
        let currentDisplayPath = relativeQueryPath;

        if (searchQuery) {
            isSearchResultView = true;
            items = await searchFilesRecursively(userUploadRootPath, searchQuery, '/', userUploadRootPath);
            currentDisplayPath = '/';
            pageTitle = `有關 "${searchQuery}" 的搜尋結果 (在 ${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件中)`;
            items.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
        } else {
            const currentFullPath = resolvePathForUser(targetUsernameForView, relativeQueryPath);
            const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
            items = dirEntries.map(entry => {
                const itemPath = path.posix.join(relativeQueryPath, entry.name);
                return {
                    name: entry.name, isDir: entry.isDirectory(), path: itemPath,
                    encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(itemPath)
                };
            }).sort((a, b) => {
                if (a.isDir && !b.isDir) return -1; if (!a.isDir && b.isDir) return 1;
                return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
            });
        }
        res.render('files', {
            user: actingUser, viewTargetUsername: viewAsAdminContext ? targetUsernameForView : null,
            items: items, currentPath: currentDisplayPath, searchQuery: searchQuery,
            isSearchResult: isSearchResultView, pageTitle: pageTitle,
            ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS, csrfToken: res.locals.csrfToken,
            message: req.query.message, messageType: req.query.messageType
        });
    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${targetUsernameForView} 的文件夾 ${searchQuery ? `(搜索: ${searchQuery})` : relativeQueryPath} 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT' && !searchQuery) friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑')) friendlyMessage = '無權訪問指定路徑。';
        const baseRedirect = '/files';
        let redirectParams = [];
        if (viewAsAdminContext) redirectParams.push(`targetUsername=${encodeURIComponent(targetUsernameForView)}`);
        if (searchQuery) { redirectParams.push(`q=${encodeURIComponent(searchQuery)}`); }
        else if (relativeQueryPath !== '/') {
            const parentPath = path.posix.dirname(relativeQueryPath);
            if (parentPath !== '.' && parentPath !== '/') { redirectParams.push(`path=${encodeURIComponent(parentPath)}`);}
        }
        redirectParams.push(`message=${encodeURIComponent(friendlyMessage)}`, `messageType=error`);
        res.redirect(`${baseRedirect}?${redirectParams.join('&')}`);
    }
});

// 文件上傳處理 (POST /upload) (与上一版本相同)
app.post('/upload', isAuthenticated, (req, res, next) => { /* ... (与上一版本相同) ... */
    upload.array('userFiles', 10)(req, res, (err) => {
        if (err) {
            console.error(`[${req.session.user.username}] Multer 上傳錯誤:`, err.message);
            const currentPath = req.body.currentPath || '/';
            const adminQuery = (req.session.user.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
            const redirectPath = `/files?path=${encodeURIComponent(currentPath)}${adminQuery}`;
            return res.redirect(`${redirectPath}&message=${encodeURIComponent(err.message)}&messageType=error`);
        }
        const currentPath = req.body.currentPath || '/';
        const adminQuery = (req.session.user.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        const redirectPath = `/files?path=${encodeURIComponent(currentPath)}${adminQuery}`;
        if (!req.files || req.files.length === 0) {
            return res.redirect(`${redirectPath}&message=沒有選擇文件。&messageType=error`);
        }
        res.redirect(`${redirectPath}&message=文件上傳成功。&messageType=success`);
    });
});

// 創建文件夾 (与上一版本相同)
app.post('/create-folder', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\') || folderName.length > 100 || !/^[^\/\\]+$/.test(folderName)) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的文件夾名稱。&messageType=error`);
    }
    try {
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, folderName));
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${folderName}" 已存在。&messageType=error`);
        }
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${folderName}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文件夾錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=創建文件夾失敗。&messageType=error`);
    }
});

// 重命名文件/文件夾 (与上一版本相同)
app.post('/rename', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255 || !/^[^\/\\]+$/.test(newName)) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱。&messageType=error`);
    }
    if (!relativeOldPath) { return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`); }
    try {
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        const parentDirOfOld = path.posix.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.posix.join(parentDirOfOld, newName));
        if (!fs.existsSync(fullOldPath)) { return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`); }
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) {
            return res.redirect(`/files?${redirectPathQuery}&message=名稱 "${newName}" 已存在。&messageType=error`);
        }
        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗。&messageType=error`);
    }
});

// 文件下載 (与上一版本相同)
app.get('/download', isAuthenticated, (req, res) => { /* ... (与上一版本相同) ... */
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) { return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。' });}
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) {
                    console.error(`[${actingUser.username}] 為 ${targetUsername} 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) { res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。' });}
                }
            });
        } else { res.status(404).render('error', { user: actingUser, message: '文件未找到或不是一個有效文件。' });}
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 準備下載 ${relativeFilePath} 時出錯:`, err);
        res.status(500).render('error', { user: actingUser, message: '處理下載請求時出錯。' });
    }
});

// 刪除文件或文件夾 (与上一版本相同)
// 注意: 批量删除时，前端会多次调用此接口。更优方案是创建一个批量删除接口。
app.get('/delete', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeItemPath) { return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);}
    const parentRelativePath = path.posix.dirname(relativeItemPath);
    let redirectQuery = (parentRelativePath === '.' || parentRelativePath === '/') ? '' : `path=${encodeURIComponent(parentRelativePath)}`;
    const adminQuery = (actingUser.role === 'admin' && req.query.targetUsername) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (adminQuery) redirectQuery = redirectQuery ? `${redirectQuery}${adminQuery}` : adminQuery.substring(1);
    try {
        const fullItemPath = resolvePathForUser(targetUsername, relativeItemPath);
        if (!fs.existsSync(fullItemPath)) { return res.redirect(`/files?${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);}
        if (isDir) { await fsp.rm(fullItemPath, { recursive: true, force: true }); }
        else { await fsp.unlink(fullItemPath); }
        res.redirect(`/files?${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files?${redirectQuery}&message=刪除項目失敗。&messageType=error`);
    }
});

// 編輯文本文件 - 顯示頁面 (与上一版本相同)
app.get('/edit', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) { return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。' });}
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) { return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。`});}
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            const content = await fsp.readFile(fullFilePath, 'utf8');
            res.render('edit-file', {
                user: actingUser, viewTargetUsername: (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : null,
                filename: filename, content: content, currentPath: relativeFilePath,
                csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
            });
        } else { res.status(404).render('error', { user: actingUser, message: '文件未找到。' });}
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。' });
    }
});

// 保存編輯後的文本文件 (与上一版本相同)
app.post('/save/:encodedPath', isAuthenticated, async (req, res) => { /* ... (与上一版本相同) ... */
    const actingUser = req.session.user;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath);
    const { fileContent } = req.body;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('edit-file', {
            user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
            filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken,
            message: `不支援保存此文件類型 (${fileExt})。`, messageType: 'error'
        });
    }
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        const parentDirOfFile = path.dirname(fullFilePath);
        if (!fs.existsSync(parentDirOfFile)) {
            console.error(`[${actingUser.username}] 尝试保存文件到不存在的父目录: ${parentDirOfFile}`);
            return res.status(400).render('edit-file', {
                user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
                filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken,
                message: '保存路徑無效 (父目錄不存在)。', messageType: 'error'
            });
        }
        await fsp.writeFile(fullFilePath, fileContent, 'utf8');
        const parentDirForRedirect = path.posix.dirname(relativeFilePath) || '/';
        const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        res.redirect(`/files?path=${encodeURIComponent(parentDirForRedirect)}${adminQuery}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 保存文件 ${relativeFilePath} 錯誤:`, err);
        res.status(500).render('edit-file', {
            user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
            filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken,
            message: '保存文件失敗。', messageType: 'error'
        });
    }
});

// --- 新的 API 端点 ---
// 获取目录树 (仅文件夹)
app.get('/api/directories', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    let targetUsernameForTree = actingUser.username;
    if (actingUser.role === 'admin' && req.query.targetUsername) {
        // 验证 targetUsername 是否存在
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT id FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) {
            targetUsernameForTree = req.query.targetUsername;
        } else {
            return res.status(404).json({ success: false, message: '目標用戶不存在。' });
        }
    }

    const userUploadRoot = getUserUploadRoot(targetUsernameForTree);
    // 从查询参数获取要排除的路径 (例如，正在移动的文件夹)
    let pathsToExclude = [];
    if (req.query.excludePaths) { // excludePaths 应该是一个逗号分隔的路径字符串
        pathsToExclude = req.query.excludePaths.split(',').map(p => path.posix.normalize(p));
    }

    try {
        const directoryTree = await getDirectoryTreeRecursive(userUploadRoot, userUploadRoot, '/', pathsToExclude);
        res.json(directoryTree);
    } catch (error) {
        console.error(`[API DirTree] 獲取用戶 ${targetUsernameForTree} 的目錄樹時出錯:`, error);
        res.status(500).json({ success: false, message: '無法獲取目錄列表。' });
    }
});

// 移动文件/文件夹
app.post('/move-items', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { sourcePaths, destinationPath } = req.body; // sourcePaths is an array of relative paths
    let targetUsernameForMove = actingUser.username;

    // 管理员操作其他用户文件的情况
    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const targetUserExists = await new Promise((resolve, reject) => { /* ... (用户存在性检查) ... */
            db.get("SELECT id FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) {
            targetUsernameForMove = req.body.targetUsername;
        } else {
            return res.status(400).json({ success: false, message: '目標用戶不存在。' });
        }
    }

    if (!sourcePaths || !Array.isArray(sourcePaths) || sourcePaths.length === 0 || !destinationPath) {
        return res.status(400).json({ success: false, message: '源路徑和目標路徑為必填項。' });
    }

    try {
        const userUploadRoot = getUserUploadRoot(targetUsernameForMove);
        const fullDestinationPath = resolvePathForUser(targetUsernameForMove, destinationPath);

        // 确保目标路径是一个目录
        const destStat = await fsp.stat(fullDestinationPath).catch(() => null);
        if (!destStat || !destStat.isDirectory()) {
            return res.status(400).json({ success: false, message: '目標路徑不是一個有效的目錄。' });
        }

        let errors = [];
        let successes = 0;

        for (const sourceRelPath of sourcePaths) {
            const fullSourcePath = resolvePathForUser(targetUsernameForMove, sourceRelPath);
            const itemName = path.basename(fullSourcePath);
            const fullNewPath = path.join(fullDestinationPath, itemName);

            // 安全检查: 防止将文件夹移动到自身或其子文件夹中
            if (fs.existsSync(fullSourcePath) && fs.statSync(fullSourcePath).isDirectory()) {
                if (fullNewPath.startsWith(fullSourcePath + path.sep) || fullNewPath === fullSourcePath) {
                    errors.push(`無法將文件夾 "${itemName}" 移動到其自身或其子文件夾中。`);
                    continue;
                }
            }
            
            // 检查目标位置是否已存在同名项
            if (fs.existsSync(fullNewPath)) {
                // 简单策略：如果目标已存在，则报错。可以扩展为重命名或覆盖。
                errors.push(`目標位置已存在同名項目 "${itemName}"。`);
                continue;
            }

            try {
                await fsp.rename(fullSourcePath, fullNewPath);
                successes++;
            } catch (moveError) {
                console.error(`[Move] 移動項目 "${sourceRelPath}" 到 "${destinationPath}" 失敗:`, moveError);
                errors.push(`移動 "${itemName}" 失敗: ${moveError.message}`);
            }
        }

        if (errors.length > 0) {
            const message = `移動操作部分完成。成功 ${successes} 項。錯誤: ${errors.join('; ')}`;
            // 根据成功数量决定状态码
            return res.status(successes > 0 ? 207 : 500).json({ success: successes > 0, message: message, errors: errors });
        }

        res.json({ success: true, message: `成功移動 ${successes} 個項目。` });

    } catch (error) {
        console.error(`[Move API] 移動項目時發生錯誤:`, error);
        res.status(500).json({ success: false, message: error.message || '移動項目時發生內部伺服器錯誤。' });
    }
});


// 管理員功能 (与上一版本相同, 移除了密码长度限制)
app.get('/admin', isAuthenticated, isAdmin, (req, res) => { /* ... (与上一版本相同) ... */
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) { console.error("獲取用戶列表錯誤:", err); return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。' });}
        res.render('admin', {
            users, currentUser: req.session.user, csrfToken: res.locals.csrfToken,
            message: req.query.message, messageType: req.query.messageType
        });
    });
});
app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => { /* ... (与上一版本相同) ... */
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;
    if (isNaN(userIdToReset)) { return res.redirect('/admin?message=無效的用戶ID。&messageType=error');}
    if (req.session.user.id === userIdToReset) { return res.redirect('/admin?message=不能重置自己的密碼。&messageType=error');}
    if (!newPassword) { return res.redirect(`/admin?message=新密碼不能為空。&messageType=error`);} // 只检查是否为空
    const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userIdToReset], function (err) {
        if (err || this.changes === 0) {
            if(err) console.error("管理員重置密碼錯誤:", err);
            return res.redirect('/admin?message=重置密碼失敗。&messageType=error');
        }
        db.get("SELECT username FROM users WHERE id = ?", [userIdToReset], (err, targetUser) => {
            if(err) console.error("管理員重置密碼後查詢用戶名錯誤:", err);
            res.redirect(`/admin?message=用戶 ${targetUser ? targetUser.username : `ID ${userIdToReset}`} 的密碼已成功重置。&messageType=success`);
        });
    });
});
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => { /* ... (与上一版本相同) ... */
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) { return res.redirect('/admin?message=無效的用戶ID。&messageType=error');}
    if (req.session.user.id === userIdToDelete) { return res.redirect('/admin?message=不能刪除自己。&messageType=error');}
    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, user) => {
        if (err || !user) {
            if(err) console.error("管理員刪除用戶時查詢用戶錯誤:", err);
            return res.redirect('/admin?message=未找到用戶。&messageType=error');
        }
        const userDirToDelete = getUserUploadRoot(user.username);
        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function (err) {
            if (err) { console.error("管理員刪除用戶時數據庫錯誤:", err); return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');}
            if (this.changes > 0) {
                try {
                    if (fs.existsSync(userDirToDelete)) { await fsp.rm(userDirToDelete, { recursive: true, force: true });}
                    res.redirect(`/admin?message=用戶 ${user.username} 及其文件已刪除。&messageType=success`);
                } catch (fsErr) {
                    console.error(`刪除用戶 ${user.username} 文件夾錯誤:`, fsErr);
                    res.redirect(`/admin?message=用戶 ${user.username} 已刪除，但其文件夾刪除失敗。&messageType=warning`);
                }
            } else { res.redirect('/admin?message=未找到用戶或刪除失敗。&messageType=error');}
        });
    });
});

// 404 和全局錯誤處理 (与上一版本相同)
app.use((req, res, next) => { /* ... (与上一版本相同) ... */
    res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。' });
});
app.use((err, req, res, next) => { /* ... (与上一版本相同) ... */
    const usernameForLog = req.session.user ? req.session.user.username : '未認證用戶';
    console.error(`[${usernameForLog}] 全局錯誤處理: ${req.method} ${req.originalUrl}`, err.stack || err);
    let publicMessage = '伺服器內部錯誤 (500)。';
    if (process.env.NODE_ENV !== 'production' && err.message) { publicMessage = err.message; }
    if (err.publicMessage) { publicMessage = err.publicMessage; }
    if (res.headersSent) { return next(err); }
    res.status(err.status || 500).render('error', { user: req.session.user, message: publicMessage });
});

app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));

process.on('SIGINT', () => { /* ... (与上一版本相同) ... */
    console.log('收到 SIGINT 信號，正在關閉伺服器...');
    db.close((err) => {
        if (err) { console.error('關閉 SQLite 資料庫時出錯:', err.message); process.exit(1);}
        console.log('SQLite 資料庫已關閉。');
        process.exit(0);
    });
});
