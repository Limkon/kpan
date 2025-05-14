// server.js (SQLite 版本 - 包含搜索功能)
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8100; // 建议从环境变量读取: process.env.PORT || 8100

// --- 常量定義 ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_strong_and_unique_secret_key_v6_final_final_SEARCH_UPDATE'; // 强烈建议从环境变量读取

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
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' } // 在生产环境中应设 secure: true (需要HTTPS)
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
    if (typeof usernameForPath !== 'string' || usernameForPath.includes('..') || usernameForPath.includes('/') || usernameForPath.includes('\\')) {
        console.error(`[Security] 無效的目標用戶名嘗試: ${usernameForPath}`);
        throw new Error('無效的目標用戶名。');
    }
    const userRoot = getUserUploadRoot(usernameForPath);
    // 使用 path.posix.normalize 来处理路径，因为它能更好地处理混合斜杠并标准化为 /
    // 然后再用 path.join 确保与操作系统兼容，但要注意相对路径的意图
    const normalizedRelativePath = path.posix.normalize(relativePath).replace(/^(\.\.[/\\])+/, ''); // 防止路径逃逸
    const requestedPath = path.join(userRoot, normalizedRelativePath);

    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        console.error(`[Security] 試圖訪問無效路徑！用戶根目錄: ${userRoot}, 請求路徑: ${requestedPath}, 解析後: ${path.resolve(requestedPath)}`);
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

/**
 * 递归地在用户目录中搜索文件。
 * @param {string} directoryToSearch - 开始搜索的目录的绝对路径。
 * @param {string} keyword - 要在文件名中搜索的关键字。
 * @param {string} currentRelativePath - 当前相对于用户根目录的路径 (用于构建结果中的路径)。
 * @param {string} userUploadRoot - 用户根上传目录的绝对路径 (用于安全检查和路径构建)。
 * @returns {Promise<Array<Object>>} - 一个解析为找到的文件对象数组的 Promise。
 */
async function searchFilesRecursively(directoryToSearch, keyword, currentRelativePath = '/', userUploadRoot) {
    let foundItems = [];
    const lowerCaseKeyword = keyword.toLowerCase();

    try {
        // 确保搜索不会超出用户根目录 (尽管初始调用应该由 resolvePathForUser 保证)
        if (!path.resolve(directoryToSearch).startsWith(path.resolve(userUploadRoot))) {
             console.warn(`[Security] 搜索尝试超出用户允许的目录: ${directoryToSearch}`);
             return []; // 或者抛出错误
        }

        const entries = await fsp.readdir(directoryToSearch, { withFileTypes: true });

        for (const entry of entries) {
            const entryAbsolutePath = path.join(directoryToSearch, entry.name);
            // 使用 path.posix.join 来确保相对路径使用 / 分隔符
            const entryRelativePath = path.posix.join(currentRelativePath, entry.name);

            if (entry.isFile()) {
                if (entry.name.toLowerCase().includes(lowerCaseKeyword)) {
                    foundItems.push({
                        name: entry.name,
                        isDir: false,
                        path: entryRelativePath, // 相对于用户根目录的完整路径
                        encodedName: encodeURIComponent(entry.name),
                        encodedPath: encodeURIComponent(entryRelativePath)
                    });
                }
            } else if (entry.isDirectory()) {
                // 递归搜索子目录
                const subDirectoryItems = await searchFilesRecursively(entryAbsolutePath, keyword, entryRelativePath, userUploadRoot);
                foundItems = foundItems.concat(subDirectoryItems);
            }
        }
    } catch (err) {
        // 如果读取某个目录出错 (例如权限问题)，记录错误并继续
        console.error(`[Search] 讀取目錄 ${directoryToSearch} 時發生錯誤:`, err.message);
        // 可以选择不中断整个搜索，只跳过此目录
    }
    return foundItems;
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
            console.error(`[${actingUsername}] Multer destination error for target ${targetUsername}:`, err);
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        // 避免文件名包含路径字符，并进行UTF-8处理
        const safeFilename = path.basename(file.originalname);
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // 再次检查文件名，防止恶意输入
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 100 * 1024 * 1024 } // 例如：限制文件大小为100MB
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

// --- 路由 ---
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

// 用戶註冊
app.get('/register', (req, res) => res.render('register', { error: null, csrfToken: req.csrfToken && req.csrfToken() })); // 假设使用了 csurf
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。', csrfToken: req.csrfToken && req.csrfToken() });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。', csrfToken: req.csrfToken && req.csrfToken() });
    if (username.includes('/') || username.includes('..') || username.includes('\\') || username.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return res.render('register', { error: '用戶名包含無效字符、過長或格式不正確。', csrfToken: req.csrfToken && req.csrfToken() });
    }
    // 增加密码强度校验 (示例)
    if (password.length < 8) {
        return res.render('register', { error: '密碼長度至少需要8位。', csrfToken: req.csrfToken && req.csrfToken() });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) {
            console.error("註冊時查詢用戶錯誤:", err);
            return res.render('register', { error: '註冊錯誤，請稍後再試。', csrfToken: req.csrfToken && req.csrfToken() });
        }
        if (row) return res.render('register', { error: '用戶名已存在。', csrfToken: req.csrfToken && req.csrfToken() });

        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) {
                console.error("註冊時查詢用戶總數錯誤:", err);
                return res.render('register', { error: '註冊錯誤，請稍後再試。', csrfToken: req.csrfToken && req.csrfToken() });
            }
            const hashedPassword = bcrypt.hashSync(password, 12); // 增加 salt rounds
            const userRole = countRow.count === 0 ? 'admin' : 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) {
                    console.error("註冊時插入用戶錯誤:", err);
                    return res.render('register', { error: '註冊失敗，請稍後再試。', csrfToken: req.csrfToken && req.csrfToken() });
                }
                getUserUploadRoot(username); // 确保用户目录被创建
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

// 用戶登錄
app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message, csrfToken: req.csrfToken && req.csrfToken() }));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            console.error("登錄時查詢用戶錯誤:", err);
            return res.render('login', { error: '登錄錯誤，請稍後再試。', csrfToken: req.csrfToken && req.csrfToken() });
        }
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。', csrfToken: req.csrfToken && req.csrfToken() });
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("登出時銷毀 session 錯誤:", err);
            // 即使销毁失败，也尝试重定向
        }
        res.redirect('/login');
    });
});

// 修改密碼
app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null, csrfToken: req.csrfToken && req.csrfToken() }));
app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error', csrfToken: req.csrfToken && req.csrfToken() });
    }
    if (newPassword !== confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配。', messageType: 'error', csrfToken: req.csrfToken && req.csrfToken() });
    }
    if (newPassword.length < 8) { // 增加密码强度校验
        return res.render('change-password', { user: req.session.user, message: '新密碼長度至少需要8位。', messageType: 'error', csrfToken: req.csrfToken && req.csrfToken() });
    }

    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, userRow) => {
        if (err || !userRow || !bcrypt.compareSync(currentPassword, userRow.password)) {
            if(err) console.error("修改密碼時查詢用戶錯誤:", err);
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error', csrfToken: req.csrfToken && req.csrfToken() });
        }
        const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) {
                console.error("修改密碼時更新數據庫錯誤:", err);
                return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error', csrfToken: req.csrfToken && req.csrfToken() });
            }
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success', csrfToken: req.csrfToken && req.csrfToken() });
        });
    });
});

// --- 文件瀏覽 (修改后支持搜索) ---
app.get('/files', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeQueryPath = req.query.path || '/'; // 正常浏览时的路径
    const searchQuery = req.query.q ? req.query.q.trim() : null; // 获取搜索关键字

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
        const userUploadRootPath = getUserUploadRoot(targetUsernameForView); // 获取用户的绝对根上传目录

        let items = [];
        let pageTitle = `${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件`;
        let isSearchResultView = false;
        let currentDisplayPath = relativeQueryPath; // 用于面包屑和表单的路径

        if (searchQuery) {
            isSearchResultView = true;
            items = await searchFilesRecursively(userUploadRootPath, searchQuery, '/', userUploadRootPath);
            currentDisplayPath = '/'; // 搜索结果的 "当前路径" 设为根，因为结果来自各处
            pageTitle = `有關 "${searchQuery}" 的搜尋結果 (在 ${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件中)`;
            items.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
        } else {
            const currentFullPath = resolvePathForUser(targetUsernameForView, relativeQueryPath);
            const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
            items = dirEntries.map(entry => {
                const itemPath = path.posix.join(relativeQueryPath, entry.name);
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
        }

        res.render('files', {
            user: actingUser,
            viewTargetUsername: viewAsAdminContext ? targetUsernameForView : null,
            items: items,
            currentPath: currentDisplayPath,
            searchQuery: searchQuery,
            isSearchResult: isSearchResultView,
            pageTitle: pageTitle,
            ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS, // 传递给模板
            csrfToken: req.csrfToken && req.csrfToken(), // 传递 CSRF token
            message: req.query.message,
            messageType: req.query.messageType
        });

    } catch (err) {
        console.error(`[${actingUser.username}] 瀏覽 ${targetUsernameForView} 的文件夾 ${searchQuery ? `(搜索: ${searchQuery})` : relativeQueryPath} 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT' && !searchQuery) friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑')) friendlyMessage = '無權訪問指定路徑。';

        const baseRedirect = '/files';
        let redirectParams = [];
        if (viewAsAdminContext) redirectParams.push(`targetUsername=${encodeURIComponent(targetUsernameForView)}`);
        
        // 如果是搜索出错，不要带 path 参数，但可以带 q 参数
        if (searchQuery) {
            redirectParams.push(`q=${encodeURIComponent(searchQuery)}`);
        } else if (relativeQueryPath !== '/') { // 非搜索错误，且不在根目录
            const parentPath = path.posix.dirname(relativeQueryPath); // 使用 posix.dirname
            if (parentPath !== '.' && parentPath !== '/') {
                 redirectParams.push(`path=${encodeURIComponent(parentPath)}`);
            }
        }

        redirectParams.push(`message=${encodeURIComponent(friendlyMessage)}`);
        redirectParams.push(`messageType=error`);

        res.redirect(`${baseRedirect}?${redirectParams.join('&')}`);
    }
});


// 文件上傳處理 (POST /upload)
app.post('/upload', isAuthenticated, (req, res, next) => {
    upload.array('userFiles', 10)(req, res, (err) => { // 最多同时上传10个文件
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


// 創建文件夾
app.post('/create-folder', isAuthenticated, async (req, res) => {
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1); // 避免开头的&

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

// 重命名文件/文件夾
app.post('/rename', isAuthenticated, async (req, res) => {
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);


    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255 || !/^[^\/\\]+$/.test(newName)) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱。&messageType=error`);
    }
    if (!relativeOldPath) {
        return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`);
    }

    try {
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        // 使用 path.posix.dirname 来获取父目录，确保URL友好
        const parentDirOfOld = path.posix.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.posix.join(parentDirOfOld, newName));

        if (!fs.existsSync(fullOldPath)) {
            return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`);
        }
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

// 文件下載
app.get('/download', isAuthenticated, (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;

    if (!relativeFilePath) {
        return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。' });
    }
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) {
                    console.error(`[${actingUser.username}] 為 ${targetUsername} 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) {
                        res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。' });
                    }
                }
            });
        } else {
            res.status(404).render('error', { user: actingUser, message: '文件未找到或不是一個有效文件。' });
        }
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 準備下載 ${relativeFilePath} 時出錯:`, err);
        res.status(500).render('error', { user: actingUser, message: '處理下載請求時出錯。' });
    }
});

// 刪除文件或文件夾
app.get('/delete', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;

    if (!relativeItemPath) {
        return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);
    }
    // 使用 path.posix.dirname
    const parentRelativePath = path.posix.dirname(relativeItemPath);
    let redirectQuery = (parentRelativePath === '.' || parentRelativePath === '/') ? '' : `path=${encodeURIComponent(parentRelativePath)}`;
    const adminQuery = (actingUser.role === 'admin' && req.query.targetUsername) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (adminQuery) redirectQuery = redirectQuery ? `${redirectQuery}${adminQuery}` : adminQuery.substring(1);

    try {
        const fullItemPath = resolvePathForUser(targetUsername, relativeItemPath);
        if (!fs.existsSync(fullItemPath)) {
            return res.redirect(`/files?${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);
        }
        if (isDir) {
            await fsp.rm(fullItemPath, { recursive: true, force: true });
        } else {
            await fsp.unlink(fullItemPath);
        }
        res.redirect(`/files?${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files?${redirectQuery}&message=刪除項目失敗。&messageType=error`);
    }
});

// 編輯文本文件 - 顯示頁面
app.get('/edit', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;

    if (!relativeFilePath) {
        return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。' });
    }
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();

    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。` });
    }
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            const content = await fsp.readFile(fullFilePath, 'utf8');
            res.render('edit-file', {
                user: actingUser,
                viewTargetUsername: (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : null,
                filename: filename,
                content: content,
                currentPath: relativeFilePath, // 这是相对于用户根目录的路径
                csrfToken: req.csrfToken && req.csrfToken(),
                message: req.query.message,
                messageType: req.query.messageType
            });
        } else {
            res.status(404).render('error', { user: actingUser, message: '文件未找到。' });
        }
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。' });
    }
});

// 保存編輯後的文本文件
app.post('/save/:encodedPath', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = decodeURIComponent(req.params.encodedPath); // 这是相对于用户根目录的路径
    const { fileContent } = req.body;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;

    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();

    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('edit-file', {
            user: actingUser,
            viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
            filename, content: fileContent, currentPath: relativeFilePath,
            csrfToken: req.csrfToken && req.csrfToken(),
            message: `不支援保存此文件類型 (${fileExt})。`, messageType: 'error'
        });
    }
    try {
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        // 确保父目录存在
        const parentDirOfFile = path.dirname(fullFilePath);
        if (!fs.existsSync(parentDirOfFile)) {
             // 如果父目录不存在，这通常是一个错误，因为文件不应该能被创建在不存在的父目录中通过此接口
            console.error(`[${actingUser.username}] 尝试保存文件到不存在的父目录: ${parentDirOfFile}`);
            return res.status(400).render('edit-file', {
                user: actingUser,
                viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
                filename, content: fileContent, currentPath: relativeFilePath,
                csrfToken: req.csrfToken && req.csrfToken(),
                message: '保存路徑無效 (父目錄不存在)。', messageType: 'error'
            });
        }

        await fsp.writeFile(fullFilePath, fileContent, 'utf8');
        // 使用 path.posix.dirname
        const parentDirForRedirect = path.posix.dirname(relativeFilePath) || '/';
        const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
        res.redirect(`/files?path=${encodeURIComponent(parentDirForRedirect)}${adminQuery}&message=文件 "${filename}" 已成功保存。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 保存文件 ${relativeFilePath} 錯誤:`, err);
        res.status(500).render('edit-file', {
            user: actingUser,
            viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
            filename, content: fileContent, currentPath: relativeFilePath,
            csrfToken: req.csrfToken && req.csrfToken(),
            message: '保存文件失敗。', messageType: 'error'
        });
    }
});


// 管理員功能
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) {
            console.error("獲取用戶列表錯誤:", err);
            return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。' });
        }
        res.render('admin', {
            users,
            currentUser: req.session.user,
            csrfToken: req.csrfToken && req.csrfToken(),
            message: req.query.message,
            messageType: req.query.messageType
        });
    });
});

app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;

    if (isNaN(userIdToReset)) {
        return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    }
    if (req.session.user.id === userIdToReset) {
        return res.redirect('/admin?message=不能重置自己的密碼。&messageType=error');
    }
    if (!newPassword || newPassword.length < 8) { // 增加密码强度校验
        return res.redirect(`/admin?message=新密碼不能為空且長度至少8位。&messageType=error`);
    }
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

app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) {
        return res.redirect('/admin?message=無效的用戶ID。&messageType=error');
    }
    if (req.session.user.id === userIdToDelete) {
        return res.redirect('/admin?message=不能刪除自己。&messageType=error');
    }
    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, user) => {
        if (err || !user) {
            if(err) console.error("管理員刪除用戶時查詢用戶錯誤:", err);
            return res.redirect('/admin?message=未找到用戶。&messageType=error');
        }
        const userDirToDelete = getUserUploadRoot(user.username); // 使用 getUserUploadRoot
        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function (err) {
            if (err) {
                console.error("管理員刪除用戶時數據庫錯誤:", err);
                return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');
            }
            if (this.changes > 0) {
                try {
                    if (fs.existsSync(userDirToDelete)) {
                        await fsp.rm(userDirToDelete, { recursive: true, force: true });
                    }
                    res.redirect(`/admin?message=用戶 ${user.username} 及其文件已刪除。&messageType=success`);
                } catch (fsErr) {
                    console.error(`刪除用戶 ${user.username} 文件夾錯誤:`, fsErr);
                    res.redirect(`/admin?message=用戶 ${user.username} 已刪除，但其文件夾刪除失敗。&messageType=warning`); // 改为 warning
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
    const usernameForLog = req.session.user ? req.session.user.username : '未認證用戶';
    console.error(`[${usernameForLog}] 全局錯誤處理: ${req.method} ${req.originalUrl}`, err.stack || err); // 记录堆栈信息
    
    // 避免将敏感的内部错误信息直接暴露给客户端
    let publicMessage = '伺服器內部錯誤 (500)。';
    if (process.env.NODE_ENV !== 'production' && err.message) { // 开发模式下可以显示更详细的错误
        publicMessage = err.message;
    }
    if (err.publicMessage) { // 如果错误对象有自定义的公开消息
        publicMessage = err.publicMessage;
    }

    if (res.headersSent) { // 如果头部已发送，则委托给 Express 的默认错误处理器
        return next(err);
    }

    res.status(err.status || 500).render('error', {
        user: req.session.user,
        message: publicMessage
    });
});

app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));

// 優雅關閉
process.on('SIGINT', () => {
    console.log('收到 SIGINT 信號，正在關閉伺服器...');
    db.close((err) => {
        if (err) {
            console.error('關閉 SQLite 資料庫時出錯:', err.message);
            process.exit(1); // 出错则非正常退出
        }
        console.log('SQLite 資料庫已關閉。');
        process.exit(0); // 正常退出
    });
});
