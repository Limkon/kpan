// server.js (SQLite 版本 - 真正完整版)
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
const port = process.env.PORT || 8100;

// --- 常量定義 ---
// 儲存應用程式數據的目錄
const DATA_DIR = path.join(__dirname, 'data');
// 儲存用戶上傳文件的基礎目錄
const UPLOAD_DIR_BASE = path.join(__dirname, 'uploads');
// SQLite 資料庫文件路徑
const DB_FILE = path.join(DATA_DIR, 'netdisk.sqlite');
// 允許在線預覽和編輯的文本文件擴展名
const ALLOWED_TEXT_EXTENSIONS = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', '.c', '.cpp', '.go', '.rb'];
// Session 密鑰，用於簽署 session ID cookie，生產環境中必須更改
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_very_strong_and_unique_secret_CHANGE_THIS_NOW'; // !!! 強烈建議從環境變數讀取並更改 !!!

// --- 目錄初始化 ---
// 確保數據目錄和上傳基礎目錄存在，如果不存在則創建
[DATA_DIR, UPLOAD_DIR_BASE].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`已自動創建目錄: ${dir}`);
    }
});

// --- SQLite 資料庫設置 ---
// 連接到 SQLite 資料庫
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) { console.error('無法連接到 SQLite 資料庫:', err.message); throw err; }
    console.log('已成功連接到 SQLite 資料庫。');
    // 序列化操作，確保資料庫初始化順序
    db.serialize(() => {
        // 創建 users 表格，如果它不存在的話
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL -- 用戶角色，例如 'user', 'admin'
        )`, (err) => {
            if (err) console.error('創建 users 表格失敗:', err.message);
            else {
                console.log("'users' 表格已準備就緒。");
                // 檢查並創建初始管理員帳戶（如果不存在）
                const initialAdminUsername = 'admin';
                const initialAdminPassword = 'admin'; // !!! 生產環境中請務必更改此密碼 !!!
                db.get("SELECT * FROM users WHERE username = ?", [initialAdminUsername], (err, adminUser) => {
                    if (err) {
                        console.error('检查初始管理员时出错:', err.message);
                        return;
                    }
                    if (!adminUser) {
                        // 哈希管理員密碼並插入到數據庫
                        const hashedPassword = bcrypt.hashSync(initialAdminPassword, 12);
                        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                            [initialAdminUsername, hashedPassword, 'admin'],
                            function (err) {
                                if (err) console.error('创建初始管理员失败:', err.message);
                                else {
                                    console.log(`初始管理员 '${initialAdminUsername}' 已创建。`);
                                    // 為初始管理員創建文件上傳根目錄
                                    getUserUploadRoot(initialAdminUsername);
                                }
                            }
                        );
                    }
                });
            }
        });
    });
});

// --- 中間件設置 ---
// 設置視圖引擎為 EJS
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
// 解析 URL 編碼的請求體
app.use(express.urlencoded({ extended: true }));
// 解析 JSON 格式的請求體
app.use(express.json());
// 設置靜態文件目錄
app.use(express.static(path.join(__dirname, 'public')));
// 配置 session
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // session 存儲是否在每次請求時都重新保存，即使沒有修改
    saveUninitialized: true, // 是否保存未初始化的 session
    cookie: {
        secure: process.env.NODE_ENV === 'production', // 生產環境中使用 HTTPS 時應設置為 true
        httpOnly: true, // 防止客戶端 JavaScript 訪問 cookie
        sameSite: 'lax' // CSRF 保護
    }
}));
// CSRF Protection (Example - uncomment and configure if used)
// const csrf = require('csurf');
// app.use(csrf());
// app.use((req, res, next) => {
//     res.locals.csrfToken = req.csrfToken ? req.csrfToken() : null;
//     next();
// });


// --- 輔助函數 ---
// 獲取用戶特定的文件上傳根目錄，如果不存在則創建
function getUserUploadRoot(username) {
    const userDir = path.join(UPLOAD_DIR_BASE, username);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

// 解析給定用戶的相對路徑，確保不會超出其根目錄（安全檢查）
function resolvePathForUser(usernameForPath, relativePath = '/') {
    // 檢查用戶名是否包含非法字符
    if (typeof usernameForPath !== 'string' || usernameForPath.includes('..') || usernameForPath.includes('/') || usernameForPath.includes('\\')) {
        console.error(`[SecurityResolve] 無效的目標用戶名嘗試: ${usernameForPath}`);
        throw new Error('無效的目標用戶名。');
    }
    // 獲取用戶根目錄
    const userRoot = getUserUploadRoot(usernameForPath);
    // 清理相對路徑中的查詢字符串
    let cleanRelativePath = relativePath;
    if (typeof relativePath === 'string' && relativePath.includes('?')) {
        cleanRelativePath = relativePath.split('?')[0];
    }
    // 規範化相對路徑，移除開頭的 '..' 以防止目錄遍歷攻擊
    const normalizedRelativePath = path.posix.normalize(cleanRelativePath).replace(/^(\.\.([/\\]|$))+/, '');
    // 將用戶根目錄與規範化後的相對路徑結合
    const requestedPath = path.join(userRoot, normalizedRelativePath);

    // 最終安全檢查：確保解析後的路徑確實位於用戶根目錄下
    if (!path.resolve(requestedPath).startsWith(path.resolve(userRoot))) {
        console.error(`[SecurityResolve] 試圖訪問無效路徑！用戶根目錄: ${userRoot}, 請求路徑: ${requestedPath}, 解析後: ${path.resolve(requestedPath)}`);
        throw new Error('試圖訪問無效路徑！');
    }
    return requestedPath;
}

// 遞歸搜索文件
async function searchFilesRecursively(directoryToSearch, keyword, currentRelativePath = '/', userUploadRoot) {
    let foundItems = [];
    const lowerCaseKeyword = keyword.toLowerCase();
    try {
        // 安全檢查：確保搜索目錄在用戶根目錄下
        if (!path.resolve(directoryToSearch).startsWith(path.resolve(userUploadRoot))) {
             console.warn(`[Security] 搜索尝试超出用户允许的目录: ${directoryToSearch}`);
             return [];
        }
        const entries = await fsp.readdir(directoryToSearch, { withFileTypes: true });
        for (const entry of entries) {
            const entryAbsolutePath = path.join(directoryToSearch, entry.name);
            const entryRelativePath = path.posix.join(currentRelativePath, entry.name);
            if (entry.isFile()) {
                // 如果文件名包含關鍵字，則添加到結果中
                if (entry.name.toLowerCase().includes(lowerCaseKeyword)) {
                    foundItems.push({
                        name: entry.name, isDir: false, path: entryRelativePath,
                        encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(entryRelativePath)
                    });
                }
            } else if (entry.isDirectory()) {
                // 排除隱藏文件夾和 node_modules
                if (entry.name.startsWith('.') || entry.name === 'node_modules') {
                    continue;
                }
                // 遞歸搜索子目錄
                const subDirectoryItems = await searchFilesRecursively(entryAbsolutePath, keyword, entryRelativePath, userUploadRoot);
                foundItems = foundItems.concat(subDirectoryItems);
            }
        }
    } catch (err) { console.error(`[Search] 讀取目錄 ${directoryToSearch} 時發生錯誤:`, err.message); }
    return foundItems;
}

// 遞歸獲取目錄樹結構
async function getDirectoryTreeRecursive(directoryToScan, userUploadRoot, currentRelativePath = '/', pathsToExclude = []) {
    let tree = [];
    try {
        // 安全檢查：確保掃描目錄在用戶根目錄下
        if (!path.resolve(directoryToScan).startsWith(path.resolve(userUploadRoot))) {
            console.warn(`[Security] 目录树扫描尝试超出用户允许的目录: ${directoryToScan}`);
            return [];
        }
        const entries = await fsp.readdir(directoryToScan, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                // 排除隱藏文件夾和 node_modules
                if (entry.name.startsWith('.') || entry.name === 'node_modules') {
                    continue;
                }
                const entryRelativePath = path.posix.join(currentRelativePath, entry.name);
                // 排除指定的路徑
                if (pathsToExclude.some(excludePath => entryRelativePath === excludePath || entryRelativePath.startsWith(excludePath + '/'))) {
                    continue;
                }
                // 遞歸獲取子目錄的樹結構
                const children = await getDirectoryTreeRecursive(
                    path.join(directoryToScan, entry.name), userUploadRoot, entryRelativePath, pathsToExclude
                );
                tree.push({ name: entry.name, path: entryRelativePath, children: children });
            }
        }
    } catch (err) { console.error(`[DirTree] 讀取目錄 ${directoryToScan} 時發生錯誤:`, err.message); }
    // 按名稱排序（中文拼音）
    return tree.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
}

// --- Multer 設置 ---
// 配置 Multer 的文件儲存方式
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // --- 新增診斷日誌 ---
        console.log(`[Multer Destination] Inside destination function.`);
        console.log(`[Multer Destination] req.body:`, req.body); // Log req.body inside Multer
        console.log(`[Multer Destination] req.files:`, req.files); // Log req.files inside Multer
        console.log(`[Multer Destination] Received file: ${file.originalname}, webkitRelativePath: ${file.webkitRelativePath}`);
        // --- 診斷日誌結束 ---

        const actingUsername = req.session.user.username;
        // 如果是管理員且指定了目標用戶名，則以上傳到目標用戶的文件夾
        const targetUsername = (req.session.user.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUsername;
        // 獲取當前頁面所在的路徑，作為上傳的基礎路徑
        const baseUploadPath = req.body.currentPath || '/';
        console.log(`[Multer Destination] actingUsername: ${actingUsername}, targetUsername: ${targetUsername}, baseUploadPath: ${baseUploadPath}`);

        let finalDestinationPath = baseUploadPath;

        // 處理文件夾上傳時的相對路徑
        if (file.webkitRelativePath && typeof file.webkitRelativePath === 'string') {
            // file.webkitRelativePath 的格式通常是 "FolderName/SubFolder/file.txt"
            // 我們需要提取文件夾結構部分，不包括文件名
            const relativeFolderPath = path.dirname(file.webkitRelativePath);
            console.log(`[Multer Destination] file.webkitRelativePath: ${file.webkitRelativePath}, parsed relativeFolderPath: ${relativeFolderPath}`);
            if (relativeFolderPath && relativeFolderPath !== '.') {
                // 將相對文件夾路徑與基礎上傳路徑合併
                finalDestinationPath = path.posix.join(baseUploadPath, relativeFolderPath);
            }
        }
        console.log(`[Multer Destination] Calculated finalDestinationPath: ${finalDestinationPath}`);

        try {
            // 解析出用戶根目錄下的完整目標路徑
            const resolvedUploadDir = resolvePathForUser(targetUsername, finalDestinationPath);
            console.log(`[Multer Destination] Resolved upload directory: ${resolvedUploadDir}`);
            // 確保目標路徑存在，如果不存在則遞歸創建
            // 這是保留目錄結構的關鍵一步
            if (!fs.existsSync(resolvedUploadDir)) {
                fs.mkdirSync(resolvedUploadDir, { recursive: true });
                console.log(`[Multer Destination] Created directory: ${resolvedUploadDir}`);
            }
            // 將文件儲存到解析出的目標資料夾
            cb(null, resolvedUploadDir);
        } catch (err) {
            console.error(`[Multer Destination ERROR] For target ${targetUsername} at path ${finalDestinationPath}:`, err);
            return cb(new Error(`上傳目標路徑處理錯誤: ${err.message}`));
        }
    },
    filename: function (req, file, cb) {
        // 對於文件夾上傳，file.originalname 仍然是原始文件名 (不含路徑)
        // Multer 會將 file.webkitRelativePath 的完整路徑（包括資料夾）傳遞給 destination
        // filename 這裡只需要返回最終的文件名即可
        const safeFilename = path.basename(file.originalname);
        console.log(`[Multer Filename] originalname: ${file.originalname}, safeFilename: ${safeFilename}`);
        // 處理文件名編碼問題，確保中文文件名正確
        cb(null, Buffer.from(safeFilename, 'latin1').toString('utf8'));
    }
});
// 配置 Multer 實例
const upload = multer({ storage: storage,
    // 文件過濾器，檢查文件名是否包含非法字符
    fileFilter: (req, file, cb) => {
        if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
            console.warn(`[Multer FileFilter] Invalid characters in filename: ${file.originalname}`);
            return cb(new Error('文件名包含無效字符。'), false);
        }
        cb(null, true);
    },
    // 文件大小限制 (例如 100MB)
    limits: { fileSize: 100 * 1024 * 1024 }
});

// --- 認證中間件 ---
// 檢查用戶是否已登錄
function isAuthenticated(req, res, next) { if (req.session.user) return next(); res.redirect('/login'); }
// 檢查用戶是否為管理員
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).render('error', {
        user: req.session.user,
        message: '禁止訪問：僅限管理員。',
        csrfToken: res.locals.csrfToken
    });
}

// --- 路由 ---
// 根路由，重定向到文件列表或登錄頁面
app.get('/', (req, res) => res.redirect(req.session.user ? '/files' : '/login'));

// 註冊頁面
app.get('/register', (req, res) => res.render('register', { error: null, message: null, csrfToken: res.locals.csrfToken }));
// 處理註冊請求
app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: '所有欄位均為必填項。', message: null, csrfToken: res.locals.csrfToken });
    if (password !== confirmPassword) return res.render('register', { error: '兩次輸入的密碼不匹配。', message: null, csrfToken: res.locals.csrfToken });
    // 用戶名格式和長度檢查
    if (username.includes('/') || username.includes('..') || username.includes('\\') || username.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return res.render('register', { error: '用戶名包含無效字符、過長或格式不正確。', message: null, csrfToken: res.locals.csrfToken });
    }
    // 檢查用戶名是否已存在
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) { console.error("註冊時查詢用戶錯誤:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。', message: null, csrfToken: res.locals.csrfToken }); }
        if (row) return res.render('register', { error: '用戶名已存在。', message: null, csrfToken: res.locals.csrfToken });
        // 獲取用戶總數（這裡似乎沒有直接用途，可能是為了將來限制註冊數）
        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) { console.error("註冊時查詢用戶總數錯誤:", err); return res.render('register', { error: '註冊錯誤，請稍後再試。', message: null, csrfToken: res.locals.csrfToken });}
            // 哈希密碼並插入新用戶到數據庫
            const hashedPassword = bcrypt.hashSync(password, 12);
            const userRole = 'user';
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
                if (err) { console.error("註冊時插入用戶錯誤:", err); return res.render('register', { error: '註冊失敗，請稍後再試。', message: null, csrfToken: res.locals.csrfToken }); }
                // 為新用戶創建文件上傳根目錄
                getUserUploadRoot(username);
                res.redirect('/login?message=註冊成功，請登錄。');
            });
        });
    });
});

// 登錄頁面
app.get('/login', (req, res) => res.render('login', { error: req.query.error, message: req.query.message, csrfToken: res.locals.csrfToken }));
// 處理登錄請求
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // 根據用戶名查詢用戶
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) { console.error("登錄時查詢用戶錯誤:", err); return res.render('login', { error: '登錄錯誤，請稍後再試。', message: null, csrfToken: res.locals.csrfToken }); }
        // 檢查用戶是否存在且密碼匹配
        if (user && bcrypt.compareSync(password, user.password)) {
            // 設置 session
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效。', message: null, csrfToken: res.locals.csrfToken });
        }
    });
});

// 登出路由
app.get('/logout', (req, res) => {
    // 銷毀 session
    req.session.destroy((err) => {
        if (err) console.error("登出時銷毀 session 錯誤:", err);
        res.redirect('/login');
    });
});

// 修改密碼頁面
app.get('/change-password', isAuthenticated, (req, res) => res.render('change-password', { user: req.session.user, message: null, messageType: null, csrfToken: res.locals.csrfToken }));
// 處理修改密碼請求
app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;
    if (!currentPassword || !newPassword || !confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項。', messageType: 'error', csrfToken: res.locals.csrfToken });
    if (newPassword !== confirmNewPassword) return res.render('change-password', { user: req.session.user, message: '兩次輸入的新密碼不匹配。', messageType: 'error', csrfToken: res.locals.csrfToken });
    // 驗證當前密碼
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, userRow) => {
        if (err || !userRow || !bcrypt.compareSync(currentPassword, userRow.password)) {
            if(err) console.error("修改密碼時查詢用戶錯誤:", err);
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確。', messageType: 'error', csrfToken: res.locals.csrfToken });
        }
        // 哈希新密碼並更新到數據庫
        const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], (err) => {
            if (err) { console.error("修改密碼時更新數據庫錯誤:", err); return res.render('change-password', { user: req.session.user, message: '更新密碼失敗。', messageType: 'error', csrfToken: res.locals.csrfToken });}
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success', csrfToken: res.locals.csrfToken });
        });
    });
});

// 文件瀏覽頁面
app.get('/files', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    // 獲取請求的路徑，默認為根目錄
    let relativeQueryPath = req.query.path || '/';
    // 清理路徑中的查詢字符串
    if (typeof relativeQueryPath === 'string' && relativeQueryPath.includes('?')) {
        relativeQueryPath = relativeQueryPath.split('?')[0];
    }
    // 規範化路徑
    relativeQueryPath = path.posix.normalize(relativeQueryPath);
    if (!relativeQueryPath || relativeQueryPath === '.') {
        relativeQueryPath = '/';
    }
    // 獲取搜索關鍵字
    const searchQuery = req.query.q ? req.query.q.trim() : null;
    // 確定要查看哪個用戶的文件（管理員可以查看其他用戶的）
    let targetUsernameForView = actingUser.username;
    let viewAsAdminContext = false;

    if (actingUser.role === 'admin' && req.query.targetUsername && req.query.targetUsername !== actingUser.username) {
        // 檢查目標用戶是否存在
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT username FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) {
            targetUsernameForView = req.query.targetUsername;
            viewAsAdminContext = true;
        } else {
            // 目標用戶不存在，重定向回文件列表並顯示錯誤消息
            return res.redirect(`/files?message=目標用戶 ${encodeURIComponent(req.query.targetUsername)} 不存在。&messageType=error`);
        }
    }
    try {
        // 獲取目標用戶的文件上傳根目錄
        const userUploadRootPath = getUserUploadRoot(targetUsernameForView);
        let items = [];
        let pageTitle = `${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件`;
        let isSearchResultView = false;
        let currentDisplayPath = relativeQueryPath;

        if (searchQuery) {
            // 如果有搜索關鍵字，執行搜索
            isSearchResultView = true;
            // 在用戶根目錄下遞歸搜索文件
            items = await searchFilesRecursively(userUploadRootPath, searchQuery, '/', userUploadRootPath);
            currentDisplayPath = '/'; // 搜索結果不顯示在特定子目錄下
            pageTitle = `有關 "${searchQuery}" 的搜尋結果 (在 ${viewAsAdminContext ? targetUsernameForView : actingUser.username} 的文件中)`;
            // 按名稱排序搜索結果
            items.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin'));
        } else {
            // 如果沒有搜索關鍵字，列出當前路徑下的文件和文件夾
            // 解析出當前路徑的完整物理路徑
            const currentFullPath = resolvePathForUser(targetUsernameForView, relativeQueryPath);
            // 讀取目錄內容
            const dirEntries = await fsp.readdir(currentFullPath, { withFileTypes: true });
            // 將目錄條目映射為文件列表項
            items = dirEntries.map(entry => {
                const itemPath = path.posix.join(relativeQueryPath, entry.name);
                return {
                    name: entry.name, isDir: entry.isDirectory(), path: itemPath,
                    encodedName: encodeURIComponent(entry.name), encodedPath: encodeURIComponent(itemPath)
                };
            }).sort((a, b) => {
                // 按文件夾優先，然後按名稱排序
                if (a.isDir && !b.isDir) return -1; if (!a.isDir && b.isDir) return 1;
                return a.name.localeCompare(b.name, 'zh-CN-u-co-pinyin');
            });
        }
        // 渲染文件列表頁面
        res.render('files', {
            user: actingUser, // 當前登錄用戶
            viewTargetUsername: viewAsAdminContext ? targetUsernameForView : null, // 如果是管理員視角，顯示目標用戶名
            items: items, // 文件和文件夾列表
            currentPath: currentDisplayPath, // 當前顯示的路徑
            searchQuery: searchQuery, // 當前搜索關鍵字
            isSearchResult: isSearchResultView, // 是否為搜索結果頁面
            ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS, // 允許預覽和編輯的擴展名
            csrfToken: res.locals.csrfToken, // CSRF Token
            message: req.query.message, messageType: req.query.messageType // 消息和消息類型
        });
    } catch (err) {
        // 處理讀取文件列表時的錯誤
        console.error(`[${actingUser.username}] 瀏覽 ${targetUsernameForView} 的文件夾 ${searchQuery ? `(搜索: ${searchQuery})` : relativeQueryPath} 錯誤:`, err);
        let friendlyMessage = '無法讀取文件列表。';
        if (err.code === 'ENOENT' && !searchQuery) friendlyMessage = '指定的路徑不存在。';
        else if (err.message.includes('無效路徑')) friendlyMessage = '無權訪問指定路徑。';
        // 重定向回文件列表頁面，並帶上錯誤消息
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

// 處理文件上傳請求
app.post('/upload', isAuthenticated, (req, res, next) => {
    console.log(`[POST /upload] Request received. User: ${req.session.user.username}, Body:`, req.body);
    // 使用 Multer 中間件處理文件上傳
    upload.array('userFiles', 100)(req, res, (err) => { // 'userFiles' 是前端表單中 input 的 name 屬性，100 是最大文件數
        if (err) {
            // 處理 Multer 上傳錯誤
            console.error(`[POST /upload] Multer 上傳錯誤 for user ${req.session.user.username}:`, err.message, err.stack);
            const currentPath = req.body.currentPath || '/';
            const redirectParams = new URLSearchParams();
            if (currentPath !== '/') redirectParams.set('path', currentPath);
            if (req.session.user.role === 'admin' && req.body.targetUsername) {
                redirectParams.set('targetUsername', req.body.targetUsername);
            }
            redirectParams.set('message', encodeURIComponent(err.message));
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
            redirectParams.set('messageType', 'error');
            return res.redirect(`/files?${redirectParams.toString()}`);
        }

        redirectParams.set('message', encodeURIComponent('項目上傳成功。'));
        redirectParams.set('messageType', 'success');
        // 重定向回文件列表頁面
        res.redirect(`/files?${redirectParams.toString()}`);
    });
});

// 處理創建文件夾請求
app.post('/create-folder', isAuthenticated, async (req, res) => {
    const { folderName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    // 構建重定向 URL 的查詢參數
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    // 驗證文件夾名稱
    if (!folderName || folderName.includes('/') || folderName.includes('..') || folderName.includes('\\') || folderName.length > 100 || !/^[^\/\\]+$/.test(folderName.trim()) || folderName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的文件夾名稱 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    const finalFolderName = folderName.trim();
    try {
        // 解析出要創建的文件夾的完整物理路徑
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, finalFolderName));
        // 檢查文件夾是否已存在
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${finalFolderName}" 已存在。&messageType=error`);
        }
        // 創建文件夾
        await fsp.mkdir(fullPathToCreate);
        res.redirect(`/files?${redirectPathQuery}&message=文件夾 "${finalFolderName}" 創建成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文件夾錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=創建文件夾失敗。&messageType=error`);
    }
});

// 處理重命名請求
app.post('/rename', isAuthenticated, async (req, res) => {
    const { oldPath: relativeOldPath, newName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    // 構建重定向 URL 的查詢參數
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQuery = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQuery) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQuery}` : adminQuery.substring(1);

    // 驗證新名稱
    if (!newName || newName.includes('/') || newName.includes('..') || newName.includes('\\') || newName.length > 255 || !/^[^\/\\]+$/.test(newName.trim()) || newName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的新名稱 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    const finalNewName = newName.trim();
    if (!relativeOldPath) { return res.redirect(`/files?${redirectPathQuery}&message=未提供原始路徑。&messageType=error`); }
    try {
        // 解析出原始路徑和新路徑的完整物理路徑
        const fullOldPath = resolvePathForUser(targetUsername, relativeOldPath);
        const parentDirOfOld = path.posix.dirname(relativeOldPath);
        const fullNewPath = resolvePathForUser(targetUsername, path.posix.join(parentDirOfOld, finalNewName));
        // 檢查原始項目是否存在
        if (!fs.existsSync(fullOldPath)) { return res.redirect(`/files?${redirectPathQuery}&message=原始文件或文件夾未找到。&messageType=error`); }
        // 檢查新名稱是否已存在（忽略大小寫，除非是同一個項目）
        if (fs.existsSync(fullNewPath) && fullOldPath.toLowerCase() !== fullNewPath.toLowerCase()) {
            return res.redirect(`/files?${redirectPathQuery}&message=名稱 "${finalNewName}" 已存在。&messageType=error`);
        }
        // 重命名文件或文件夾
        await fsp.rename(fullOldPath, fullNewPath);
        res.redirect(`/files?${redirectPathQuery}&message=重命名成功。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 重命名錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=重命名失敗。&messageType=error`);
    }
});

// 處理文件下載請求
app.get('/download', isAuthenticated, (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) { return res.status(400).render('error', { user: actingUser, message: '未指定下載文件路徑。', csrfToken: res.locals.csrfToken });}
    try {
        // 解析出文件的完整物理路徑
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        // 檢查文件是否存在且是一個文件
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            // 發送文件進行下載
            res.download(fullFilePath, path.basename(relativeFilePath), (err) => {
                if (err) {
                    console.error(`[${actingUser.username}] 為 ${targetUsername} 下載文件 ${relativeFilePath} 出錯:`, err);
                    if (!res.headersSent) { res.status(500).render('error', { user: actingUser, message: '下載文件時發生內部錯誤。', csrfToken: res.locals.csrfToken });}
                }
            });
        } else { res.status(404).render('error', { user: actingUser, message: '文件未找到或不是一個有效文件。', csrfToken: res.locals.csrfToken });}
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 準備下載 ${relativeFilePath} 時出錯:`, err);
        res.status(500).render('error', { user: actingUser, message: '處理下載請求時出錯。', csrfToken: res.locals.csrfToken });
    }
});

// 處理打包下載請求 (多個文件/文件夾壓縮為 ZIP)
app.post('/download-archive', isAuthenticated, async (req, res) => {
    console.log("[/download-archive] Received request.");
    console.log("[/download-archive] req.headers['content-type']:", req.headers['content-type']);
    console.log("[/download-archive] Raw req.body:", JSON.stringify(req.body, null, 2));

    const actingUser = req.session.user;
    const itemsToArchiveString = req.body.items;
    let itemsToArchive;

    // 嘗試解析請求體中的 items 數據
    if (itemsToArchiveString && typeof itemsToArchiveString === 'string') {
        try {
            itemsToArchive = JSON.parse(itemsToArchiveString);
            console.log("[/download-archive] Parsed items from req.body.items:", itemsToArchive);
        } catch (e) {
            console.error("[/download-archive] Failed to parse items JSON from req.body.items:", e);
            let redirectUrl = req.headers.referer || '/files';
            const errorParams = new URLSearchParams({ message: '打包下載失敗：項目數據格式錯誤。', messageType: 'error' }).toString();
            redirectUrl = redirectUrl.includes('?') ? `${redirectUrl.split('?')[0]}?${errorParams}` : `${redirectUrl}?${errorParams}`;
            return res.redirect(redirectUrl);
        }
    } else if (req.body.items && Array.isArray(req.body.items)) {
        itemsToArchive = req.body.items;
        console.log("[/download-archive] Items directly from req.body.items (likely parsed by express.json):", itemsToArchive);
    } else {
        console.log("[/download-archive] req.body.items is missing or not a string/array.");
    }

    // 確定目標用戶名
    let targetUsername = actingUser.username;
    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT id FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) {
            targetUsername = req.body.targetUsername;
        } else {
            let redirectUrl = req.headers.referer || '/files';
            const errorParams = new URLSearchParams({ message: '打包下載失敗：目標用戶不存在。', messageType: 'error' }).toString();
            redirectUrl = redirectUrl.includes('?') ? `${redirectUrl.split('?')[0]}?${errorParams}` : `${redirectUrl}?${errorParams}`;
            return res.redirect(redirectUrl);
        }
    }

    // 檢查是否有項目需要打包
    if (!itemsToArchive || !Array.isArray(itemsToArchive) || itemsToArchive.length === 0) {
        console.log("[/download-archive] No items to archive after parsing.");
        let redirectUrl = req.headers.referer || '/files';
        const errorParams = new URLSearchParams({ message: '未選擇要下載的項目或解析失敗。', messageType: 'error' }).toString();
        redirectUrl = redirectUrl.includes('?') ? `${redirectUrl.split('?')[0]}?${errorParams}` : `${redirectUrl}?${errorParams}`;
        return res.redirect(redirectUrl);
    }

    // 創建 archiver 實例，用於創建 ZIP 文件
    const archive = archiver('zip', { zlib: { level: 9 } }); // 設置壓縮級別
    const archiveName = `archive-${targetUsername}-${Date.now()}.zip`; // 生成唯一的 ZIP 文件名
    res.attachment(archiveName); // 設置響應頭，指示瀏覽器下載文件
    archive.pipe(res); // 將壓縮流導向響應對象

    // 處理 archiver 的警告和錯誤事件
    archive.on('warning', function(err) {
        if (err.code === 'ENOENT') console.warn('[Archiver Warning]', err);
        else console.error('[Archiver Error]', err);
    });
    archive.on('error', function(err) {
        console.error('創建壓縮文件時發生嚴重錯誤:', err);
        if (!res.headersSent) {
             if (!res.writableEnded) {
                 res.status(500).send('創建壓縮文件失敗。');
            }
        } else if (!res.writableEnded) {
            res.end();
        }
    });
    // 監聽響應關閉事件
    res.on('close', function() {
        console.log(`壓縮文件 '${archiveName}' 已發送 ${archive.pointer()} 字節。`);
    });

    try {
        // 遍歷要打包的項目，並將它們添加到壓縮包中
        for (const item of itemsToArchive) {
            if (!item || typeof item.path !== 'string' || typeof item.name !== 'string') {
                console.warn(`[/download-archive] Invalid item structure in archive list:`, item);
                archive.append(`錯誤：一個無效的項目結構被傳遞。\n`, { name: `打包錯誤日誌.txt` });
                continue;
            }
            // 解析出項目的完整物理路徑
            const fullPath = resolvePathForUser(targetUsername, item.path);
            // 檢查項目是否存在
            if (!fs.existsSync(fullPath)) {
                console.warn(`打包下載：項目 ${item.path} 不存在，已跳過。`);
                archive.append(`錯誤：項目 ${item.name} (位於 ${item.path}) 未找到或無法訪問。\n`, { name: `打包錯誤日誌.txt` });
                continue;
            }
            const stat = await fsp.stat(fullPath);
            // 確定項目在 ZIP 中的名稱（移除開頭的 '/'）
            const entryNameInZip = item.path.startsWith('/') ? item.path.substring(1) : item.path;
            if (stat.isFile()) {
                // 添加文件到壓縮包
                archive.file(fullPath, { name: entryNameInZip });
            } else if (stat.isDirectory()) {
                // 添加文件夾到壓縮包（包括其內容）
                archive.directory(fullPath, entryNameInZip);
            }
        }
    } catch (error) {
        console.error('添加文件到壓縮包時出錯:', error);
        archive.append(`內部錯誤：處理某些文件時發生問題。\n${error.message}\n`, { name: `內部伺服器錯誤日誌.txt` });
    }

    console.log(`[/download-archive] Finalizing archive: ${archiveName}`);
    // 完成壓縮過程
    await archive.finalize();
});

// 處理刪除項目請求
app.get('/delete', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeItemPath = req.query.path;
    const isDir = req.query.isDir === 'true';
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeItemPath) { return res.redirect(`/files?message=未指定要刪除的項目路徑。&messageType=error`);}
    // 獲取父目錄路徑用於重定向
    const parentRelativePath = path.posix.dirname(relativeItemPath);
    let redirectQuery = (parentRelativePath === '.' || parentRelativePath === '/') ? '' : `path=${encodeURIComponent(parentRelativePath)}`;
    const adminQuery = (actingUser.role === 'admin' && req.query.targetUsername) ? `&targetUsername=${encodeURIComponent(req.query.targetUsername)}` : '';
    if (adminQuery) redirectQuery = redirectQuery ? `${redirectQuery}${adminQuery}` : adminQuery.substring(1);
    try {
        // 解析出要刪除項目的完整物理路徑
        const fullItemPath = resolvePathForUser(targetUsername, relativeItemPath);
        // 檢查項目是否存在
        if (!fs.existsSync(fullItemPath)) { return res.redirect(`/files?${redirectQuery}&message=要刪除的項目未找到。&messageType=error`);}
        // 刪除文件或文件夾
        if (isDir) { await fsp.rm(fullItemPath, { recursive: true, force: true }); } // 遞歸刪除文件夾
        else { await fsp.unlink(fullItemPath); } // 刪除文件
        res.redirect(`/files?${redirectQuery}&message=項目 "${path.basename(relativeItemPath)}" 已刪除。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 刪除項目 ${relativeItemPath} 錯誤:`, err);
        res.redirect(`/files?${redirectQuery}&message=刪除項目失敗。&messageType=error`);
    }
});

// 處理文件預覽請求
app.get('/view', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) { return res.status(400).render('error', { user: actingUser, message: '未指定查看文件路徑。', csrfToken: res.locals.csrfToken }); }
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    // 檢查文件類型是否允許預覽
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) { return res.status(403).render('error', { user: actingUser, message: `不支援預覽此文件類型 (${fileExt})。您可以嘗試下載它。`, csrfToken: res.locals.csrfToken }); }
    try {
        // 解析出文件的完整物理路徑
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        // 檢查文件是否存在且是一個文件
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            // 讀取文件內容
            const content = await fsp.readFile(fullFilePath, 'utf8');
            // 渲染文件預覽頁面
            res.render('view-file', {
                user: actingUser, viewTargetUsername: (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : null,
                filename: filename, content: content, currentPath: relativeFilePath,
                fileExtension: fileExt, ALLOWED_TEXT_EXTENSIONS: ALLOWED_TEXT_EXTENSIONS,
                csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
            });
        } else { res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken }); }
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 讀取文件 ${relativeFilePath} 查看錯誤:`, err);
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。', csrfToken: res.locals.csrfToken });
    }
});

// 處理文件編輯頁面請求
app.get('/edit', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const relativeFilePath = req.query.path;
    const targetUsername = (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : actingUser.username;
    if (!relativeFilePath) { return res.status(400).render('error', { user: actingUser, message: '未指定編輯文件路徑。', csrfToken: res.locals.csrfToken });}
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    // 檢查文件類型是否允許編輯
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) { return res.status(403).render('error', { user: actingUser, message: `不支援編輯此文件類型 (${fileExt})。`, csrfToken: res.locals.csrfToken });}
    try {
        // 解析出文件的完整物理路徑
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        // 檢查文件是否存在且是一個文件
        if (fs.existsSync(fullFilePath) && fs.statSync(fullFilePath).isFile()) {
            // 讀取文件內容
            const content = await fsp.readFile(fullFilePath, 'utf8');
            // 渲染文件編輯頁面
            res.render('edit-file', {
                user: actingUser, viewTargetUsername: (actingUser.role === 'admin' && req.query.targetUsername) ? req.query.targetUsername : null,
                filename: filename, content: content, currentPath: relativeFilePath,
                csrfToken: res.locals.csrfToken, message: req.query.message, messageType: req.query.messageType
            });
        } else { res.status(404).render('error', { user: actingUser, message: '文件未找到。', csrfToken: res.locals.csrfToken });}
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 讀取文件 ${relativeFilePath} 編輯錯誤:`, err);
        res.status(500).render('error', { user: actingUser, message: '讀取文件內容失敗。', csrfToken: res.locals.csrfToken });
    }
});

// 處理保存文件請求
app.post('/save/:encodedPath', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    // 解碼文件路徑
    const relativeFilePath = decodeURIComponent(req.params.encodedPath);
    const { fileContent } = req.body;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    const filename = path.basename(relativeFilePath);
    const fileExt = path.extname(filename).toLowerCase();
    // 檢查文件類型是否允許保存（與編輯類型一致）
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        return res.status(403).render('edit-file', {
            user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
            filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken,
            message: `不支援保存此文件類型 (${fileExt})。`, messageType: 'error'
        });
    }
    try {
        // 解析出文件的完整物理路徑
        const fullFilePath = resolvePathForUser(targetUsername, relativeFilePath);
        const parentDirOfFile = path.dirname(fullFilePath);
        // 檢查父目錄是否存在
        if (!fs.existsSync(parentDirOfFile)) {
            console.error(`[${actingUser.username}] 尝试保存文件到不存在的父目录: ${parentDirOfFile}`);
            return res.status(400).render('edit-file', {
                user: actingUser, viewTargetUsername: targetUsername !== actingUser.username ? targetUsername : null,
                filename, content: fileContent, currentPath: relativeFilePath, csrfToken: res.locals.csrfToken,
                message: '保存路徑無效 (父目錄不存在)。', messageType: 'error'
            });
        }
        // 寫入文件內容
        await fsp.writeFile(fullFilePath, fileContent, 'utf8');
        // 構建重定向 URL，返回到文件所在的目錄
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

// 處理創建文本文件請求
app.post('/create-text-file', isAuthenticated, async (req, res) => {
    const { newFileName, currentPath: relativeCurrentPath } = req.body;
    const actingUser = req.session.user;
    const targetUsername = (actingUser.role === 'admin' && req.body.targetUsername) ? req.body.targetUsername : actingUser.username;
    // 構建重定向 URL 的查詢參數
    let redirectPathQuery = relativeCurrentPath ? `path=${encodeURIComponent(relativeCurrentPath)}` : '';
    const adminQueryForRedirect = (actingUser.role === 'admin' && req.body.targetUsername) ? `&targetUsername=${encodeURIComponent(req.body.targetUsername)}` : '';
    if (adminQueryForRedirect) redirectPathQuery = redirectPathQuery ? `${redirectPathQuery}${adminQueryForRedirect}` : adminQueryForRedirect.substring(1);

    // 驗證文件名
    if (!newFileName || newFileName.includes('/') || newFileName.includes('..') || newFileName.includes('\\') || newFileName.length > 100 || !/^[^\/\\]+$/.test(newFileName.trim()) || newFileName.trim().startsWith('.')) {
        return res.redirect(`/files?${redirectPathQuery}&message=無效的文件名 (不能包含特殊字符或以點開頭)。&messageType=error`);
    }
    let finalFileName = newFileName.trim();
    const fileExt = path.extname(finalFileName).toLowerCase();
    // 如果沒有指定允許的文本文件擴展名，則默認添加 .txt
    if (!ALLOWED_TEXT_EXTENSIONS.includes(fileExt)) {
        finalFileName += '.txt';
        if (!ALLOWED_TEXT_EXTENSIONS.includes('.txt')) {
             console.warn(".txt extension is not in ALLOWED_TEXT_EXTENSIONS, but used as default for new text files.");
        }
    }
    try {
        // 解析出要創建文件的完整物理路徑
        const fullPathToCreate = resolvePathForUser(targetUsername, path.join(relativeCurrentPath, finalFileName));
        // 檢查文件是否已存在
        if (fs.existsSync(fullPathToCreate)) {
            return res.redirect(`/files?${redirectPathQuery}&message=文件 "${finalFileName}" 已存在。&messageType=error`);
        }
        // 創建空文件
        await fsp.writeFile(fullPathToCreate, '', 'utf8');
        // 構建重定向 URL，跳轉到編輯頁面
        const editPath = path.posix.join(relativeCurrentPath, finalFileName);
        let editRedirectQuery = `path=${encodeURIComponent(editPath)}`;
        if (actingUser.role === 'admin' && req.body.targetUsername) {
            editRedirectQuery += `&targetUsername=${encodeURIComponent(req.body.targetUsername)}`;
        }
        res.redirect(`/edit?${editRedirectQuery}&message=文件 "${finalFileName}" 創建成功，開始編輯。&messageType=success`);
    } catch (err) {
        console.error(`[${actingUser.username}] 為 ${targetUsername} 創建文本文件錯誤:`, err);
        res.redirect(`/files?${redirectPathQuery}&message=創建文本文件失敗。&messageType=error`);
    }
});

// API 路由：獲取目錄樹結構
app.get('/api/directories', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    // 確定要獲取哪個用戶的目錄樹
    let targetUsernameForTree = actingUser.username;
    if (actingUser.role === 'admin' && req.query.targetUsername) {
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT id FROM users WHERE username = ?", [req.query.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) targetUsernameForTree = req.query.targetUsername;
        else return res.status(404).json({ success: false, message: '目標用戶不存在。' });
    }
    const userUploadRoot = getUserUploadRoot(targetUsernameForTree);
    // 獲取需要排除的路徑列表
    let pathsToExclude = [];
    if (req.query.excludePaths) {
        pathsToExclude = req.query.excludePaths.split(',').map(p => path.posix.normalize(p));
    }
    try {
        // 獲取目錄樹結構
        const directoryTree = await getDirectoryTreeRecursive(userUploadRoot, userUploadRoot, '/', pathsToExclude);
        res.json(directoryTree);
    } catch (error) {
        console.error(`[API DirTree] 獲取用戶 ${targetUsernameForTree} 的目錄樹時出錯:`, error);
        res.status(500).json({ success: false, message: '無法獲取目錄列表。' });
    }
});

// 處理移動項目請求
app.post('/move-items', isAuthenticated, async (req, res) => {
    const actingUser = req.session.user;
    const { sourcePaths, destinationPath } = req.body;
    // 確定要移動哪個用戶的項目
    let targetUsernameForMove = actingUser.username;
    if (actingUser.role === 'admin' && req.body.targetUsername) {
        const targetUserExists = await new Promise((resolve, reject) => {
            db.get("SELECT id FROM users WHERE username = ?", [req.body.targetUsername], (err, row) => {
                if (err) reject(err); else resolve(!!row);
            });
        });
        if (targetUserExists) targetUsernameForMove = req.body.targetUsername;
        else return res.status(400).json({ success: false, message: '目標用戶不存在。' });
    }
    // 檢查請求參數
    if (!sourcePaths || !Array.isArray(sourcePaths) || sourcePaths.length === 0 || !destinationPath) {
        return res.status(400).json({ success: false, message: '源路徑和目標路徑為必填項。' });
    }
    try {
        const userUploadRoot = getUserUploadRoot(targetUsernameForMove);
        // 解析出目標路徑的完整物理路徑
        const fullDestinationPath = resolvePathForUser(targetUsernameForMove, destinationPath);
        // 檢查目標路徑是否存在且是一個目錄
        const destStat = await fsp.stat(fullDestinationPath).catch(() => null);
        if (!destStat || !destStat.isDirectory()) {
            return res.status(400).json({ success: false, message: '目標路徑不是一個有效的目錄。' });
        }
        let errors = []; let successes = 0;
        // 遍歷要移動的源路徑
        for (const sourceRelPath of sourcePaths) {
            // 解析出源路徑的完整物理路徑
            const fullSourcePath = resolvePathForUser(targetUsernameForMove, sourceRelPath);
            const itemName = path.basename(fullSourcePath);
            // 構建新路徑的完整物理路徑
            const fullNewPath = path.join(fullDestinationPath, itemName);
            // 檢查是否嘗試將文件夾移動到其自身或其子文件夾中
            if (fs.existsSync(fullSourcePath) && fs.statSync(fullSourcePath).isDirectory()) {
                if (fullNewPath.startsWith(fullSourcePath + path.sep) || fullNewPath === fullSourcePath) {
                    errors.push(`無法將文件夾 "${itemName}" 移動到其自身或其子文件夾中。`); continue;
                }
            }
            // 檢查目標位置是否已存在同名項目
            if (fs.existsSync(fullNewPath)) {
                errors.push(`目標位置已存在同名項目 "${itemName}"。`); continue;
            }
            try {
                // 移動項目
                await fsp.rename(fullSourcePath, fullNewPath); successes++;
            } catch (moveError) {
                console.error(`[Move] 移動項目 "${sourceRelPath}" 到 "${destinationPath}" 失敗:`, moveError);
                errors.push(`移動 "${itemName}" 失敗: ${moveError.message}`);
            }
        }
        // 根據移動結果返回響應
        if (errors.length > 0) {
            const message = `移動操作部分完成。成功 ${successes} 項。錯誤: ${errors.join('; ')}`;
            return res.status(successes > 0 ? 207 : 500).json({ success: successes > 0, message: message, errors: errors });
        }
        res.json({ success: true, message: `成功移動 ${successes} 個項目。` });
    } catch (error) {
        console.error(`[Move API] 移動項目時發生錯誤:`, error);
        res.status(500).json({ success: false, message: error.message || '移動項目時發生內部伺服器錯誤。' });
    }
});

// 管理面板頁面 (僅限管理員訪問)
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    // 獲取所有用戶列表
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) { console.error("獲取用戶列表錯誤:", err); return res.status(500).render('error', { user: req.session.user, message: '無法獲取用戶列表。', csrfToken: res.locals.csrfToken });}
        // 渲染管理面板頁面
        res.render('admin', {
            users, currentUser: req.session.user, csrfToken: res.locals.csrfToken,
            message: req.query.message, messageType: req.query.messageType
        });
    });
});

// 處理管理員添加用戶請求
// MODIFIED: Admin can add other admin accounts
app.post('/admin/add-user', isAuthenticated, isAdmin, (req, res) => {
    const { newUsername, newPassword, confirmNewPassword, role } = req.body; // Added role
    if (!newUsername || !newPassword || !confirmNewPassword || !role) { // Added role check
        return res.redirect('/admin?message=所有新用戶欄位（包括角色）均為必填項。&messageType=error');
    }
    if (role !== 'user' && role !== 'admin') { // Validate role
        return res.redirect('/admin?message=無效的用戶角色。&messageType=error');
    }
    if (newPassword !== confirmNewPassword) {
        return res.redirect('/admin?message=新用戶的兩次密碼輸入不匹配。&messageType=error');
    }
    // 用戶名格式和長度檢查
    if (newUsername.includes('/') || newUsername.includes('..') || newUsername.includes('\\') || newUsername.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(newUsername)) {
        return res.redirect('/admin?message=新用戶名包含無效字符、過長或格式不正確。&messageType=error');
    }
    // REMOVED: Restriction on creating user named 'admin'
    // if (newUsername.toLowerCase() === 'admin') {
    //     return res.redirect('/admin?message=不能創建名為 "admin" 的用戶。&messageType=error');
    // }
    // 檢查用戶名是否已存在
    db.get("SELECT * FROM users WHERE username = ?", [newUsername], (err, existingUser) => {
        if (err) {
            console.error("管理員添加用戶時檢查用戶名錯誤:", err);
            return res.redirect('/admin?message=添加用戶失敗，請稍後再試。&messageType=error');
        }
        if (existingUser) {
            return res.redirect(`/admin?message=用戶名 "${newUsername}" 已存在。&messageType=error`);
        }
        // 哈希密碼並插入新用戶到數據庫
        const hashedPassword = bcrypt.hashSync(newPassword, 12);
        db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [newUsername, hashedPassword, role], // Use role from form
            function (err) {
                if (err) {
                    console.error("管理員添加用戶時插入數據庫錯誤:", err);
                    return res.redirect('/admin?message=添加用戶失敗，請稍後再試。&messageType=error');
                }
                // 為新用戶創建文件上傳根目錄
                getUserUploadRoot(newUsername);
                res.redirect(`/admin?message=用戶 "${newUsername}" (角色: ${role}) 已成功創建。&messageType=success`);
            }
        );
    });
});

// 處理管理員重置用戶密碼請求
app.post('/admin/reset-password/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToReset = parseInt(req.params.userId, 10);
    const { newPassword } = req.body;
    if (isNaN(userIdToReset)) { return res.redirect('/admin?message=無效的用戶ID。&messageType=error');}
    // 檢查是否嘗試重置自己的密碼
    if (req.session.user.id === userIdToReset) { return res.redirect('/admin?message=不能重置自己的密碼。&messageType=error');}
    if (!newPassword) { return res.redirect(`/admin?message=新密碼不能為空。&messageType=error`);}
    // 哈希新密碼並更新到數據庫
    const hashedNewPassword = bcrypt.hashSync(newPassword, 12);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userIdToReset], function (err) {
        if (err || this.changes === 0) {
            if(err) console.error("管理員重置密碼錯誤:", err);
            return res.redirect('/admin?message=重置密碼失敗。&messageType=error');
        }
        // 獲取被重置密碼的用戶名並重定向
        db.get("SELECT username FROM users WHERE id = ?", [userIdToReset], (err, targetUser) => {
            if(err) console.error("管理員重置密碼後查詢用戶名錯誤:", err);
            res.redirect(`/admin?message=用戶 ${targetUser ? targetUser.username : `ID ${userIdToReset}`} 的密碼已成功重置。&messageType=success`);
        });
    });
});

// 處理管理員刪除用戶請求
// MODIFIED: Admin can delete the built-in admin account (if not self)
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);
    if (isNaN(userIdToDelete)) { return res.redirect('/admin?message=無效的用戶ID。&messageType=error');}
    // This check correctly prevents self-deletion
    if (req.session.user.id === userIdToDelete) { return res.redirect('/admin?message=不能刪除自己。&messageType=error');}

    // 獲取要刪除的用戶信息
    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, user) => {
        if (err || !user) {
            if(err) console.error("管理員刪除用戶時查詢用戶錯誤:", err);
            return res.redirect('/admin?message=未找到用戶。&messageType=error');
        }
        // REMOVED: Special protection for user named 'admin'. Self-delete protection is sufficient.
        // if (user.username.toLowerCase() === 'admin') {
        //     return res.redirect('/admin?message=不能刪除主要的 "admin" 管理員帳戶。&messageType=error');
        // }
        const userDirToDelete = getUserUploadRoot(user.username);
        // 從數據庫中刪除用戶
        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], async function (err) {
            if (err) { console.error("管理員刪除用戶時數據庫錯誤:", err); return res.redirect('/admin?message=刪除用戶失敗。&messageType=error');}
            if (this.changes > 0) {
                try {
                    // 刪除用戶的文件夾
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

// 404 錯誤處理
app.use((req, res, next) => {
    res.status(404).render('error', { user: req.session.user, message: '找不到頁面 (404)。', csrfToken: res.locals.csrfToken });
});
// 全局錯誤處理
app.use((err, req, res, next) => {
    const usernameForLog = req.session.user ? req.session.user.username : '未認證用戶';
    console.error(`[${usernameForLog}] 全局錯誤處理: ${req.method} ${req.originalUrl}`, err.stack || err);
    let publicMessage = '伺服器內部錯誤 (500)。';
    // 在非生產環境中顯示詳細錯誤信息
    if (process.env.NODE_ENV !== 'production' && err.message) { publicMessage = err.message; }
    if (err.publicMessage) { publicMessage = err.publicMessage; }
    if (res.headersSent) { return next(err); }
    res.status(err.status || 500).render('error', { user: req.session.user, message: publicMessage, csrfToken: res.locals.csrfToken });
});

// 啟動伺服器
app.listen(port, () => console.log(`伺服器運行在 http://localhost:${port}`));
// 處理 SIGINT 信號，平滑關閉伺服器和數據庫連接
process.on('SIGINT', () => {
    console.log('收到 SIGINT 信號，正在關閉伺服器...');
    db.close((err) => {
        if (err) { console.error('關閉 SQLite 資料庫時出錯:', err.message); process.exit(1);}
        console.log('SQLite 資料庫已關閉。');
        process.exit(0);
    });
});
