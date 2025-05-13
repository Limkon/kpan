// server.js (SQLite 版本 - 包含所有新功能)
// 導入所需模組
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises; // For async file operations
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8100; // 您指定的端口

// 資料庫文件路徑
const DB_FILE = path.join(__dirname, 'data', 'netdisk.sqlite');
// 上傳文件存儲目錄
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// 确保data和uploads目录存在
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
    console.log("已自動創建 'data' 目錄。");
}
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
    console.log("已自動創建 'uploads' 目錄。");
}

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
        if (err) {
            console.error('創建 users 表格失敗:', err.message);
        } else {
            console.log("'users' 表格已準備就緒。");
            db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
                if (err) {
                    console.error("檢查用戶數量時出錯:", err.message);
                    return;
                }
                if (row.count === 0) {
                    console.log("資料庫中沒有用戶。請通過 /register 註冊第一個用戶，該用戶將成為管理員。");
                }
            });
        }
    });
});

// 中間件設置
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true })); // For form data
app.use(express.json()); // For potential JSON payloads if you extend API
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your_very_secret_key_for_v2_features', // 請務必更改為更安全的密鑰
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 在生產環境中應設為 true (HTTPS)
}));

// Multer 設置
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userUploadDir = path.join(UPLOAD_DIR, req.session.user.username);
        if (!fs.existsSync(userUploadDir)) {
            fs.mkdirSync(userUploadDir, { recursive: true });
        }
        cb(null, userUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage });

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
    res.status(403).render('error', { message: '禁止訪問：僅限管理員', user: req.session.user });
}

// --- 路由 ---

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/files');
    } else {
        res.redirect('/login');
    }
});

// 註冊
app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;

    if (!username || !password || !confirmPassword) {
        return res.render('register', { error: '所有欄位均為必填項' });
    }
    if (password !== confirmPassword) {
        return res.render('register', { error: '兩次輸入的密碼不匹配' });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) {
            console.error("註冊時查詢用戶出錯:", err.message);
            return res.render('register', { error: '註冊過程中發生錯誤，請稍後再試。' });
        }
        if (row) {
            return res.render('register', { error: '用戶名已存在' });
        }

        db.get("SELECT COUNT(*) as count FROM users", (err, countRow) => {
            if (err) {
                console.error("檢查用戶總數時出錯:", err.message);
                return res.render('register', { error: '註冊過程中發生錯誤，請稍後再試。' });
            }

            const hashedPassword = bcrypt.hashSync(password, 10);
            const userRole = countRow.count === 0 ? 'admin' : 'user';

            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                [username, hashedPassword, userRole],
                function (err) {
                    if (err) {
                        console.error("插入新用戶失敗:", err.message);
                        return res.render('register', { error: '註冊失敗，請稍後再試。' });
                    }
                    console.log(`新用戶 ${username} (ID: ${this.lastID}) 已註冊為 ${userRole}`);
                    res.redirect('/login');
                }
            );
        });
    });
});

// 登錄
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            console.error("登錄時查詢用戶出錯:", err.message);
            return res.render('login', { error: '登錄過程中發生錯誤，請稍後再試。' });
        }
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/files');
        } else {
            res.render('login', { error: '用戶名或密碼無效' });
        }
    });
});

// 登出
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("登出失敗:", err);
            // 即使登出失敗，也嘗試重定向到登錄頁面
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// 修改密碼
app.get('/change-password', isAuthenticated, (req, res) => {
    res.render('change-password', { user: req.session.user, message: null, messageType: null });
});

app.post('/change-password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.session.user.id;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '所有欄位均為必填項', messageType: 'error' });
    }
    if (newPassword !== confirmNewPassword) {
        return res.render('change-password', { user: req.session.user, message: '新密碼與確認密碼不匹配', messageType: 'error' });
    }
    if (newPassword.length < 6) { // 簡單的密碼長度檢查
        return res.render('change-password', { user: req.session.user, message: '新密碼長度至少為6位', messageType: 'error' });
    }


    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) {
            console.error("修改密碼時查詢用戶出錯:", err.message);
            return res.render('change-password', { user: req.session.user, message: '修改密碼過程中發生錯誤', messageType: 'error' });
        }
        if (!user || !bcrypt.compareSync(currentPassword, user.password)) {
            return res.render('change-password', { user: req.session.user, message: '當前密碼不正確', messageType: 'error' });
        }

        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hashedNewPassword, userId], function(err) {
            if (err) {
                console.error("更新密碼失敗:", err.message);
                return res.render('change-password', { user: req.session.user, message: '更新密碼失敗，請稍後再試', messageType: 'error' });
            }
            console.log(`用戶 ID ${userId} 的密碼已更新。`);
            // 可以選擇讓用戶重新登錄
            // req.session.destroy();
            // res.redirect('/login?message=密碼已成功修改，請重新登錄');
            res.render('change-password', { user: req.session.user, message: '密碼已成功修改！', messageType: 'success' });
        });
    });
});


// 文件列表和上傳頁面
app.get('/files', isAuthenticated, (req, res) => {
    const user = req.session.user;
    const userUploadDir = path.join(UPLOAD_DIR, user.username);

    if (!fs.existsSync(userUploadDir)) {
        fs.mkdirSync(userUploadDir, { recursive: true });
    }

    fs.readdir(userUploadDir, (err, files) => {
        if (err) {
            console.error("讀取文件目錄失敗:", err);
            return res.status(500).render('error', {message: '無法讀取文件列表', user: req.session.user});
        }
        res.render('files', {
            user: user,
            files: files.map(f => ({ name: f, encodedName: encodeURIComponent(f) })) || [],
            message: req.query.message, // For general messages
            messageType: req.query.messageType // For styling messages (e.g., 'error', 'success')
        });
    });
});

// 文件上傳處理
app.post('/upload', isAuthenticated, upload.array('userFiles', 10), (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.redirect('/files?message=沒有選擇文件&messageType=error');
    }
    res.redirect('/files?message=文件上傳成功&messageType=success');
});

// 文件下載處理
app.get('/download/:filename', isAuthenticated, (req, res) => {
    const user = req.session.user;
    const filename = decodeURIComponent(req.params.filename);
    const filePath = path.join(UPLOAD_DIR, user.username, filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath, filename, (err) => {
            if (err) {
                console.error("下載文件時出錯:", err);
                if (!res.headersSent) {
                     res.status(500).render('error', {message: '下載文件時出錯。', user: req.session.user});
                }
            }
        });
    } else {
        console.warn(`嘗試下載不存在的文件: ${filePath}`);
        res.status(404).render('error', {message: '文件未找到。', user: req.session.user});
    }
});

// 刪除文件處理
app.get('/delete/:filename', isAuthenticated, (req, res) => {
    const user = req.session.user;
    const filename = decodeURIComponent(req.params.filename);
    const filePath = path.join(UPLOAD_DIR, user.username, filename);

    if (fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
            if (err) {
                console.error("刪除文件失敗:", err);
                return res.redirect(`/files?message=刪除文件 ${filename} 失敗&messageType=error`);
            }
            res.redirect(`/files?message=文件 ${filename} 已刪除&messageType=success`);
        });
    } else {
        res.redirect(`/files?message=文件 ${filename} 未找到&messageType=error`);
    }
});

// 編輯文本文件 - 顯示編輯頁面
app.get('/edit/:filename', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    const filename = decodeURIComponent(req.params.filename);
    const filePath = path.join(UPLOAD_DIR, user.username, filename);

    // 簡單的文件類型檢查，只允許編輯某些擴展名的文件
    const allowedExtensions = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', 'c', 'cpp', 'go', 'rb'];
    const fileExt = path.extname(filename).toLowerCase();

    if (!allowedExtensions.includes(fileExt)) {
        return res.status(403).render('error', {message: `不支援編輯此文件類型 (${fileExt})`, user: req.session.user});
    }

    try {
        if (fs.existsSync(filePath)) {
            const content = await fsp.readFile(filePath, 'utf8');
            res.render('edit-file', {
                user: user,
                filename: filename,
                content: content,
                message: null,
                messageType: null
            });
        } else {
            res.status(404).render('error', {message: '文件未找到。', user: req.session.user});
        }
    } catch (err) {
        console.error(`讀取文件 ${filename} 進行編輯時出錯:`, err);
        res.status(500).render('error', {message: '讀取文件內容失敗。', user: req.session.user});
    }
});

// 保存編輯後的文本文件
app.post('/save/:filename', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    const filename = decodeURIComponent(req.params.filename);
    const filePath = path.join(UPLOAD_DIR, user.username, filename);
    const { fileContent } = req.body;

    const allowedExtensions = ['.txt', '.md', '.json', '.js', '.css', '.html', '.xml', '.log', '.csv', '.py', '.java', 'c', 'cpp', 'go', 'rb'];
    const fileExt = path.extname(filename).toLowerCase();

    if (!allowedExtensions.includes(fileExt)) {
         return res.status(403).render('edit-file', {
            user: user,
            filename: filename,
            content: fileContent, // Show current content back
            message: `不支援保存此文件類型 (${fileExt})`,
            messageType: 'error'
        });
    }

    try {
        if (fs.existsSync(filePath)) { // 再次確認文件存在以防萬一
            await fsp.writeFile(filePath, fileContent, 'utf8');
            console.log(`文件 ${filename} 已被用戶 ${user.username} 更新。`);
            res.redirect(`/files?message=文件 ${filename} 已成功保存&messageType=success`);
        } else {
            res.status(404).render('edit-file', {
                user: user,
                filename: filename,
                content: fileContent,
                message: '文件未找到，無法保存。',
                messageType: 'error'
            });
        }
    } catch (err) {
        console.error(`保存文件 ${filename} 時出錯:`, err);
        res.status(500).render('edit-file', {
            user: user,
            filename: filename,
            content: fileContent,
            message: '保存文件失敗。',
            messageType: 'error'
        });
    }
});


// 管理員頁面 - 用戶管理
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) {
            console.error("獲取用戶列表失敗:", err.message);
            return res.status(500).render('error', {message: '無法獲取用戶列表', user: req.session.user});
        }
        res.render('admin', {
            users: users,
            currentUser: req.session.user,
            message: req.query.message,
            messageType: req.query.messageType
        });
    });
});

// 管理員刪除用戶
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);

    if (isNaN(userIdToDelete)) {
        return res.redirect('/admin?message=無效的用戶ID&messageType=error');
    }
    if (req.session.user.id === userIdToDelete) {
        return res.redirect('/admin?message=不能刪除當前登錄的管理員帳戶&messageType=error');
    }

    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, userToDeleteData) => {
        if (err) {
            console.error("刪除用戶前查找用戶名失敗:", err.message);
            return res.redirect('/admin?message=刪除用戶時發生錯誤&messageType=error');
        }
        if (!userToDeleteData) {
            return res.redirect('/admin?message=未找到該用戶&messageType=error');
        }

        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], function (err) {
            if (err) {
                console.error("刪除用戶失敗:", err.message);
                return res.redirect('/admin?message=刪除用戶失敗&messageType=error');
            }
            if (this.changes > 0) {
                console.log(`用戶 ID ${userIdToDelete} (用戶名: ${userToDeleteData.username}) 已被刪除。`);
                const userDirToDelete = path.join(UPLOAD_DIR, userToDeleteData.username);
                if (fs.existsSync(userDirToDelete)) {
                    fs.rm(userDirToDelete, { recursive: true, force: true }, (rmErr) => {
                        if (rmErr) {
                            console.error(`刪除用戶 ${userToDeleteData.username} 的文件夾 ${userDirToDelete} 失敗:`, rmErr);
                            res.redirect(`/admin?message=用戶已刪除，但其文件夾刪除失敗。&messageType=error`);
                        } else {
                            console.log(`用戶 ${userToDeleteData.username} 的文件夾 ${userDirToDelete} 已成功刪除。`);
                            res.redirect('/admin?message=用戶及其文件已成功刪除&messageType=success');
                        }
                    });
                } else {
                    res.redirect('/admin?message=用戶已刪除（該用戶沒有文件夾）&messageType=success');
                }
            } else {
                res.redirect('/admin?message=未找到用戶或刪除失敗&messageType=error');
            }
        });
    });
});

// 簡單的錯誤頁面 (可選)
app.get('/error-page', (req, res) => { // 示例，實際錯誤處理應更完善
    res.render('error', { message: req.query.message || '發生未知錯誤', user: req.session.user });
});

// 404 處理 (應放在所有路由之後)
app.use((req, res, next) => {
    res.status(404).render('error', { message: '找不到頁面 (404)', user: req.session.user });
});

// 全局錯誤處理中間件 (應放在所有路由和中間件之後)
app.use((err, req, res, next) => {
    console.error("全局錯誤處理:", err.stack);
    res.status(500).render('error', { message: '伺服器內部錯誤 (500)', user: req.session.user });
});


// 啟動伺服器
app.listen(port, () => {
    console.log(`伺服器運行在 http://localhost:${port}`);
    console.log('請在瀏覽器中打開此地址。');
});

// 確保在應用程式關閉時關閉資料庫連接
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            return console.error(err.message);
        }
        console.log('已關閉 SQLite 資料庫連接。');
        process.exit(0);
    });
});
