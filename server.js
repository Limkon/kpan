// server.js (SQLite 版本 - 修复视图路径并更新端口)
// 导入所需模块
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8100; // <--- 已按您的要求更改端口

// 資料庫文件路徑
const DB_FILE = path.join(__dirname, 'data', 'netdisk.sqlite');
// 上傳文件存儲目錄
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// 确保data和uploads目录存在
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
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
app.set('views', path.join(__dirname, 'views')); // <--- 明确设置视图目录
app.set('view engine', 'ejs'); // 设置模板引擎为 EJS

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your_very_secret_key_sqlite_8100', // 建议更改为更安全的密钥
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 在生產環境中應設為 true (HTTPS)
}));

// Multer 設置 (文件上傳處理)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // 文件将存储在用户特定的目录中
        const userUploadDir = path.join(UPLOAD_DIR, req.session.user.username);
        if (!fs.existsSync(userUploadDir)) {
            fs.mkdirSync(userUploadDir, { recursive: true });
        }
        cb(null, userUploadDir);
    },
    filename: function (req, file, cb) {
        // 保留原始文件名, 并尝试解决中文乱码问题
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
    res.status(403).send('禁止訪問：僅限管理員');
}

// --- 路由 ---

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/files');
    } else {
        res.redirect('/login'); // <--- 这是导致错误的 res.render 调用的地方之一
    }
});

// 註冊頁面
app.get('/register', (req, res) => {
    res.render('register', { error: null }); // <--- 确保 register.ejs 存在
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.render('register', { error: '用戶名和密碼不能為空' });
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

// 登錄頁面
app.get('/login', (req, res) => {
    res.render('login', { error: null }); // <--- 确保 login.ejs 存在
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
            return res.redirect('/files');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
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
            return res.status(500).send('無法讀取文件列表');
        }
        res.render('files', { // <--- 确保 files.ejs 存在
            user: user,
            files: files.map(f => ({ name: f, encodedName: encodeURIComponent(f) })) || [],
            message: req.query.message
        });
    });
});

// 文件上傳處理
app.post('/upload', isAuthenticated, upload.array('userFiles', 10), (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.redirect('/files?message=沒有選擇文件');
    }
    res.redirect('/files?message=文件上傳成功');
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
                    res.status(500).send('下載文件時出錯。');
                }
            }
        });
    } else {
        console.warn(`嘗試下載不存在的文件: ${filePath}`);
        res.status(404).send('文件未找到');
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
                return res.redirect(`/files?message=刪除文件 ${filename} 失敗`);
            }
            res.redirect(`/files?message=文件 ${filename} 已刪除`);
        });
    } else {
        res.redirect(`/files?message=文件 ${filename} 未找到`);
    }
});


// 管理員頁面 - 用戶管理
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role FROM users", [], (err, users) => {
        if (err) {
            console.error("獲取用戶列表失敗:", err.message);
            return res.status(500).send("無法獲取用戶列表");
        }
        res.render('admin', { users: users, currentUser: req.session.user, message: req.query.message }); // <--- 确保 admin.ejs 存在
    });
});

// 管理員刪除用戶
app.get('/admin/delete/:userId', isAuthenticated, isAdmin, (req, res) => {
    const userIdToDelete = parseInt(req.params.userId, 10);

    if (isNaN(userIdToDelete)) {
        return res.redirect('/admin?message=無效的用戶ID');
    }

    if (req.session.user.id === userIdToDelete) {
        return res.redirect('/admin?message=不能刪除當前登錄的管理員帳戶');
    }

    db.get("SELECT username FROM users WHERE id = ?", [userIdToDelete], (err, userToDelete) => {
        if (err) {
            console.error("刪除用戶前查找用戶名失敗:", err.message);
            return res.redirect('/admin?message=刪除用戶時發生錯誤');
        }
        if (!userToDelete) {
            return res.redirect('/admin?message=未找到該用戶');
        }

        db.run("DELETE FROM users WHERE id = ?", [userIdToDelete], function (err) {
            if (err) {
                console.error("刪除用戶失敗:", err.message);
                return res.redirect('/admin?message=刪除用戶失敗');
            }
            if (this.changes > 0) {
                console.log(`用戶 ID ${userIdToDelete} (用戶名: ${userToDelete.username}) 已被刪除。`);
                const userDirToDelete = path.join(UPLOAD_DIR, userToDelete.username);
                if (fs.existsSync(userDirToDelete)) {
                    fs.rm(userDirToDelete, { recursive: true, force: true }, (rmErr) => {
                        if (rmErr) {
                            console.error(`刪除用戶 ${userToDelete.username} 的文件夾 ${userDirToDelete} 失敗:`, rmErr);
                            res.redirect(`/admin?message=用戶已刪除，但其文件夾刪除失敗。`);
                        } else {
                            console.log(`用戶 ${userToDelete.username} 的文件夾 ${userDirToDelete} 已成功刪除。`);
                            res.redirect('/admin?message=用戶及其文件已成功刪除');
                        }
                    });
                } else {
                    res.redirect('/admin?message=用戶已刪除（該用戶沒有文件夾）');
                }
            } else {
                res.redirect('/admin?message=未找到用戶或刪除失敗');
            }
        });
    });
});


// 啟動伺服器
app.listen(port, () => {
    console.log(`伺服器運行在 http://localhost:${port}`); // <--- 确保日志输出正确的端口
    console.log('請在瀏覽器中打開此地址。');
});

process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            return console.error(err.message);
        }
        console.log('已關閉 SQLite 資料庫連接。');
        process.exit(0);
    });
});
