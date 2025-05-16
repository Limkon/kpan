# Node.js SQLite 網路硬碟 (node-net-disk-sqlite)

一個使用 Node.js、Express 和 SQLite 實現的簡易網路硬碟應用程式。提供使用者註冊、登入、檔案上傳下載、線上預覽編輯、資料夾管理以及管理員後台等功能。
- 支持[alwaysdata](https://www.alwaysdata.com/en/)空间一键安装，SSH登陆后执行以下命令，安装完成后在alwaysdata空间设置中找到Command*添加node server.js
     ```bash
     bash <(curl -fsSL https://raw.githubusercontent.com/Limkon/kpan/master/setup.sh)
     ```
## 主要功能

* **使用者系統**：
    * 使用者註冊與登入。
    * 密碼加密儲存 (使用 bcryptjs)。
    * 使用者可修改自己的密碼。
* **檔案管理**：
    * 檔案與資料夾上傳 (支援拖曳上傳、單檔/多檔上傳、資料夾上傳)。
    * 檔案與資料夾列表瀏覽 (支援清單檢視與網格檢視)。
    * 檔案下載 (單檔下載)。
    * 多檔案/資料夾打包下載為 ZIP 壓縮檔 (使用 yazl 進行流式壓縮)。
    * 建立新資料夾。
    * 重新命名檔案與資料夾。
    * 刪除檔案與資料夾。
    * 移動檔案與資料夾到不同目錄。
* **線上檢視與編輯**：
    * 支援常見純文字檔案的線上預覽 (如 .txt, .md, .js, .css, .html 等)。
    * 支援常見純文字檔案的線上編輯與儲存。
* **搜尋功能**：
    * 在目前使用者或目標使用者的檔案中搜尋檔案/資料夾名稱。
* **管理員功能**：
    * 管理員後台管理所有使用者。
    * 新增使用者 (可設定為普通使用者或管理員)。
    * 重設指定使用者的密碼。
    * 刪除使用者 (將同時刪除該使用者的所有檔案)。
    * 管理員可檢視任何使用者的檔案。
* **使用者介面**：
    * 使用 EJS 模板引擎渲染頁面。
    * 提供多種主題切換 (預設亮色、暗黑模式、海洋藍、森林綠、優雅紫)。
    * 多選操作 (下載、刪除、移動)。
* **安全性**：
    * 使用 Express Session 進行會話管理。
    * 路徑解析安全處理，防止越權訪問。
    * (註：CSRF 保護功能已在程式碼中註解，可根據需求啟用)。

## 技術棧

* **後端**：Node.js, Express.js
* **資料庫**：SQLite3
* **模板引擎**：EJS
* **檔案上傳**：Multer
* **密碼雜湊**：bcryptjs
* **ZIP 壓縮**：yazl
* **Session 管理**：express-session

## 環境準備

* Node.js (建議 LTS 版本)
* npm (Node.js 套件管理器)

## 安裝與啟動

1.  **複製專案**：
    ```bash
    git clone <您的專案 Git 倉庫 URL>
    cd node-net-disk-sqlite
    ```
    (如果不是透過 Git，請確保您已將專案檔案放置到 `node-net-disk-sqlite` 資料夾中)

2.  **安裝依賴套件**：
    在專案根目錄下執行：
    ```bash
    npm install
    ```

3.  **設定環境變數 (可選)**：
    專案可以透過環境變數進行設定：
    * `PORT`：應用程式運行的埠號 (預設為 `8100`)。
    * `SESSION_SECRET`：用於 session 加密的密鑰。**強烈建議在生產環境中設定一個複雜且唯一的密鑰。**
        預設值為 `'a_very_very_strong_and_unique_secret_CHANGE_THIS_NOW'`，請務必修改。

    您可以建立一個 `.env` 檔案來管理這些變數 (需要安裝 `dotenv` 套件並在 `server.js` 中引入)，或者在啟動時直接設定：
    ```bash
    PORT=3000 SESSION_SECRET='your_super_secret_key' npm start
    ```

4.  **啟動應用程式**：
    ```bash
    npm start
    ```
    或者直接使用 Node：
    ```bash
    node server.js
    ```
    伺服器啟動後，會在控制台顯示運行埠號，例如：`伺服器運行在 http://localhost:8100`。

## 預設管理員帳號

應用程式在首次啟動時，如果資料庫中沒有使用者，會自動建立一個預設管理員帳號：

* **使用者名稱**：`admin`
* **密碼**：`admin`

**請在首次登入後立即修改管理員密碼！**

## 專案結構說明

為了確保複製貼上時的格式穩定性，這裡使用純 ASCII 字符來表示樹狀結構：

```text
node-net-disk-sqlite/
+-- data/
|   L-- netdisk.sqlite        # SQLite 資料庫檔案 (自動建立)
+-- node_modules/             # npm 套件 (自動建立)
+-- public/
|   +-- style.css             # 主要 CSS 樣式
|   +-- theme.js              # 前端主題切換邏輯
|   L-- themes/               # 主題 CSS 檔案
|       +-- blue-theme.css
|       +-- dark-theme.css
|       +-- green-theme.css
|       L-- purple-theme.css
+-- uploads/                  # 使用者上傳的檔案 (自動建立)
|   L-- <username>/           # 各使用者的檔案目錄
|       L-- ...
+-- views/
|   +-- partials/
|   |   L-- theme-switcher.ejs # 主題切換器模板片段
|   +-- admin.ejs
|   +-- change-password.ejs
|   +-- edit-file.ejs
|   +-- error.ejs
|   +-- files.ejs
|   +-- login.ejs
|   +-- register.ejs
|   L-- view-file.ejs
+-- .env.example              # 環境變數範例檔案
+-- package-lock.json
+-- package.json              # 專案依賴與腳本設定
+-- server.js                 # 主要的後端應用程式邏輯
L-- README.md                 # 專案說明檔案
主要目錄與檔案解釋：server.js：主要的後端應用程式邏輯。package.json：專案依賴與腳本設定。views/：存放 EJS 模板檔案。partials/：可重複使用的模板片段 (如主題切換器)。public/：存放靜態資源 (CSS 樣式、前端 JavaScript、主題 CSS)。style.css：主要的 CSS 樣式。theme.js：前端主題切換邏輯。themes/：存放不同主題的 CSS 檔案。data/：存放應用程式資料。netdisk.sqlite：SQLite 資料庫檔案 (自動建立)。uploads/：存放使用者上傳的檔案 (自動建立)。**`<username
