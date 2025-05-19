#!/bin/bash
set -e # 当命令以非零状态退出时，立即退出脚本

echo "🚀 开始安装项目..."

# GitHub 仓库信息
GITHUB_USER="Limkon"
REPO_NAME="kpan" # 这也将用作项目子目录名
BRANCH="master"

echo "👤 GitHub 用户名: $GITHUB_USER"
echo "📦 仓库名: $REPO_NAME"
echo "🌿 分支: $BRANCH"

# 下载链接
TAR_URL="https://github.com/$GITHUB_USER/$REPO_NAME/archive/refs/heads/$BRANCH.tar.gz"
echo "🔗 下载链接: $TAR_URL"

# 验证下载链接是否可访问
# 使用 curl --head -fsSL 检查链接，-f 会在HTTP错误时静默失败并返回错误码，-s 静默模式，-S 显示错误，-L 跟随重定向
if ! curl --head -fsSL "$TAR_URL" >/dev/null 2>&1; then
    echo "❌ 错误：无法访问 $TAR_URL，可能是网络问题、链接无效或仓库是私有的。"
    exit 1
fi

# 项目将安装到当前目录下的 REPO_NAME 子目录中
BASE_INSTALL_DIR=$(pwd)
PROJECT_DIR="$BASE_INSTALL_DIR/$REPO_NAME"
echo "📁 项目将安装到目录: $PROJECT_DIR"

# 如果项目目录已存在，询问用户是否覆盖或退出
if [ -d "$PROJECT_DIR" ]; then
    echo "⚠️ 警告: 目录 $PROJECT_DIR 已存在。"
    read -p "您想覆盖它吗? (输入 'yes' 继续, 其他任何输入将退出): " OVERWRITE_CHOICE
    if [ "$OVERWRITE_CHOICE" != "yes" ]; then
        echo "安装已取消。"
        exit 0
    fi
    echo "🗑️ 删除已存在的目录 $PROJECT_DIR ..."
    rm -rf "$PROJECT_DIR"
fi

mkdir -p "$PROJECT_DIR" # 创建项目目录

# 创建临时目录并解压项目
TEMP_DIR=$(mktemp -d)
echo "📂 创建临时目录: $TEMP_DIR"

echo "⏳ 正在下载并解压项目到临时目录..."
if ! curl -fsSL "$TAR_URL" | tar -xz -C "$TEMP_DIR" --strip-components=1; then
    echo "❌ 错误：下载或解压 $TAR_URL 失败。"
    rm -rf "$TEMP_DIR" # 清理临时目录
    exit 1
fi
echo "✅ 项目解压完成。"

# 删除 .github 目录（如果存在于解压内容中）
if [ -d "$TEMP_DIR/.github" ]; then
    echo "🗑️ 删除 $TEMP_DIR/.github 目录..."
    rm -rf "$TEMP_DIR/.github"
fi

# 将临时目录中的所有内容（包括隐藏文件）复制到项目目录
echo "⏳ 正在复制文件到 $PROJECT_DIR ..."
# 使用 cp -a 来保留文件属性并复制所有内容 (包括以.开头的隐藏文件)
# "$TEMP_DIR/." 表示复制 $TEMP_DIR 目录下的所有内容
if cp -a "$TEMP_DIR/." "$PROJECT_DIR/"; then
    echo "✅ 文件已成功复制到 $PROJECT_DIR"
else
    echo "❌ 错误：复制文件到 $PROJECT_DIR 失败。"
    rm -rf "$TEMP_DIR" # 清理临时目录
    rm -rf "$PROJECT_DIR" # 清理部分创建的项目目录
    exit 1
fi

# 清理临时目录
echo "🗑️ 清理临时目录 $TEMP_DIR ..."
rm -rf "$TEMP_DIR"

# 进入项目目录进行后续操作
cd "$PROJECT_DIR"

echo "🔧 检查系统 Node.js 和 npm 环境..."

# 1. 检查 Node.js 是否安装
if ! command -v node &> /dev/null; then
    echo "❌ 错误: Node.js 未安装。请先安装 Node.js (推荐 v18 或更高版本) 然后重试。"
    echo "   例如，在 Ubuntu/Debian 上: sudo apt update && sudo apt install nodejs npm"
    echo "   或从 NodeSource: curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - && sudo apt-get install -y nodejs"
    exit 1
fi

# 2. 检查 npm 是否安装
if ! command -v npm &> /dev/null; then
    echo "❌ 错误: npm 未安装。请确保 npm 与 Node.js 一起安装。"
    exit 1
fi

# 3. 检查 Node.js 版本 (推荐 v18 或更高)
NODE_VERSION_OUTPUT=$(node -v)
NODE_MAJOR_VERSION=$(echo "$NODE_VERSION_OUTPUT" | sed -E 's/v([0-9]+)\..*/\1/')
DESIRED_MAJOR_VERSION="18"

if [ "$NODE_MAJOR_VERSION" -lt "$DESIRED_MAJOR_VERSION" ]; then
    echo "❌ 错误: Node.js 版本过低。需要 v$DESIRED_MAJOR_VERSION 或更高版本, 当前版本: $NODE_VERSION_OUTPUT"
    echo "   请升级您的 Node.js 版本。"
    exit 1
else
    echo "✅ Node.js 版本检查通过: $NODE_VERSION_OUTPUT (主版本: $NODE_MAJOR_VERSION)"
fi

echo "🧩 当前使用 Node: $(which node) (版本: $NODE_VERSION_OUTPUT)"
echo "🧩 当前使用 npm: $(which npm) (版本: $(npm -v))"

# 确保 package.json 文件存在
if [ ! -f "package.json" ]; then # 此时已 cd 到 $PROJECT_DIR
    echo "⚠️  警告: 项目中未找到 package.json 文件。将创建一个包含基本启动脚本的 package.json。"
    echo "{
  \"name\": \"$REPO_NAME\",
  \"version\": \"1.0.0\",
  \"description\": \"Downloaded from GitHub $GITHUB_USER/$REPO_NAME\",
  \"main\": \"server.js\",
  \"scripts\": {
    \"start\": \"node server.js\"
  },
  \"dependencies\": {}
}" > "package.json"
    echo "👍 已创建基础的 package.json。"
else
    echo "👍 项目中已存在 package.json。"
fi

echo "📦 正在安装依赖 (根据 package.json)..."
# 假设下载的仓库中 package.json 是完整的。
# set -e 会在 npm install 失败时停止脚本。
if npm install; then
    echo "✅ 依赖安装成功。"
else
    echo "❌ 依赖安装过程中发生错误。"
    # 由于 set -e，脚本在此处会自动退出。
    exit 1
fi

# 获取 node 的绝对路径，用于开机启动项
NODE_EXEC_PATH=$(command -v node)
if [ -z "$NODE_EXEC_PATH" ]; then
    echo "❌ 致命错误：无法找到 node 执行路径，即使之前检查通过。这不应该发生。"
    exit 1
fi

echo "🚀 准备创建开机启动项..."
# 创建开机启动项目录 (如果不存在)
AUTOSTART_DIR="$HOME/.config/autostart"
mkdir -p "$AUTOSTART_DIR"

AUTOSTART_FILE="$AUTOSTART_DIR/$REPO_NAME-startup.desktop" # 使用仓库名作为文件名
echo "📝 创建开机启动项文件: $AUTOSTART_FILE"

# 创建 .desktop 文件内容
# Exec 命令会将标准输出和标准错误都追加到项目目录下的 startup.log 文件
# 注意：'$PROJECT_DIR' 和 '$NODE_EXEC_PATH' 在这里是字面量，cat的EOF内变量会展开
cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=$REPO_NAME Server
Comment=Start $REPO_NAME Server automatically at login
Exec=bash -c "cd '$PROJECT_DIR' && '$NODE_EXEC_PATH' server.js >> '$PROJECT_DIR/startup.log' 2>&1"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Icon=application-default-icon
Terminal=false
EOF

# 为 .desktop 文件添加执行权限 (通常不需要，但为了完整性)
# chmod +x "$AUTOSTART_FILE" # .desktop 文件通常不需要执行权限来工作

echo "✅ 项目安装完成！"
echo "👍 开机启动项已创建于: $AUTOSTART_FILE"
echo "   (可能需要重新登录或重启系统以使开机启动生效)"
echo "   服务启动日志将记录在: $PROJECT_DIR/startup.log"
echo "👉 您可以检查该文件的内容，并根据需要进行调整。"
echo "🚀 手动启动服务器: cd \"$PROJECT_DIR\" && npm start"
echo "   (如果 package.json 中没有 'start' 脚本, 请使用: cd \"$PROJECT_DIR\" && node server.js)"

exit 0
