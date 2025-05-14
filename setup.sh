#!/bin/bash
set -e

echo "🚀 开始安装项目..."

# GitHub 仓库信息
GITHUB_USER="Limkon"
REPO_NAME="kpan"
BRANCH="master"

echo "👤 GitHub 用户名: $GITHUB_USER"
echo "📦 仓库名: $REPO_NAME"
echo "🌿 分支: $BRANCH"

# 下载链接
TAR_URL="https://github.com/$GITHUB_USER/$REPO_NAME/archive/refs/heads/$BRANCH.tar.gz"
echo "📦 下载链接: $TAR_URL"

# 验证下载链接是否可访问
if ! curl -fsSL --head "$TAR_URL" >/dev/null 2>&1; then
    echo "❌ 错误：无法访问 $TAR_URL，可能是网络问题或链接无效"
    exit 1
fi

# 获取当前脚本执行的目录作为项目目录的基准
# 如果脚本不是在目标项目目录中运行，请调整 PROJECT_DIR 的获取方式
PROJECT_DIR=$(pwd)
echo "📁 项目将安装到目录: $PROJECT_DIR"

# 创建临时目录并解压项目
TEMP_DIR=$(mktemp -d)
echo "📂 创建临时目录: $TEMP_DIR"

echo "⏳ 正在下载并解压项目..."
if ! curl -fsSL "$TAR_URL" | tar -xz -C "$TEMP_DIR" --strip-components=1; then
    echo "❌ 错误：下载或解压 $TAR_URL 失败"
    rm -rf "$TEMP_DIR" # 清理临时目录
    exit 1
fi
echo "✅ 项目解压完成。"

# 删除 .github 目录（如果存在）
if [ -d "$TEMP_DIR/.github" ]; then
    echo "🗑️ 删除 $TEMP_DIR/.github 目录..."
    rm -rf "$TEMP_DIR/.github"
fi

# 将临时目录中的所有内容（包括隐藏文件，除了. 和 ..）复制到项目目录
echo "⏳ 正在复制文件到 $PROJECT_DIR ..."
cd "$TEMP_DIR"
if find . -maxdepth 1 -mindepth 1 -exec cp -rft "$PROJECT_DIR" '{}' +; then
    echo "✅ 文件已成功复制到 $PROJECT_DIR"
else
    echo "❌ 错误：复制文件到 $PROJECT_DIR 失败"
    cd "$PROJECT_DIR" # 返回原始目录以防后续清理失败
    rm -rf "$TEMP_DIR"
    exit 1
fi

# 清理临时目录
echo "🗑️ 清理临时目录 $TEMP_DIR ..."
rm -rf "$TEMP_DIR"
cd "$PROJECT_DIR" # 确保当前目录是项目目录

echo "🔧 检查系统 Node.js 和 npm 环境..."

# 1. 检查 Node.js 是否安装
if ! command -v node &> /dev/null; then
    echo "❌ 错误: Node.js 未安装。请先安装 Node.js (推荐 v18 或更高版本) 然后重试。"
    echo "    例如，在 Ubuntu/Debian 上: sudo apt update && sudo apt install nodejs npm"
    echo "    或从 NodeSource: curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - && sudo apt-get install -y nodejs"
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
    echo "    请升级您的 Node.js 版本。"
    exit 1
else
    echo "✅ Node.js 版本检查通过: $NODE_VERSION_OUTPUT (主版本: $NODE_MAJOR_VERSION)"
fi

echo "🧩 当前使用 Node: $(which node) (版本: $NODE_VERSION_OUTPUT)"
echo "🧩 当前使用 npm: $(which npm) (版本: $(npm -v))"

# 确保 package.json 文件存在
# 如果下载的仓库中应该有 package.json，这一步主要是为了防止仓库不规范
if [ ! -f "$PROJECT_DIR/package.json" ]; then
    echo "⚠️  警告: $PROJECT_DIR/package.json 未找到。将创建一个空的 package.json。"
    echo "{ \"name\": \"$REPO_NAME\", \"version\": \"1.0.0\", \"description\": \"Downloaded from GitHub\", \"main\": \"server.js\", \"scripts\": { \"start\": \"node server.js\" } }" > "$PROJECT_DIR/package.json"
else
    echo "👍 $PROJECT_DIR/package.json 已存在。"
fi

echo "📦 正在安装依赖 (如果 package.json 中已定义，则会安装它们，否则会尝试安装指定包)..."
# 如果下载的仓库中 package.json 已完整定义依赖，则直接运行 "npm install" 即可。
# 如果需要确保某些特定基础包存在并添加到 package.json（如果它不完整或为空），
# 则可以明确列出它们。set -e 会在 npm install 失败时停止脚本。
#
# 原脚本是: npm install axios express ws cookie-parser body-parser http-proxy-middleware
# 如果 package.json 已经有这些，则不需要显式列出。
# 为了通用性，如果仓库的 package.json 是可靠的，首选 `npm install`。
# 如果您想确保这些特定包被安装（即使不在package.json中），那么原命令是合适的。
# 这里我们采用更通用的 `npm install`，假设仓库的 `package.json` 是可信的。
# 如果您确定需要安装那些特定的包，即使它们不在下载的 package.json 中，
# 请改回: if npm install axios express ws cookie-parser body-parser archiver; then
#
# ** 这是之前发生错误的地方 (原脚本的第117-122行)。**
# ** 请确保您使用的脚本文件没有隐藏的特殊字符或不正确的换行符。**
if npm install; then # 假设下载的仓库中 package.json 是完整的
    echo "✅ 依赖安装成功。"
else
    echo "❌ 依赖安装过程中发生错误。"
    # 由于 set -e，npm install 失败时脚本通常会自动退出。
    # 这里的 exit 1 提供了更明确的错误处理路径。
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
# 注意：Exec 路径中的 $PROJECT_DIR 和 $NODE_EXEC_PATH 会在生成文件时被替换为实际路径。
# 确保 server.js 在 $PROJECT_DIR 的根目录下。
cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=$REPO_NAME Server
Comment=Start $REPO_NAME Server automatically at login
Exec=bash -c "cd '$PROJECT_DIR' && '$NODE_EXEC_PATH' server.js"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Icon=application-default-icon
Terminal=false
EOF

# 为 .desktop 文件添加执行权限 (通常不需要，但某些环境可能关注)
chmod +x "$AUTOSTART_FILE"

echo "✅ 项目安装完成！"
echo "👍 开机启动项已创建于: $AUTOSTART_FILE"
echo "    (可能需要重新登录或重启系统以使开机启动生效)"
echo "👉 您可以检查该文件的内容，并根据需要进行调整。"
echo "🚀 手动启动服务器: cd \"$PROJECT_DIR\" && npm start"
echo "    (如果 package.json 中没有 'start' 脚本, 请使用: cd \"$PROJECT_DIR\" && node server.js)"
