import React from 'react';
// import '../../styles/DashboardPage.css';

const FileItem = ({ item, onClick }) => {
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  return (
    <div className="file-item" onClick={onClick} title={`文件: ${item.name}`}>
      <span className="item-icon">📄</span> {/* 可以用 SVG 或字体图标替换 */}
      <span className="item-name">{item.name}</span>
      <span className="item-size">{formatBytes(item.size)}</span>
      <span className="item-modified">{new Date(item.lastModified).toLocaleDateString()}</span>
    </div>
  );
};

export default FileItem;
