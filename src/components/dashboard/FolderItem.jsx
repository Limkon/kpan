import React from 'react';
// import '../../styles/DashboardPage.css';

const FolderItem = ({ item, onClick }) => {
  return (
    <div className="folder-item" onClick={onClick} title={`文件夹: ${item.name}`}>
      <span className="item-icon">📁</span> {/* 可以用 SVG 或字体图标替换 */}
      <span className="item-name">{item.name}</span>
      {/* 文件夹通常不显示大小和修改日期，或显示项目数量 */}
      <span className="item-size"></span>
      <span className="item-modified">{new Date(item.lastModified).toLocaleDateString()}</span>
    </div>
  );
};

export default FolderItem;
