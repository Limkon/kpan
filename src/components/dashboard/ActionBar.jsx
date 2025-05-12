import React from 'react';
// import '../../styles/DashboardPage.css';

const ActionBar = ({ onUploadClick, onCreateFolderClick, currentPath }) => {
  return (
    <div className="action-bar">
      {/* <button onClick={onUploadClick}>上传到 "{currentPath === '/' ? '根目录' : currentPath.split('/').pop()}"</button> */}
      {/* <button onClick={onCreateFolderClick}>在当前位置新建文件夹</button> */}
      {/* 其他操作按钮，例如排序、视图切换等 */}
      <span>当前路径的操作栏 (具体按钮由 Sidebar 或其他地方触发)</span>
    </div>
  );
};

export default ActionBar;
