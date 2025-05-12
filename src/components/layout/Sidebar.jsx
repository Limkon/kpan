import React from 'react';
// import '../../styles/DashboardPage.css';

const Sidebar = ({ onUploadClick, onCreateFolderClick }) => {
  // 在实际应用中，这里可能包含文件夹树或其他导航链接
  return (
    <aside className="dashboard-sidebar">
      <button onClick={onUploadClick}>上传文件</button>
      <button onClick={onCreateFolderClick}>新建文件夹</button>
      {/* <button>我的分享</button> */}
      {/* <button>回收站</button> */}
      {/* <button>设置</button> */}
    </aside>
  );
};

export default Sidebar;
