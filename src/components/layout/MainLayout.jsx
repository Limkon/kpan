import React from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
// import '../../styles/DashboardPage.css'; // CSS 会在 DashboardPage 中统一引入

const MainLayout = ({ children, onUploadClick, onCreateFolderClick }) => {
  return (
    <div className="dashboard-layout">
      <Navbar />
      <div className="dashboard-main-wrapper">
        <Sidebar onUploadClick={onUploadClick} onCreateFolderClick={onCreateFolderClick} />
        <main className="dashboard-content-area">
          {children}
        </main>
      </div>
    </div>
  );
};

export default MainLayout;
