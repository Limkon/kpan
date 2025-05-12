import React from 'react';
import { useAuth } from '../../contexts/AuthContext'; // 假设您有 AuthContext
import { useNavigate } from 'react-router-dom';
// import '../../styles/DashboardPage.css'; // CSS 会在 DashboardPage 中统一引入

const Navbar = () => {
  const { currentUser, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="dashboard-navbar">
      <div className="logo">LocalDrive</div>
      {currentUser && (
        <div className="user-menu">
          <span>你好, {currentUser.username}!</span>
          <button onClick={handleLogout} style={{marginLeft: '10px'}}>登出</button>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
