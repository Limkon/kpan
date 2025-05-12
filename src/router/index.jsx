// src/router/index.jsx
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from '../pages/LoginPage';
import RegisterPage from '../pages/RegisterPage';
import DashboardPage from '../pages/DashboardPage'; // 假设这是文件管理主页面
// import AdminPage from '../pages/AdminPage';
// import SharedItemPage from '../pages/SharedItemPage';

// 简单的私有路由组件
const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('accessToken');
  return token ? children : <Navigate to="/login" />;
};

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route
        path="/dashboard/*" // 使用 /* 允许仪表盘内部嵌套路由
        element={
          <PrivateRoute>
            <DashboardPage />
          </PrivateRoute>
        }
      />
      {/* <Route path="/admin" element={<PrivateRoute adminOnly={true}><AdminPage /></PrivateRoute>} /> */}
      {/* <Route path="/share/:token" element={<SharedItemPage />} /> */}
      <Route path="/" element={<Navigate to="/dashboard" />} />
      <Route path="*" element={<Navigate to="/dashboard" />} /> {/* 404 or redirect */}
    </Routes>
  );
};

export default AppRoutes;
