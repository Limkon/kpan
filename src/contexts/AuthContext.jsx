// src/contexts/AuthContext.jsx
import React, { createContext, useState, useEffect, useContext, useCallback } from 'react';
import { getCurrentUser } from '../api/authApi'; // API 调用函数，用于获取当前用户信息
import axiosInstance from '../api/axiosInstance'; // 引入配置好的 Axios 实例

// 1. 创建 Context 对象
const AuthContext = createContext(null);

// 2. 创建 AuthProvider 组件
export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null); // 存储当前用户信息
  const [isAuthenticated, setIsAuthenticated] = useState(false); // 标记用户是否已认证
  const [loading, setLoading] = useState(true); // 初始加载状态，用于检查本地 token

  // 检查本地 token 并获取用户信息的函数
  const verifyAuth = useCallback(async () => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      // 如果存在 token，可以先假设用户已认证，以避免 UI 闪烁
      // 实际的认证状态将在获取用户信息后确认
      // axiosInstance 拦截器应该已经配置为自动发送此 token
      try {
        const response = await getCurrentUser(); // 发送请求获取用户信息
        setCurrentUser(response.data);
        setIsAuthenticated(true);
      } catch (error) {
        console.error("验证 Token 失败或获取用户信息失败:", error);
        localStorage.removeItem('accessToken'); // Token 无效或已过期，清除它
        setCurrentUser(null);
        setIsAuthenticated(false);
      }
    }
    setLoading(false); // 完成检查，更新加载状态
  }, []);

  // Effect Hook：在组件挂载时运行一次，检查认证状态
  useEffect(() => {
    verifyAuth();
  }, [verifyAuth]);

  // Login 函数
  // userDetails: 从登录 API 响应中获取的用户对象 (e.g., { id, username, role })
  // token: 从登录 API 响应中获取的 accessToken
  const login = useCallback((userDetails, token) => {
    localStorage.setItem('accessToken', token);
    setCurrentUser(userDetails);
    setIsAuthenticated(true);
    // axiosInstance 的请求拦截器会自动从 localStorage 获取新的 token
  }, []);

  // Logout 函数
  const logout = useCallback(() => {
    localStorage.removeItem('accessToken');
    setCurrentUser(null);
    setIsAuthenticated(false);
    // 导航到登录页面的逻辑应该由调用 logout 的组件处理
    // 例如: navigate('/login');
  }, []);

  // Context 的值
  const contextValue = {
    currentUser,
    isAuthenticated,
    loading,
    login,
    logout,
    // verifyAuth, // 可以选择性暴露 verifyAuth，如果需要在应用其他地方手动触发验证
  };

  // 只有在初始加载完成后才渲染子组件，以确保子组件能正确获取认证状态
  return (
    <AuthContext.Provider value={contextValue}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

// 3. 创建自定义 Hook useAuth，方便组件使用 Context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === null) {
    // 如果在 AuthProvider 外部使用此 Hook，则抛出错误
    throw new Error("useAuth 必须在 AuthProvider 内部使用");
  }
  return context;
};
