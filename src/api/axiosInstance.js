// src/api/axiosInstance.js
import axios from 'axios';

const axiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
});

// 请求拦截器：用于添加 token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken'); // 从 localStorage 获取 token
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器：可以用于统一处理错误，或处理 token 过期等
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Token 过期或无效，可以重定向到登录页面
      localStorage.removeItem('accessToken');
      // window.location.href = '/login'; // 或者使用 React Router 的 navigate
      console.error("Unauthorized or Token Expired. Redirecting to login.");
    }
    return Promise.reject(error);
  }
);

export default axiosInstance;
