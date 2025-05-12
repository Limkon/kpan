// src/api/authApi.js
import axiosInstance from './axiosInstance';

export const registerUser = (userData) => {
  return axiosInstance.post('/auth/register', userData);
};

export const loginUser = (credentials) => {
  return axiosInstance.post('/auth/login', credentials);
};

export const getCurrentUser = () => {
  return axiosInstance.get('/auth/me');
};
