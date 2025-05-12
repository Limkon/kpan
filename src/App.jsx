// src/App.jsx
import React from 'react';
import AppRoutes from './router';
// import Navbar from './components/layout/Navbar'; // 示例

function App() {
  return (
    <div className="App">
      {/* <Navbar /> */}
      <main>
        <AppRoutes />
      </main>
    </div>
  );
}

export default App;
