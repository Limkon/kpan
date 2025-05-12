import React from 'react';
// import '../../styles/DashboardPage.css';

const Breadcrumbs = ({ path, onNavigate }) => {
  const parts = path === '/' || !path ? ['根目录'] : ['根目录', ...path.split('/').filter(p => p)];

  const handleClick = (index) => {
    if (index === 0) {
      onNavigate('/'); // 导航到根目录
    } else {
      const newPath = '/' + parts.slice(1, index + 1).join('/');
      onNavigate(newPath);
    }
  };

  return (
    <div className="breadcrumbs">
      {parts.map((part, index) => (
        <React.Fragment key={index}>
          <span onClick={() => handleClick(index)} title={`导航到 ${part}`}>
            {part}
          </span>
          {index < parts.length - 1 && <span className="separator">&gt;</span>}
        </React.Fragment>
      ))}
    </div>
  );
};

export default Breadcrumbs;
